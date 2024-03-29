/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM instrumentation bootstrap
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres.

   This code is the rewrite of afl-as.h's main_payload.
*/
#define _GNU_SOURCE /* Bring REG_XXX names from /usr/include/sys/ucontext.h */

#include "./android-ashmem.h"
#include "./config.h"
#include "./types.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <ucontext.h>
#include <udis86.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <stdatomic.h>
#include <threads.h>


/* This is a somewhat ugly hack for the experimental 'trace-pc-guard' mode.
   Basically, we need to make sure that the forkserver is initialized after
   the LLVM-generated runtime initialization pass, not before. */

#ifdef USE_TRACE_PC
#  define CONST_PRIO 5
#else
#  define CONST_PRIO 0
#endif /* ^USE_TRACE_PC */



/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to run.
   It will end up as .comm, so it shouldn't be too wasteful. */

u8 __afl_area_initial[MAP_SIZE];
u8 *__afl_area_ptr = __afl_area_initial;
u8 __phantom_bitmap_initial[BITMAP_SIZE];
u8 *__phantom_bitmap_ptr = __phantom_bitmap_initial;
u8 __source_map_initial[MAP_SIZE];
u8 *__source_map_ptr = __source_map_initial;

__thread u8 __crash_mask = 255;

__thread u32 __afl_prev_loc;
atomic_ushort __prev_idx = 0;
mtx_t __df_lock;


/* Running in persistent mode? */

static u8 is_persistent;


/* SHM setup. */

static void __afl_map_shm(void) {

    u8 *id_str = getenv(SHM_ENV_VAR);

    /* If we're running under AFL, attach to the appropriate region, replacing the
       early-stage __afl_area_initial region that is needed to allow some really
       hacky .init code to work correctly in projects such as OpenSSL. */

    if (id_str) {

        u32 shm_id = atoi(id_str);

        __afl_area_ptr = shmat(shm_id, NULL, 0);

        /* Whooooops. */

        if (__afl_area_ptr == (void *) -1) _exit(1);

        /* Write something into the bitmap so that even with low AFL_INST_RATIO,
           our parent doesn't give up on us. */

        __afl_area_ptr[0] = 1;

    }

    u8 *__phantom_bitmap_str = getenv(SHM_PHANTOM_BITMAP_ENV_VAR);
    if (__phantom_bitmap_str) {

        u32 shm_id = atoi(__phantom_bitmap_str);

        __phantom_bitmap_ptr = shmat(shm_id, NULL, 0);

        /* Whooooops. */

        if (__phantom_bitmap_ptr == (void *) -1) _exit(1);

    }

    u8 *source_map_id_str = getenv(SHM_SOURCE_MAP_ENV_VAR);
    if (source_map_id_str) {

        u32 shm_id = atoi(source_map_id_str);

        __source_map_ptr = shmat(shm_id, NULL, 0);

        /* Whooooops. */

        if (__source_map_ptr == (void *) -1) _exit(1);

    }

}


/* Fork server logic. */

static void __afl_start_forkserver(void) {

    static u8 tmp[4];
    s32 child_pid;

    u8 child_stopped = 0;

    /* Phone home and tell the parent that we're OK. If parent isn't there,
       assume we're not running in forkserver mode and just execute program. */

    if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

    while (1) {

        u32 was_killed;
        int status;

        /* Wait for parent by reading from the pipe. Abort if read fails. */

        if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

        /* If we stopped the child in persistent mode, but there was a race
           condition and afl-fuzz already issued SIGKILL, write off the old
           process. */

        if (child_stopped && was_killed) {
            child_stopped = 0;
            if (waitpid(child_pid, &status, 0) < 0) _exit(1);
        }

        if (!child_stopped) {

            /* Once woken up, create a clone of our process. */

            child_pid = fork();
            if (child_pid < 0) _exit(1);

            /* In child process: close fds, resume execution. */

            if (!child_pid) {

                close(FORKSRV_FD);
                close(FORKSRV_FD + 1);
                return;

            }

        } else {

            /* Special handling for persistent mode: if the child is alive but
               currently stopped, simply restart it with SIGCONT. */

            kill(child_pid, SIGCONT);
            child_stopped = 0;

        }

        /* In parent process: write PID to pipe, then wait for child. */

        if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);

        if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0)
            _exit(1);

        /* In persistent mode, the child stops itself with SIGSTOP to indicate
           a successful run. In this case, we want to wake it up without forking
           again. */

        if (WIFSTOPPED(status)) child_stopped = 1;

        /* Relay wait status to pipe, then loop back. */

        if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);

    }

}


/* A simplified persistent mode handler, used as explained in README.llvm. */

int __afl_persistent_loop(unsigned int max_cnt) {

    static u8 first_pass = 1;
    static u32 cycle_cnt;

    if (first_pass) {

        /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
           On subsequent calls, the parent will take care of that, but on the first
           iteration, it's our job to erase any trace of whatever happened
           before the loop. */

        if (is_persistent) {

            memset((void *) __source_map_ptr, 0, MAP_SIZE);
            memset((void *) __phantom_bitmap_ptr, 0, BITMAP_SIZE);
            memset(__afl_area_ptr, 0, MAP_SIZE);

            __afl_area_ptr[0] = 1;
            __afl_prev_loc = 0;
        }

        cycle_cnt = max_cnt;
        first_pass = 0;
        return 1;

    }

    if (is_persistent) {

        if (--cycle_cnt) {

            raise(SIGSTOP);

            __afl_area_ptr[0] = 1;
            __afl_prev_loc = 0;

            return 1;

        } else {

            /* When exiting __AFL_LOOP(), make sure that the subsequent code that
               follows the loop is not traced. We do that by pivoting back to the
               dummy output region. */

            __afl_area_ptr = __afl_area_initial;

        }

    }

    return 0;

}


/* This one can be called from user code when deferred forkserver mode
    is enabled. */

void __afl_manual_init(void) {

    static u8 init_done;

    if (!init_done) {

        __afl_map_shm();
        __afl_start_forkserver();
        init_done = 1;

    }

}

static ud_t ud_obj;

static inline uint8_t is_raise(ud_t *ud, uint32_t len) {
   return (len == 8) && (*((uint64_t *) ud_insn_ptr(ud)) == 1134484032328);
}

static void crash_action_ignore(int signal, siginfo_t *si, void *arg) {

   ucontext_t *ctx = (ucontext_t *) arg;

   /* We are on linux x86, the returning IP is stored in RIP (64bit) or EIP (32bit).
      In this example, the length of the offending instruction is 6 bytes.
      So we skip the offender ! */
#if __WORDSIZE == 64
   uint64_t pc = ctx->uc_mcontext.gregs[REG_RIP];
   ud_set_input_buffer(&ud_obj, (const uint8_t *) pc, 15);
   if (ud_decode(&ud_obj)) {
       uint32_t len = ud_insn_len(&ud_obj);
       if (!is_raise(&ud_obj, len)) {
           __crash_mask = 0;
           ctx->uc_mcontext.gregs[REG_RIP] += len;
       }
   }
#else
   uint64_t pc = ctx->uc_mcontext.gregs[REG_EIP];
   ud_set_input_buffer(&ud_obj, (const uint8_t *) pc, 15);
   if (ud_decode(&ud_obj))
   {
       uint32_t len = ud_insn_len(&ud_obj);
       if (!is_raise(&ud_obj, len)) {
           __crash_mask = 0;
           ctx->uc_mcontext.gregs[REG_EIP] += len;
       }
   }
#endif
}

static void ignore_crash(int signum) {
   struct sigaction *sa = (struct sigaction *) malloc(sizeof (struct sigaction));
   memset(sa, 0, sizeof(struct sigaction));
   sigemptyset(&(sa->sa_mask));
   sa->sa_sigaction = crash_action_ignore;
   sa->sa_flags = SA_SIGINFO;
   sigaction(signum, sa, NULL);
}

/* Proper initialization routine. */

__attribute__((constructor(CONST_PRIO))) void __afl_auto_init(void) {
    is_persistent = !!getenv(PERSIST_ENV_VAR);

   ud_init(&ud_obj);
#if __WORDSIZE == 64
   ud_set_mode(&ud_obj, 64);
#else
   ud_set_mode(&ud_obj, 32);
#endif
   ignore_crash(SIGSEGV);
   ignore_crash(SIGFPE);
   ignore_crash(SIGILL);
   ignore_crash(SIGBUS);


    if (getenv(DEFER_ENV_VAR)) return;

    __afl_manual_init();

}

__attribute__((destructor(CONST_PRIO))) void __afl_debug_print(void) {
    if(__afl_area_ptr != __afl_area_initial) {
        return;
    }

    FILE *f = fopen("path.txt", "w+");
    fprintf(f, "------------- afl map -----------\n");
    u8 * ptr = __afl_area_ptr;
    u32 num = 0;
    while (ptr != __afl_area_ptr + MAP_SIZE) {
        if ((*ptr) > 0)
            fprintf(f, "idx: %d, val: %d\n", num, *(ptr));
        ptr++;
        num++;
    }

    fprintf(f, "\n\n------------- phantom bitmp -----------\n");
    ptr = __phantom_bitmap_ptr;
     num = 0;
    while (ptr != __phantom_bitmap_ptr + BITMAP_SIZE) {
        u8 bitmap_entry = *ptr;
        if (bitmap_entry) {
            u8 bit = 0;
            while (bit != 8) {
                if (bitmap_entry & (0x1 << bit)) {
                    fprintf(f, "edge: %d\n", num + bit);
                }
                bit++;
            }
        }
        ptr++;
        num += 8;
    }

    fprintf(f, "\n\n------------- source map -----------\n");
    ptr = __source_map_ptr;
    num = 0;
    while (ptr != __source_map_ptr + MAP_SIZE) {
        if ((*ptr) > 0)
            fprintf(f, "idx: %d, val: %d\n", num, *(ptr));
        ptr++;
        num++;
    }

    fclose(f);
}


/* The following stuff deals with supporting -fsanitize-coverage=trace-pc-guard.
   It remains non-operational in the traditional, plugin-backed LLVM mode.
   For more info about 'trace-pc-guard', see README.llvm.

   The first function (__sanitizer_cov_trace_pc_guard) is called back on every
   edge (as opposed to every basic block). */

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    __afl_area_ptr[*guard]++;
}


/* Init callback. Populates instrumentation IDs. Note that we're using
   ID of 0 as a special value to indicate non-instrumented bits. That may
   still touch the bitmap, but in a fairly harmless way. */

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {

    u32 inst_ratio = 100;
    u8 *x;

    if (start == stop || *start) return;

    x = getenv("AFL_INST_RATIO");
    if (x) inst_ratio = atoi(x);

    if (!inst_ratio || inst_ratio > 100) {
        fprintf(stderr, "[-] ERROR: Invalid AFL_INST_RATIO (must be 1-100).\n");
        abort();
    }

    /* Make sure that the first element in the range is always set - we use that
       to avoid duplicate calls (which can happen as an artifact of the underlying
       implementation in LLVM). */

    *(start++) = TS_R(MAP_SIZE - 1) + 1;

    while (start < stop) {

        if (TS_R(100) < inst_ratio) *start = TS_R(MAP_SIZE - 1) + 1;
        else *start = 0;

        start++;

    }

}

// 前者的简单版本
void __ts_trace_simple_br_cmp_tt(s32 thenEdge, s32 elseEdge, u32 cond, u32 size, u64 arg1, u64 arg2) {}
void __ts_trace_simple_phantom_cmp_tt(s32 thenEdge, s32 elseEdge, u32 cond, u32 size, u64 arg1, u64 arg2) {}
