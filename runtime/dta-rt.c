#define _GNU_SOURCE

#include <stdint.h>
#include <udis86.h>
#include <unistd.h>
#include <ucontext.h>
#include <signal.h>

#include <stdlib.h>
#include <string.h>

#define DEBUG 1

typedef uint32_t u32;
typedef int32_t s32;
#ifdef __x86_64__
typedef unsigned long long u64;
#else
typedef uint64_t u64;
#endif

#ifdef USE_TRACE_PC
#  define CONST_PRIO 5
#else
#  define CONST_PRIO 0
#endif /* ^USE_TRACE_PC */

void __ts_trace_simple_br_cmp_tt(s32 thenEdge, s32 elseEdge, u32 cond, u32 size, u64 arg1, u64 arg2) {}

void __ts_trace_simple_phantom_cmp_tt(s32 thenEdge, s32 elseEdge, u32 cond, u32 size, u64 arg1, u64 arg2) {}

void __ts_trace(u64 arg, u32 size) {}

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
#ifndef DEBUG  
   if (ud_decode(&ud_obj))
#else
   if (ud_disassemble(&ud_obj))
#endif 
   {
       uint32_t len = ud_insn_len(&ud_obj);
       printf("64: %s, pc: %lx\n", ud_insn_asm(&ud_obj), pc);
       if (!is_raise(&ud_obj, len)) {
           ctx->uc_mcontext.gregs[REG_RIP] += len;
       }
   }
#else
   uint64_t pc = ctx->uc_mcontext.gregs[REG_EIP];
   ud_set_input_buffer(&ud_obj, (const uint8_t *) pc, 15);
#ifndef DEBUG  
   if (ud_decode(&ud_obj))
#else
   if (ud_disassemble(&ud_obj))
#endif 
   {
       uint32_t len = ud_insn_len(&ud_obj);
         printf("32: %s\n", ud_insn_asm(&ud_obj));
       if (!is_raise(&ud_obj, len)) {
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
 
   ud_init(&ud_obj);
#if __WORDSIZE == 64
   ud_set_mode(&ud_obj, 64);
#else
   ud_set_mode(&ud_obj, 32);
#endif

#ifdef DEBUG
   printf("[debug mode]\n");
   ud_set_syntax(&ud_obj, UD_SYN_INTEL);
#endif

   ignore_crash(SIGSEGV);
   ignore_crash(SIGFPE);
   ignore_crash(SIGILL);
   ignore_crash(SIGBUS);
}