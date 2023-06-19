//
// Created by camsyn on 2022/6/24.
//

#define AFL_MAIN

#include "android-ashmem.h"

#define MESSAGES_TO_STDOUT

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _FILE_OFFSET_BITS 64

#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "alloc-inl.h"
#include "config.h"
#include "debug.h"
#include "enhancement.h"
#include "hash.h"

enum fuzz_strategy {
    Origin, HavocDTA, RandEdge, RandSplice
};

typedef enum fuzz_strategy FuzzStrategy;

FuzzStrategy fuzz_st;

// ------------------------ From AFL-Fuzz -------------------------------------
static s32 dev_null_fd = -1;
static s32 out_fd = -1;
static u8 *out_file, /* File to fuzz, if any             */
    *out_dir,        /* Working & output directory       */
    *syn_dir;
static u8 *DTA_file = NULL;
static s32 DTA_fd;
static char **DTA_argv;
static u8 *source_map_file;
static u8 *phantom_bitmap_file;

enum {
  /* 00 */ FAULT_NONE,
  /* 01 */ FAULT_TMOUT,
  /* 02 */ FAULT_CRASH,
  /* 03 */ FAULT_ERROR,
  /* 04 */ FAULT_NOINST,
  /* 05 */ FAULT_NOBITS
};

static void write_for_DTA(void *mem, u32 len) {
  s32 fd = DTA_fd;
  
  if (DTA_file) {

      unlink(DTA_file); /* Ignore errors. */

      fd = open(DTA_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

      if (fd < 0) PFATAL("Unable to create '%s'", DTA_file);

  } else lseek(fd, 0, SEEK_SET);

  ck_write(fd, mem, len, out_file);

  if (!DTA_file) {

      if (ftruncate(fd, len)) PFATAL("ftruncate() failed");
      lseek(fd, 0, SEEK_SET);

  } else close(fd);
}


static SaveIfInteresting save_if_interesting;
static FuzzBuf tryonce;
static ExecTarget exec_target;
static Write2TestCase write_4_fuzz;
static u32 exec_timeout;
// ----------------------- Only used in concurrent fuzzing
// ------------------------

#define MAX_QUERY_PER_ROUND 1024

#define TsAnswerState ((State)*ts_answer_shm)
#define SetTsAnswerState(state) *ts_answer_shm = (u8)(state)

enum ts_state { INIT, READY, HOLD, OKAY, NONE };
typedef enum ts_state State;

static s32 con_phantom_pid = -1;
// static s32 con_source_pid = -1;
static s32 pin_pid = -1;

struct query {
  u32 query_id;
  u32 num_edge;
};
typedef struct query Query;

struct phantom_edge {
  u32 edge;
  u32 taint_min;
  u32 taint_max;
  u32 reserve;
};
typedef struct phantom_edge PhantomEdge;

struct phantom_seed {
  u32 id;
  u32 seed_len;
  u32 num_edge;
  char seed_name[32];
};
typedef struct phantom_seed PhantomSeed;
typedef char SeedPath[256];

struct answer {
  u8 state;
  u32 num_seed;
  // .... phantom seed
  u32 num_orig_seed;
  // .... orig seed
};
typedef struct answer Answer;

struct edges_with_taint {
  u32 num_edge;
  PhantomEdge *edges;
};
typedef struct edges_with_taint TaintedEdges;

TaintedEdges tainted_edges[SEED_SET_SIZE];

static u8 do_ts = 0;
static s32 ts_query_shm_id = -1;
static s32 ts_ans_shm_id = -1;
static u8 *ts_query_shm;
static u8 *ts_answer_shm;

static ExtSeed *ext_seed_cache[SEED_SET_SIZE];
static u32 edge_list_idx = 0;
static u8 query_update = 0;

#ifdef DEBUG_INFO
static u32 task_id = 0;
#endif

u32 seed_exec_num = 0;

u32 seed_transfer_num = 0;

// ------------------------My Variable ----------------------------------------
static u8 *ext_dir = NULL;

static s32 expmap_shm_id = -1;         /* ID of the source_map SHM region   */
static s32 bitmap_shm_id = -1;         /* ID of the phantom_bitmap SHM region   */
static s32 taintmap_shm_id = -1;       /* ID of the phantom_bitmap SHM region   */
static s32 phantom_taintmap_shm_id = -1; /* ID of the phantom_bitmap SHM region   */

static u8 *source_map = NULL; /* SHM:
                          main-fuzzing -> required path,
                          mutated-if fuzzing -> exec path  */
static u8 virgin_bits[MAP_SIZE];
static u32 compact_exp_edges[MAP_SIZE];
static u32 source_size;
static u8 edge_ts_cnt[MAP_SIZE];

static u8 *phantom_bitmap = NULL;
static u8 freemap[BITMAP_SIZE]; /* The cumulative coverage of phantom */

static u32 num_new_phantom_edge = 0;
// trick: #(new phantom edge) < 8K
static u32 new_phantom_edges[BITMAP_SIZE];
// descibe loc 0 ~ 2^19
static u8 aug_loc_bitmap[MAP_SIZE];
// The same edge can be augmented at most 8 times!
static u8 aug_edge_map[MAP_SIZE];
// #define set_aug_bitmp(loc) do {; set_bitmap(aug_loc_bitmap, _loc);} while(0)
static u32 aug_loc;
// ----------- ext management ---------------------------
static u8 *ext_bitmap = NULL;
static u8 *cur_seed, *last_seed;
static u32 cur_len, last_len, ext_len, orig_len, llen, slen, tlen;

static ExtSeed *ext_queue_top = NULL;
ExtSeed *ext_queue_head = NULL;
ExtSeed *ext_queue_tail = NULL;
ExtSeed *curExtSeed;

static u32 ext_queue_size = 0;
static u32 cum_ext_queue_size = 0;
static u32 max_ext_seed_size = 0;

// ----------- ext management ---------------------------
u32 *queue_size;

static TaintScope *taint_table = NULL;
static TaintScope *phantom_taint_table = NULL;
static TaintScope *ext_taint_table = NULL;

static char *PIN_PATH = NULL;
static char *TRACK_TOOL = NULL;
static char *TAINT_TARGET = NULL;

static u32 user_argc;
static char **user_argv;

static u32 cur_id, last_id;
static u32 ext_id = 0;

static u32 order = 0;

static TaintMode DTA_mode;

FuzzMode fuzzMode;

static ExtSeed *ts_history[SEED_SET_SIZE];

static u8 *ext_buf = NULL, *out_buf = NULL, *in_buf = NULL, *last_buf = NULL;
u8 *shared_file = NULL;
// static u32 out_len;

static u8 max_size_update = 0; /* max ext seed size is updated */

// --------------------- debug time ----------------------
u64 random_time = 0, dry_time = 0, taint_query_time = 0, taint_splice_time = 0,
    query_time = 0, parse_answer_time = 0, pre_splice_time = 0, DTA_time = 0,
    d_mutate_time = 0, my_total_time = 0, afl_time = 0, delta;

u8 *time_log_file;
u8 print_time_count = 0;
u8 debug_mode = 0;
// ------------------------My Variable ----------------------------------------

// -------------------- My Function ------------------------------------
// static u32 *taint_map[MAP_SIZE];
// static u32 taint_num_map[MAP_SIZE];
FILE *__log = NULL;
char *logfile = "log.txt";

#define in_bitmap(bitmap, num) ((bitmap[(num) >> 3]) & ((u8)(1 << ((num)&7))))
#define set_bitmap(bitmap, loc) bitmap[(loc) >> 3] |= ((u8)(1 << ((loc)&7)))
#define clear_bitmap(bitmap, loc) bitmap[(loc) >> 3] &= ~((u8)(1 << ((loc)&7)))
#define source_edge_passed(edge) (virgin_bits[edge] == 0)

static void write_map() {
  if (fuzzMode == ConSource || fuzzMode == Source || fuzzMode == Integrated) {
    unlink(source_map_file); /* Ignore errors. */
    s32 fd = open(source_map_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", source_map_file);

    ck_write(fd, virgin_bits, MAP_SIZE, source_map_file);

    close(fd);
  }
  if (fuzzMode == MutateIf || fuzzMode == ConMutateIf ||
      fuzzMode == Integrated) {
    unlink(phantom_bitmap_file); /* Ignore errors. */
    s32 fd = open(phantom_bitmap_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", phantom_bitmap_file);

    ck_write(fd, freemap, BITMAP_SIZE, phantom_bitmap_file);

    close(fd);
  }
}

static inline u8 simple_run_target(void *mem, u32 len) {
  write_4_fuzz(mem, len);

  if (fuzzMode == ConSource || fuzzMode == LafTaint)
    reset_source_shm();
  // trick: double the timeout to ensure the execution.
  return exec_target(user_argv, exec_timeout * 2);
}

static inline void append_to_ext_queue(ExtSeed *q) {
  u32 len = q->seed_len;
  if (max_ext_seed_size < len) {
    max_ext_seed_size = len;
    max_size_update = 1;
  }
  if (ext_queue_top) {
    ext_queue_top->next = q;
    q->last = ext_queue_top;
    ext_queue_top = q;
  } else {
    ext_queue_head = ext_queue_top = q;
    ext_queue_head->last = NULL;
  }
  q->next = NULL;
}
static inline void remove_from_ext_queue(ExtSeed *q) {
  if (q == ext_queue_head) {
    ext_queue_head = curExtSeed->next;
    ext_queue_head->last = NULL;
  } else if (q == ext_queue_top) {
    ext_queue_top = curExtSeed->last;
    ext_queue_top->next = NULL;
  } else {
    q->last->next = q->next;
    q->next->last = q->last;
  }
  ext_queue_size--;
}
static inline void move_to_top_when_taint_miss(ExtSeed *q) {
  if (!ext_queue_tail) {
    ext_queue_tail = q;
  }
  remove_from_ext_queue(q);
  append_to_ext_queue(q);
}

static ExtSeed *create_to_ext_queue(u8 *name, u8 *taintmap_name,
                                    u8 *bitmap_name, u8 *seed_name, __off_t len,
                                    u32 id) {
  ExtSeed *q = ck_alloc(sizeof(struct ext_queue_entry));

  q->taintmap_name = ck_strdup(taintmap_name);
  q->bitmap_name = ck_strdup(bitmap_name);
  q->seed_name = ck_strdup(seed_name);
  q->name = ck_strdup(name);
  q->seed_len = len;
  q->next = NULL;
  q->id = id;

  append_to_ext_queue(q);

  ext_queue_size++;

  return q;
}

static inline u64 get_cur_time(void) {
  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + (tv.tv_usec);
}

static void taint_query(u32 edge, u32 *min_loc, u32 *max_loc, TaintMode mode) {
  if (DTA_mode == NO_TAINT) return;
  u64 time = get_cur_time();
  TaintScope *scope;
  switch (mode) {
    case SOURCE_TAINT:
      scope = taint_table ? taint_table + edge : NULL;
      break;
    case PHANTOM_TAINT:
      scope = phantom_taint_table ? phantom_taint_table + edge : NULL;
      break;
    case EXT_TAINT:
      if (fuzzMode == ConSource) {
        TaintedEdges *edges = (tainted_edges + (curExtSeed->id));
        PhantomEdge *edge = (edges->edges) + edge_list_idx;
        *min_loc = edge->taint_min;
        *max_loc = edge->taint_max;
        taint_query_time += get_cur_time() - time;
        return;
      } else {
        scope = ext_taint_table ? ext_taint_table + edge : NULL;
      }
      break;
    default:
      scope = NULL;
      break;
  }

  if (scope) {
    *min_loc = scope->min;
    *max_loc = scope->max;
  }

  taint_query_time += get_cur_time() - time;
}

void update_source_virgin_bits() {
  if (fuzzMode != LafTaint && fuzzMode != ConSource) {
    return;
  }
#ifdef WORD_SIZE_64

  u64 *current = (u64 *)source_map;
  u64 *virgin = (u64 *)virgin_bits;

  u32 i = (MAP_SIZE >> 3);

#else
  u32 *current = (u32 *)source_map;
  u32 *current = (u32 *)virgin_bits;

  u32 i = (MAP_SIZE >> 2);

#endif /* ^WORD_SIZE_64 */

  while (i--) {
    if (unlikely(*current)) {
      *virgin &= ~(*current);
    }
    current++;
    virgin++;
  }
}

/**
 * Update and compact the source edges list
 *
 */
// todo : 8个一组进行检索
static inline void update_compact_exp_edges() {
#ifdef WORD_SIZE_64

  u64 *current = (u64 *)source_map;
  u64 *virgin = (u64 *)virgin_bits;

  u32 i = (MAP_SIZE >> 3);
  static const u8 BOUND = 8;

#else
  u32 *current = (u32 *)source_map;
  u32 *virgin = (u32 *)virgin_bits;

  u32 i = (MAP_SIZE >> 2);
  static const u8 BOUND = 4;

#endif /* ^WORD_SIZE_64 */

  source_size = 0;

  while (i--) {
    if (unlikely(*current)) {
      *virgin &= ~(*current);

      u8 *vir = (u8 *)virgin, *cur = (u8 *)current;
      u8 idx = 0;
      u32 edge = cur - source_map;
      do {
        if (unlikely(vir[idx])) {
          if (unlikely(cur[idx]) && edge_ts_cnt[edge] < SPLICE_EDGE_TIME &&
              in_bitmap(freemap, edge)) {
            LOGD("%u ", edge);
            compact_exp_edges[source_size++] = edge;
          }
        }
        edge++;
      } while (++idx != BOUND);
    }
    current++;
    virgin++;
  }
  LOGD("\n");
}

static inline void update_compact_exp_edges_loosely() {
#ifdef WORD_SIZE_64

  u64 *current = (u64 *)source_map;
  u64 *virgin = (u64 *)virgin_bits;

  u32 i = (MAP_SIZE >> 3);
  static const u8 BOUND = 8;

#else
  u32 *current = (u32 *)source_map;
  u32 *current = (u32 *)virgin_bits;

  u32 i = (MAP_SIZE >> 2);
  static const u8 BOUND = 4;

#endif /* ^WORD_SIZE_64 */

  source_size = 0;

  while (i--) {
    if (unlikely(*current)) {
      *virgin &= ~(*current);

      u8 *vir = (u8 *)virgin, *cur = (u8 *)current;
      u8 idx = 0;
      u32 edge = cur - source_map;
      do {
        if (unlikely(vir[idx])) {
          if (unlikely(cur[idx]) && edge_ts_cnt[edge] < SPLICE_EDGE_TIME) {
            compact_exp_edges[source_size++] = edge;
            LOGD("%u ", edge);
          }
        }
        edge++;
      } while (++idx != BOUND);
    }
    current++;
    virgin++;
  }

  LOGD("\n");
}

static void load_ext_taint_table(ExtSeed *seed) {
  if (ext_taint_table)
    munmap((void *)ext_taint_table, MAP_SIZE * sizeof(TaintScope));

  if (DTA_mode == PHANTOM_TAINT) {
    s32 fd = open(seed->taintmap_name, O_RDONLY);

    if (fd < 0) {
      ext_taint_table = NULL;
      move_to_top_when_taint_miss(seed);
    } else {
      ext_taint_table =
          (TaintScope *)mmap(0, MAP_SIZE * sizeof(TaintScope),
                             PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    }

    close(fd);
  } else {
    ext_taint_table = NULL;
  }
}

static void parse_answer() {
  u64 time = get_cur_time();

  u32 num_seed = *((u32 *)(ts_answer_shm + 1));
  u8 *ptr = ts_answer_shm + 5;

  max_ext_seed_size = 0;
  ext_queue_head = ext_queue_top = NULL;
  cum_ext_queue_size = num_seed;
  while (num_seed--) {
    u32 id = *((u32 *)ptr), num_edges = *((u32 *)(ptr + 8));
    LOGD("\text_id: %u, ", id);
    ExtSeed *ext_seed = ext_seed_cache[id];
    if (ext_seed) {
      append_to_ext_queue(ext_seed);
      ptr += 44;

      LOGD("Cached, Get Ext Seed: %s\n", ext_seed->seed_name);
    } else {
      u32 seed_len = *((u32 *)(ptr + 4));
      ptr += 12;

      u8 *name = ptr, *seed_path;
      seed_path = alloc_printf("%s/seeds/%s", ext_dir, name);
      ext_seed = create_to_ext_queue(name, NULL, NULL, seed_path, seed_len, id);
      ck_free(seed_path);

      ext_seed_cache[id] = ext_seed;

      ptr += 32;
      LOGD("Parsed, Get Ext Seed: %s\n", ext_seed->seed_name);
    }
    LOGD("\t\tRelevant Edge Num: %u\n", num_edges);

    TaintedEdges *edges = tainted_edges + id;
    edges->num_edge = num_edges;
    ck_free(edges->edges);
    u32 size = num_edges * sizeof(PhantomEdge);
    edges->edges = ck_alloc_nozero(size);
    memcpy(edges->edges, ptr, size);
    ptr += size;
  }

  LOGD("handling answer, phantom_seed num: %u, orig_seed num: %u ...\n",
       cum_ext_queue_size, seed_exec_num);

  time = get_cur_time() - time;
  parse_answer_time += time;
}

static void ts_query(u32 curr_id, u8 *curr_seed_path, u8 *curr_buf,
                     u32 curr_len) {
  u64 time = get_cur_time();

  // reset_source_shm();
  // tryonce(user_argv, curr_buf, curr_len);
  LOGD("------------------\n");
  simple_run_target(curr_buf, curr_len);
  update_compact_exp_edges_loosely();
  LOGD("Task id: %u, Request for seed: %u\n", task_id++, curr_id);
  u32 *ptr = (u32 *)ts_query_shm;
  *(ptr++) = curr_id;
  *(ptr++) = source_size;
  memcpy(ptr, compact_exp_edges, source_size * 4);
  ptr += source_size;
  strcpy((u8 *)ptr, curr_seed_path);

  SetTsAnswerState(HOLD);

  kill(con_phantom_pid, SIGRTMAX);

  time = get_cur_time() - time;
  query_time += time;
}

static void parse_query(u32 *id) {
  // resolve query id
  u32 *ptr = (u32 *)ts_query_shm;
  u32 q_id = *(ptr++);
  *id = q_id;
  u32 num_edge = *(ptr++);

  ExtSeed *seed = ts_history[q_id];
  source_size = 0;
  // Only if has next phantom seed, the edges effects.
  if (next_ext_seed(&seed)) {
    LOGD("Get Request, edge after filter: ");
    while (num_edge--) {
      u32 edge = *(ptr++);
      if (in_bitmap(freemap, edge) == 0) {
        LOGD("%u ", edge);
        compact_exp_edges[source_size++] = edge;
      }
    }
    LOGD("\n");
  } else {
    LOGD("No new phantom seed\n");
    ptr += num_edge;
  }

  LOGD("q_id: %u, ext_id: %u, q_seed: %s\n", q_id,
       ts_history[q_id] ? ts_history[q_id]->id : 0, (char *)ptr);
}

static ExtSeed * ts_answer(ExtSeed *seed) {
  u32 explore_id = 0, explore_edge;
  curExtSeed = NULL;
  u32 *num_seed = (u32 *)(ts_answer_shm + 1);
  u8 *ptr = (u8 *)(num_seed + 1);
  *num_seed = 0;

  while (source_size && next_ext_seed(&seed)) {
    load_ext_seed(seed);
    u32 *seed_id = (u32 *)ptr;
    u32 *seed_len = seed_id + 1;
    u32 *num_edge = seed_id + 2;
    *num_edge = 0;
    if (next_explore_edge(&explore_edge, &explore_id)) {
      
      *seed_id = seed->id;
      *seed_len = seed->seed_len;
      // The length of short name of phantom seed must be lesser than 32.
      strcpy(ptr + 12, seed->name);
      LOGD("\tExt Seed: %s\n", seed->name);
      load_ext_taint_table(seed);
      ptr += 44;
      do {
        u32 min_loc = 0, max_loc = 0;
        taint_query(explore_edge, &min_loc, &max_loc, EXT_TAINT);
        LOGD("\t\tedge: %u, min: %u, max: %u\n", explore_edge, min_loc,
             max_loc);

        PhantomEdge m_edge = {explore_edge, min_loc, max_loc, 0};
        memcpy(ptr, &m_edge, sizeof(PhantomEdge));
        ptr += sizeof(PhantomEdge);
        if (ptr >= ts_answer_shm + TS_ANS_SHM_SIZE) {
          SetTsAnswerState(OKAY);
          return seed; 
        }
        (*num_edge)++;
      } while (next_explore_edge(&explore_edge, &explore_id));
      (*num_seed)++;
    }
  }
  SetTsAnswerState((*num_seed) == 0 ? NONE : OKAY);
  return ext_queue_tail ? ext_queue_tail->last : ext_queue_top;
}

static void con_query_handler(int sig) {
  u32 query_id;
  LOGD("---- task id: %u, ext id : %u ---\n", task_id++, ext_id);

  parse_query(&query_id);

  ExtSeed *seed = ts_history[query_id];
  ts_history[query_id] = ts_answer(seed);
  // read_seed_2_tmp_buf(query_seed);
  query_update = 1;
  // 万万不可，若此时正有process读取该文件，会引发错误？
  // tryonce(user_argv, in_buf, len);

 
}

void show_trace_bits(u8 *bits) {
  u32 idx = 0;
  while (idx != MAP_SIZE) {
    if (*bits) {
      LOGD("edge: %u, val: %u\n", idx, *bits);
    }
    bits++;
    idx++;
  }
}

static inline void printBitmap(u8 *bitmap, u8 reverse) {
  u8 *ptr = bitmap;
  u32 num = 0;
  u8 mask = reverse == 1 ? 0xff : 0;
  while (ptr != bitmap + BITMAP_SIZE) {
    u8 bitmap_entry = (*ptr) ^ mask;

    if (bitmap_entry) {
      u8 bit = 0;
      while (bit != 8) {
        if (bitmap_entry & (0x1 << bit)) {
          LOGD("%d ", num + bit);
        }
        bit++;
      }
    }
    ptr++;
    num += 8;
  }
  LOGD("\n\n");
}

static inline u8 has_new_phantom(u8 augment_mode) {
#ifdef WORD_SIZE_64

  u64 *current = (u64 *)phantom_bitmap;
  u64 *free = (u64 *)freemap;

  u32 i = (BITMAP_SIZE >> 3);
  static const u8 BOUND = 8;

#else
  u32 *current = (u32 *)phantom_bitmap;
  u32 *free = (u32 *)freemap;

  u32 i = (BITMAP_SIZE >> 2);
  static const u8 BOUND = 4;

#endif /* ^WORD_SIZE_64 */

  u8 ret = 0;
  while (i--) {
    /* Optimize for (*current & *free) == 0 - i.e., no bits in current bitmap
    that have not been already cleared from the free map - since this will
    almost always be the case. */

    if (unlikely(*current)) {
      if (unlikely(*current & *free)) {
        u8 idx = 0;
        u8 *cur = ((u8 *)current), *fr = ((u8 *)free);
        do {
          u8 c = cur[idx], f = fr[idx];
          if (c && (c & f)) {
            u32 edge = (cur + idx - phantom_bitmap) << 3;
            u8 probe = 0x1;
            do {
              if ((c & probe) && (f & probe)) {
                new_phantom_edges[num_new_phantom_edge] = edge;
                if (num_new_phantom_edge < BITMAP_SIZE - 1) {
                  num_new_phantom_edge++;
                }
              }
              edge++;
              probe <<= 1;
            } while (probe);
          }
        } while (++idx != BOUND);
        if (!augment_mode) *current &= *free;
        *free &= ~*current;
        ret = 1;
      }
      // Reduce redundunt phantom edge.
      else if (!augment_mode) {
        *current = 0;
      }
    }
    current++;
    free++;
  }
  return ret;
}

static u8 *mutate_deterministic(u8 *mem, u32 len, u32 loc, s8 direction,
                                u32 curr_id, u8 try_times) {
  if (!try_times) {
    return mem;
  }
  u8 num = 0;
  if (direction == 0) {
    aug_loc = loc;
    u8 cache = mem[loc];
    do {
      mem[loc] = num;
      u8 fault = simple_run_target(mem, len);

      if (fault == FAULT_TMOUT || fuzzMode == ConSource || fuzzMode == LafTaint ||
          save_if_meet_new_phantom(mem, len, user_argv, 0, curr_id)) {
        u8 flag =  save_if_interesting(user_argv, mem, len, fault);
        if ( flag ) 
          update_source_virgin_bits();
      }
      num++;
    } while (num);
    mem[loc] = cache;
  } else {
    loc += direction;
    if (loc == 0xffffffff) {
      return mem;
    } else if (loc >= len) {
      if (len >= (cur_len) || !in_buf) {
        orig_len = len << 1;
        u8 *new_mem = ck_alloc_nozero(orig_len);
        memcpy(new_mem, mem, len);
        // orig_in = ck_realloc(orig_in, orig_len);
        ck_free(mem);
        mem = new_mem;
      }

      len++;
      LOGD("ext seed len expand, %u -> %u\n", len - 1, len);
    }

    u8 cache = mem[loc];
    u8 num = 0;
    u8 flag = 1;
    do {
      mem[loc] = num;
      // tryonce(user_argv, mem, len);
      u8 fault = simple_run_target(mem, len);
      aug_loc = loc;
      mem[loc] = num;
      if (fault == FAULT_TMOUT) {
        save_if_interesting(user_argv, mem, len, fault);
      } else if (save_if_meet_new_phantom(mem, len, user_argv, 0, curr_id)) {
        save_if_interesting(user_argv, mem, len, fault);
        flag = 0;
        mem = mutate_deterministic(mem, len, loc, direction, curr_id, 2);
        cache = num;
      }
      num++;
    } while (num);
    mem[loc] = cache;
    if (try_times > 1 && flag) {
      mem = mutate_deterministic(mem, len, loc, direction, curr_id,
                                 try_times - 1);
    }
  }
  return mem;
}

static inline void fill_freemap(u8 *ext_bitmap) {
#ifdef WORD_SIZE_64

  u64 *current = (u64 *)ext_bitmap;
  u64 *free = (u64 *)freemap;

  u32 i = (BITMAP_SIZE >> 3);

#else
  u32 *current = (u32 *)ext_bitmap;
  u32 *free = (u32 *)freemap;

  u32 i = (BITMAP_SIZE >> 2);

#endif /* ^WORD_SIZE_64 */

  while (i--) {
    /* Optimize for (*current & *free) == 0 - i.e., no bits in current bitmap
    that have not been already cleared from the free map - since this will
    almost always be the case. */

    if (unlikely(*current) && unlikely(*current & *free)) {
      *free &= ~*current;
    }

    current++;
    free++;
  }
}

static inline void save_as_ext_seed(void *mem, u32 len, u8 *filename) {
  s32 fd;
  u8 *taintmap_path = NULL;

  if (DTA_mode == PHANTOM_TAINT) {
    taintmap_path = alloc_printf("%s/taint_map/%s", out_dir, filename);
    fd = open(taintmap_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", taintmap_path);
    ck_write(fd, (u8 *)phantom_taint_table, MAP_SIZE * sizeof(TaintScope),
             taintmap_path);
    close(fd);
  }

  u8 *bitmap_path = alloc_printf("%s/phantom_bitmap/%s", out_dir, filename);
  fd = open(bitmap_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", bitmap_path);
  ck_write(fd, (u8 *)phantom_bitmap, BITMAP_SIZE, bitmap_path);
  close(fd);

  u8 *seed_path = alloc_printf("%s/seeds/%s", out_dir, filename);
  fd = open(seed_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", seed_path);
  ck_write(fd, mem, len, seed_path);

  close(fd);

  if (fuzzMode == Integrated || fuzzMode == ConMutateIf) {
    create_to_ext_queue(filename, taintmap_path, bitmap_path, seed_path, len,
                        cum_ext_queue_size++);
  }
  ck_free(taintmap_path);
  ck_free(bitmap_path);
  ck_free(seed_path);
}

int save_if_meet_new_phantom(void *content, u32 len, char **argv, u8 augment_mode,
                           u32 curr_id) {
  if (fuzzMode != ConMutateIf) return 0;
  if (has_new_phantom(augment_mode)) {
    u8 *filename = augment_mode
                       ? alloc_printf(PHANTOM_PREFIX "%u,src:%u", ext_id, curr_id)
                       : alloc_printf(PHANTOM_PREFIX "%u,from:%u,aug:%u", ext_id,
                                      curr_id, aug_loc);

    if (DTA_mode == PHANTOM_TAINT) {
      // 若触发新边大于 2， 则可认为 augment直接贯穿了nested if,
      // 进入了更多的新状态，而不仅仅是一层if
      if (num_new_phantom_edge > 2) {
        augment_mode = 1;
      }
      if (augment_mode) {
        taint_analyze(content, len, PHANTOM_TAINT, DTA_argv);
      } else {
        // 非aug mode的aug loc已知，不必进行重型的DTA
        u32 idx = 0;
        do {
          u32 edge = new_phantom_edges[idx];
          // todo : 这里taint loc len直接定为 1 ，真的可以吗？
          // 需不需要设置对应freemap bit无效化
          TaintScope s = {aug_loc, aug_loc + 1};
          LOGD("\tcollect edge: %u , loc: %u\n", edge, aug_loc);
          phantom_taint_table[edge] = s;
        } while (++idx != num_new_phantom_edge);
        num_new_phantom_edge = 0;
      }
    }

    save_as_ext_seed(content, len, filename);
    LOGD("store ext seed: %s\n", filename);

    // Search for the neighbor phantom edge.
    curr_id = ext_id++;
    if (augment_mode) {
      u32 *aug_locs = (u32 *)ck_alloc(num_new_phantom_edge << 2);
      u32 min = 0, max = 0;
      u32 idx = 0, aug_num = 0;
      do {
        u32 edge = new_phantom_edges[idx];
        taint_query(edge, &min, &max, PHANTOM_TAINT);

        if (max - min == 1) {
          u32 _loc = min & 0x3ffff;
          clear_bitmap(aug_loc_bitmap, _loc);
          LOGD("\tAugment loc %u, edge: %u\n", min, edge);
          aug_locs[aug_num++] = min;
        } else
        // if (debug_mode)
        {
          LOGD("\tTainted loc [ %u, %u ), edge: %u\n", min, max, edge);
        }
      } while (++idx != num_new_phantom_edge);
      num_new_phantom_edge = 0;

      u8 *orig_buf = NULL;
      if (aug_num) {
        orig_len = len << 1;
        orig_buf = ck_alloc_nozero(orig_len);
      }
      while (aug_num--) {
        u32 loc = aug_locs[aug_num];

        u32 _loc = loc & 0x3ffff;
        if (in_bitmap(aug_loc_bitmap, _loc)) {
          continue;
        }
        set_bitmap(aug_loc_bitmap, _loc);

        memcpy(orig_buf, content, len);
        orig_buf = mutate_deterministic(orig_buf, len, loc, 1, curr_id, 1);
        orig_buf = mutate_deterministic(orig_buf, len, loc, 0, curr_id, 1);
        orig_buf = mutate_deterministic(orig_buf, len, loc, -1, curr_id, 1);
      }
      if (orig_buf) ck_free(orig_buf);
      ck_free(aug_locs);
    }

    ck_free(filename);

    return 1;
  }
  return 0;
}

void reset_taint_shm(TaintMode mode) {
  switch (mode) {
    case SOURCE_TAINT:
      if (taint_table)
        memset((u8 *)taint_table, 0, MAP_SIZE * sizeof(TaintScope));
      break;
    case PHANTOM_TAINT:
      if (phantom_taint_table)
        memset((u8 *)phantom_taint_table, 0, MAP_SIZE * sizeof(TaintScope));
      break;
    default:
      break;
  }
}

void reset_phantom_shm() {
  if (phantom_bitmap) memset((u8 *)phantom_bitmap, 0, BITMAP_SIZE);
}

void reset_source_shm() {
  if (source_map) {
    memset((u8 *)source_map, 0, MAP_SIZE);
  }
}

static void remove_shm(void) {
  if (expmap_shm_id != -1) shmctl(expmap_shm_id, IPC_RMID, NULL);
  if (bitmap_shm_id != -1) shmctl(bitmap_shm_id, IPC_RMID, NULL);
  if (taintmap_shm_id != -1) shmctl(taintmap_shm_id, IPC_RMID, NULL);
  if (phantom_taintmap_shm_id != -1)
    shmctl(phantom_taintmap_shm_id, IPC_RMID, NULL);
  if (ts_ans_shm_id != -1) shmctl(ts_ans_shm_id, IPC_RMID, NULL);
  if (ts_query_shm_id != -1) shmctl(ts_query_shm_id, IPC_RMID, NULL);

  if (fuzzMode == ConMutateIf) {
    unlink(shared_file);
  }
}

static void setup_shm() {
  u8 *shm_str;
  atexit(remove_shm);

  // init source_map
  if (fuzzMode == ConSource || fuzzMode == LafTaint) {
    expmap_shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

    if (expmap_shm_id < 0) PFATAL("shmget() failed");

    shm_str = alloc_printf("%d", expmap_shm_id);

    /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

    setenv(SHM_SOURCE_MAP_ENV_VAR, shm_str, 1);

    ck_free(shm_str);

    source_map = shmat(expmap_shm_id, NULL, 0);

    if (source_map == (void *)-1) PFATAL("shmat() failed");

    // init taint map

    taintmap_shm_id = shmget(IPC_PRIVATE, MAP_SIZE * sizeof(TaintScope),
                             IPC_CREAT | IPC_EXCL | 0600);

    if (taintmap_shm_id < 0) PFATAL("shmget() failed");

    shm_str = alloc_printf("%d", taintmap_shm_id);

    /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

    setenv(SHM_TAINT_MAP_ENV_VAR, shm_str, 1);

    ck_free(shm_str);
    taint_table = shmat(taintmap_shm_id, NULL, 0);
    if (taint_table == (void *)-1) PFATAL("shmat() failed");
  }

  if (fuzzMode == ConMutateIf) {
    // init phantom_bitmap

    bitmap_shm_id =
        shmget(IPC_PRIVATE, BITMAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

    if (bitmap_shm_id < 0) PFATAL("shmget() failed");

    shm_str = alloc_printf("%d", bitmap_shm_id);

    /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
    we don't want them to detect instrumentation, since we won't be sending
    fork server commands. This should be replaced with better auto-detection
    later on, perhaps? */

    setenv(SHM_PHANTOM_BITMAP_ENV_VAR, shm_str, 1);

    ck_free(shm_str);

    phantom_bitmap = shmat(bitmap_shm_id, NULL, 0);

    if (phantom_bitmap == (void *)-1) PFATAL("shmat() failed");

    phantom_taintmap_shm_id = shmget(IPC_PRIVATE, MAP_SIZE * sizeof(TaintScope),
                                   IPC_CREAT | IPC_EXCL | 0600);

    if (phantom_taintmap_shm_id < 0) PFATAL("shmget() failed");

    shm_str = alloc_printf("%d", phantom_taintmap_shm_id);

    setenv(SHM_PHANTOM_TAINT_MAP_ENV_VAR, shm_str, 1);

    ck_free(shm_str);
    phantom_taint_table = shmat(phantom_taintmap_shm_id, NULL, 0);
    if (phantom_taint_table == (void *)-1) PFATAL("shmat() failed");

    // 1M shared mem
    ts_query_shm_id =
        shmget(IPC_PRIVATE, TS_QUERY_SHM_SIZE, IPC_CREAT | IPC_EXCL | 0600);
    if (ts_query_shm_id < 0) PFATAL("shmget() failed");
    ts_query_shm = (u8 *)shmat(ts_query_shm_id, NULL, 0);
    if (ts_query_shm == (void *)-1) PFATAL("shmat() failed");

    // 1M shared mem
    ts_ans_shm_id =
        shmget(IPC_PRIVATE, TS_ANS_SHM_SIZE, IPC_CREAT | IPC_EXCL | 0600);
    if (ts_ans_shm_id < 0) PFATAL("shmget() failed");
    ts_answer_shm = (u8 *)shmat(ts_ans_shm_id, NULL, 0);
    if (ts_query_shm == (void *)-1) PFATAL("shmat() failed");

  }

  

  if (fuzzMode == ConMutateIf) {

  }


}

static void setup_DTA_argv_file() {
  u32 i = 0;
  u8 *cwd = getcwd(NULL, 0);
  DTA_argv = ck_alloc(user_argc * sizeof(char *));

  if (!cwd) PFATAL("getcwd() failed");

  while (user_argv[i]) {
    u8 *aa_loc = strstr(user_argv[i], ".cur_input");
    if (aa_loc) {
      u8 *n_arg;

      /* If we don't have a file name chosen yet, use a safe default. */

      if (!DTA_file) DTA_file = alloc_printf("%s/.cur_input_DTA", out_dir);

      /* Be sure that we're always using fully-qualified paths. */

      /* Construct a replacement argv value. */

      *aa_loc = 0;
      n_arg =
          alloc_printf("%s%s%s", user_argv[i], ".cur_input_DTA", aa_loc + 10);
      DTA_argv[i] = n_arg;
      *aa_loc = '.';
    } else {
      DTA_argv[i] = user_argv[i];
    }

    i++;
  }

  free(cwd); /* not tracked */
}


void setup_stdin_file_for_DTA(void) {

    u8 *fn = alloc_printf("%s/.cur_input_DTA", out_dir);

    unlink(fn); /* Ignore errors */

    DTA_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

    if (DTA_fd < 0) PFATAL("Unable to create '%s'", fn);

    ck_free(fn);
}

static void setup_DTA() {
  PIN_PATH = alloc_printf("%s/pin", getenv("PIN_ROOT"));
  reset_taint_shm(SOURCE_TAINT);
  reset_taint_shm(PHANTOM_TAINT);
  u8 *path = getenv("MIRAGE_PATH");
  if (path) {
    if (path[strlen(path) - 1] == '/')
      TRACK_TOOL =
          alloc_printf("%s/pin_track.so", getenv("MIRAGE_PATH"));
    else
      TRACK_TOOL =
          alloc_printf("%s/pin_track.so", getenv("MIRAGE_PATH"));
  } else {
    TRACK_TOOL = "./pin_track.so";
  }
}

void phantom_write_info_2_mmap() {
  if (fuzzMode != ConMutateIf) return;

  int fd = open(shared_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    PFATAL("open() failed");
  }

  if (ftruncate(fd, SHARE_SIZE)) PFATAL("ftruncate() failed");

  char *mm = (char *)mmap(NULL, SHARE_SIZE, PROT_WRITE, MAP_SHARED, fd, 0);
  if (mm == MAP_FAILED) {
    PFATAL("mmap() failed");
  }
  close(fd);

  s32 *ptr = (s32 *)(mm + 4);
  ptr[0] = getpid();
  ptr[1] = ts_query_shm_id;
  ptr[2] = ts_ans_shm_id;
  strcpy(mm + 16, out_dir);

  LOGD(
      "write info: \n"
      "\tpid: %d, ts_query_id: %d, ts_ans_id: %d\n"
      "\tphantom dir: %s\n",
      ptr[0], ptr[1], ptr[2], mm + 16);
  *mm = READY;

  munmap(mm, SHARE_SIZE);
}

void source_read_info_from_mmap() {
  if (fuzzMode != ConSource || ext_dir != NULL) return;

  int fd = open(shared_file, O_RDWR);
  if (fd < 0) {
    LOGD("open %s fail\n", shared_file);
    return;
  }

  char *mm =
      (char *)mmap(NULL, SHARE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (mm == MAP_FAILED) {
    LOGD("mmap %s fail\n", shared_file);
    close(fd);
    return;
  }

 
  s32 *ptr = (s32 *)(mm + 4);
  con_phantom_pid = ptr[0];
  ts_query_shm_id = ptr[1];
  struct shmid_ds shm_data;
  shmctl(ts_query_shm_id, IPC_STAT, &shm_data);
  if (shm_data.shm_nattch >= 2) {
    LOGD("shared file is not ready to read, %ld processes own the shm %f.\n", 
          shm_data.shm_nattch, ts_query_shm_id);
    close(fd);
    return;
  }

  *mm = INIT;
  ts_ans_shm_id = ptr[2];

  ts_query_shm = (u8 *)shmat(ts_query_shm_id, NULL, 0);
  ts_answer_shm = (u8 *)shmat(ts_ans_shm_id, NULL, 0);

  ext_dir = strdup(mm + 16);

  LOGD(
      "read info: \n"
      "\tpid: %d, ts_query_id: %d, ts_ans_id: %d\n"
      "\tphantom dir: %s\n",
      ptr[0], ptr[1], ptr[2], mm + 16);

  munmap(mm, SHARE_SIZE);
  SetTsAnswerState(READY);

  close(fd);
}

void mem_initialize() {
  memset(edge_ts_cnt, 0, MAP_SIZE);
  memset(virgin_bits, 255, MAP_SIZE);
  memset(freemap, 255, BITMAP_SIZE);
  memset(ts_history, 0, (SEED_SET_SIZE) * sizeof(ExtSeed *));
  memset(aug_edge_map, 0, MAP_SIZE);
}

static inline void setup_files(s32 dev_null_fd_, s32 out_fd_, u8 *out_file_, u8 *out_dir_, u8 *syn_dir_) {
  dev_null_fd = dev_null_fd_;
  out_fd = out_fd_;
  out_file = out_file_;
  out_dir = out_dir_;
  u32 tail = strlen(out_dir)-1;
  if(out_dir[tail] == '/' || out_dir[tail] == '\\') {
    out_dir[tail] = 0;
  }
  syn_dir = syn_dir_ ? syn_dir_ : out_dir;
  tail = strlen(syn_dir)-1;
  if(syn_dir[tail] == '/' || syn_dir[tail] == '\\') {
    syn_dir[tail] = 0;
  }
}

void setup_enhancement(s32 dev_null_fd_, s32 out_fd_, u8 *out_file_, u8 *out_dir_, u8 *syn_dir_,
                       u32 user_argc_, FuzzMode mode, u8 *taint_target,
                       u32 *afl_queue_size, u32 timeout,
                       SaveIfInteresting save_func, FuzzBuf try_once,
                       ExecTarget exec_target_, Write2TestCase w2tc,
                       char **use_argv) {
  user_argv = use_argv;
  exec_timeout = timeout;

  save_if_interesting = save_func;
  tryonce = try_once;
  write_4_fuzz = w2tc;
  exec_target = exec_target_;

  TAINT_TARGET = taint_target;

  fuzzMode = mode;
  queue_size = afl_queue_size;

  user_argc = user_argc_;

  setup_files(dev_null_fd_, out_fd_, out_file_, out_dir_, syn_dir_);
  mem_initialize();

  shared_file = alloc_printf("%s/" SHARE_FILE, syn_dir);

  if (!!getenv("LOG_FILE")) {
    logfile = getenv("LOG_FILE");
  }

  setup_shm();

  if (!getenv("NO_PHANTOM_TAINT")) {
    DTA_mode = PHANTOM_TAINT;
    LOGD("DTA Mode: PHANTOM TAINT\n");
  } else {
    DTA_mode = SOURCE_TAINT;
    LOGD("DTA Mode: CURR TAINT\n");
  }

  if (!!getenv("RAND_SPLICE")) {
     fuzz_st = RandSplice;
     DTA_mode = NO_TAINT;
     LOGD("DTA Mode alter -> No TAINT, as the fuzzing strategy is RandSplice\n");
     OKF("Random Splice Mode");
  } else if (!!getenv("RAND_EDGE")) {
     fuzz_st = RandEdge;
     OKF("Random Edge Mode");

  } else if (!!getenv("HAVOC_DTA")) {
     fuzz_st = HavocDTA;
     fuzzMode = LafTaint;
     OKF("Havoc DTA Mode");
  }

  if (DTA_mode != SOURCE_TAINT ||
      (fuzzMode != MutateIf && fuzzMode != ConMutateIf)) {
    setup_DTA();
  }
  setup_DTA_argv_file();
  if (!DTA_file) 
    setup_stdin_file_for_DTA();

  debug_mode = !!getenv("DEBUG");
  if (fuzzMode == Source) {
    read_ext_seed(ext_dir);
  } else if (fuzzMode == ConSource || fuzzMode == LafTaint) {
    memset(ext_seed_cache, 0, SEED_SET_SIZE * sizeof(ExtSeed *));
    memset(tainted_edges, 0, SEED_SET_SIZE * sizeof(TaintedEdges));
  } else if (fuzzMode == ConMutateIf) {
#ifdef DEBUG_INFO
    if (__log) fclose(__log);
    __log = NULL;
    logfile = alloc_printf("phantom-%s", logfile);
#else

#endif
    LOGD("--- Con Phantom Fuzzing Mode ---\n");
    // Child Process, Concurrent MutateIf Fuzzing
    struct sigaction sa;

    sa.sa_flags = SA_RESTART;
    sa.sa_sigaction = NULL;

    sigemptyset(&sa.sa_mask);

    /* SIGRTMAX: answer the query from source fuzzing */
    sa.sa_handler = con_query_handler;
    sigaction(SIGRTMAX, &sa, NULL);

    phantom_write_info_2_mmap();
  }
  source_map_file = (u8 *)alloc_printf("%s/source_bitmap", out_dir);
  phantom_bitmap_file = (u8 *)alloc_printf("%s/phantom_bitmap", out_dir);
  time_log_file = alloc_printf("%s/time.log", out_dir);
}

int set_taint_target(char *target) {
  if (target) {
    return 0;
  }
  TAINT_TARGET = target;
  return 1;
}

void taint_analysis_run(TaintMode mode, char *argv[]) {
  if (!PIN_PATH) {
    return;
  }
  int status;
  u32 extra_args_num = mode == PHANTOM_TAINT ? 6 : 5;
  u32 arg_idx = 0;
  pid_t pid = fork();
  if (!pid) {
    char **taint_run_argv =
        alloca((user_argc + extra_args_num) * sizeof(char *));
    // int fd = open("taint_analysis.txt", O_WRONLY | O_CREAT | O_EXCL, 0600);
    // redirect standard output and error to file.
    // close(1);
    // close(2);
    // dup(fd);
    // dup(fd);

    taint_run_argv[arg_idx++] = (char *)PIN_PATH;
    taint_run_argv[arg_idx++] = "-t";
    taint_run_argv[arg_idx++] = TRACK_TOOL;
    if (mode == PHANTOM_TAINT) {
      taint_run_argv[arg_idx++] = "-m";
    }
    taint_run_argv[arg_idx++] = "--";
    taint_run_argv[arg_idx++] = (TAINT_TARGET != NULL) ? TAINT_TARGET : argv[0];
    int i = 1;
    for (; i < user_argc; i++) {
      taint_run_argv[arg_idx++] = (char *)argv[i];
    }
    taint_run_argv[arg_idx] = NULL;

    if (debug_mode) {
      char **ptr = taint_run_argv;
      while (*ptr) {
        LOGD("%s \\\n", *ptr);
        ptr++;
      }
      LOGD("\n");
    }


    setsid();

    dup2(dev_null_fd, 1);
    dup2(dev_null_fd, 2);

    if (DTA_file) {

        dup2(dev_null_fd, 0);

    } else {

        dup2(DTA_fd, 0);
        close(DTA_fd);

    }
    close(dev_null_fd);

    reset_taint_shm(mode);
    execvp((char *)PIN_PATH, taint_run_argv);

    PFATAL("execvp() for taint analysis failed!\n"
           "Please check if the PIN_ROOT is correct!\n");
  } else {
    /*不可用SIGALARM设置超时handler，因为其已被AFL占用*/
    pin_pid = pid;

    if (waitpid(pid, &status, 0) <= 0) PFATAL("waitpid() failed");
  }
}

void taint_analyze(u8 *content, u32 len, TaintMode mode, char **argv) {
  if (fuzz_st == RandSplice) return;

  u64 time = get_cur_time();

  write_for_DTA(content, len);
  taint_analysis_run(mode, argv);
  DTA_time += get_cur_time() - time;
}

void read_ext_seed(u8 *ext_dir) {
  struct dirent **nl;
  s32 nl_cnt;
  u32 i;
  u8 *bitmap_dir, *seed_dir, *taintmap_dir;

  ACTF("Scanning '%s'...", ext_dir);
  /* We use scandir() + alphasort() rather than readdir() because otherwise,
     the ordering  of test cases would vary somewhat randomly and would be
     difficult to control. */
  taintmap_dir = alloc_printf("%s/taint_map", ext_dir);
  bitmap_dir = alloc_printf("%s/phantom_bitmap", ext_dir);
  seed_dir = alloc_printf("%s/seeds", ext_dir);
  nl_cnt = scandir(seed_dir, &nl, NULL, alphasort);

  if (nl_cnt < 0) {
    if (errno == ENOENT || errno == ENOTDIR)

      SAYF("\n" cLRD "[-] " cRST
           "The input directory does not seem to be valid - try again. The "
           "fuzzer needs\n"
           "    one or more test case to start with - ideally, a small file "
           "under 1 kB\n"
           "    or so. The cases must be stored as regular files directly in "
           "the input\n"
           "    directory.\n");

    PFATAL("Unable to open '%s'", bitmap_dir);
  }

  for (i = 0; i < nl_cnt; i++) {
    struct stat st;

    u8 *fn = alloc_printf("%s/%s", seed_dir, nl[i]->d_name);
    u8 *fn2 = alloc_printf("%s/%s", bitmap_dir, nl[i]->d_name);
    u8 *fn3 = alloc_printf("%s/%s", taintmap_dir, nl[i]->d_name);
    u8 *name = alloc_printf("%s", nl[i]->d_name);

    free(nl[i]); /* not tracked */

    if (lstat(fn, &st) || access(fn, R_OK)) PFATAL("Unable to access '%s'", fn);

    /* This also takes care of . and .. */

    if (!S_ISREG(st.st_mode) || !st.st_size ||
        strstr(fn, "/README.testcases")) {
      ck_free(fn);
      ck_free(fn2);
      ck_free(fn3);
      ck_free(name);
      continue;
    }

    create_to_ext_queue(name, fn3, fn2, fn, st.st_size, cum_ext_queue_size++);
    ck_free(fn);
    ck_free(fn2);
    ck_free(fn3);
    ck_free(name);

    s32 fd = open(fn2, O_RDONLY);
    if (fd < 0) PFATAL("Unable to open '%s'", fn2);

    if (ext_bitmap) {
      munmap((void *)ext_bitmap, BITMAP_SIZE);
    }

    ext_bitmap = (u8 *)mmap(0, BITMAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    fill_freemap(ext_bitmap);
  }

  free(nl); /* not tracked */

  if (!ext_queue_size) {
    SAYF("\n" cLRD "[-] " cRST
         "Looks like there are no valid test cases in the input directory! The "
         "fuzzer\n"
         "    needs one or more test case to start with - ideally, a small "
         "file under\n"
         "    1 kB or so. The cases must be stored as regular files directly "
         "in the\n"
         "    input directory.\n");

    FATAL("No usable path data in '%s'", bitmap_dir);
  }

  ck_free(taintmap_dir);
  ck_free(bitmap_dir);
  ck_free(seed_dir);

  printBitmap(freemap, 1);
}

u8 *read_ext_phantom_map(const ExtSeed *seed) {
  u32 fd = open(seed->bitmap_name, O_RDONLY);
  if (fd < 0) PFATAL("Unable to open '%s'", seed->bitmap_name);

  u8 *addr = (u8 *)mmap(0, BITMAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);

  close(fd);

  return addr;
}

void check_for_kick_out(ExtSeed *seed) {}

u8 next_ext_seed(ExtSeed **seed) {
  if (!(*seed)) {
    // 若之前已有记录，采用之前的记录
    if (curExtSeed) {
      curExtSeed = *seed = curExtSeed->next;
    }
    // 从头开始
    else {
      curExtSeed = *seed = ext_queue_head;
    }
  } else {
    curExtSeed = *seed = (*seed)->next;
  }

  if (curExtSeed == ext_queue_tail) {
    curExtSeed = *seed = NULL;
  }

  if (curExtSeed && curExtSeed->zombie == 1 && ext_queue_size > 10) {
    *seed = (*seed)->next;
    remove_from_ext_queue(curExtSeed);
    ck_free(curExtSeed);
    curExtSeed = *seed;
  }
  return !!(curExtSeed);
}

/**
 * Get the next node to explore.
 *
 * @param explore_edge the next explore node
 * @param idx the index of curr source parent
 * @return
 */
u8 next_explore_edge(u32 *explore_edge, u32 *idx) {
  if (fuzzMode == ConSource) {
    TaintedEdges *edges = tainted_edges + (curExtSeed->id);
    if (*idx == 0) {
      edge_list_idx = 0;
    } else {
      edge_list_idx++;
    }
    *idx = edge_list_idx + 1;
    if (*idx > edges->num_edge) {
      edge_list_idx = *idx = 0;
      return 0;
    }
    *explore_edge = edges->edges[edge_list_idx].edge;
    return 1;
  } else {
    u32 *exp_edge = compact_exp_edges + (*idx);
    u32 num = *idx;
    while (num != source_size) {
      u32 edge = *exp_edge;
      if (unlikely(in_bitmap(ext_bitmap, edge))) {
        *explore_edge = edge;
        break;
      }
      num++;
      exp_edge++;
    }
    if (num == source_size) {
      if (*idx == 0 && curExtSeed) {
        curExtSeed->cnt++;
        if (curExtSeed->cnt > *queue_size) {
          check_for_kick_out(curExtSeed);
        }
      }
      *idx = 0;
      return 0;
    } else {
      *idx = num + 1;
      return 1;
    }
  }
}

u32 get_ts_cycles(u32 curr_id) {
  if (fuzzMode == ConSource) {
    return cum_ext_queue_size;
  }
  ExtSeed *seed = ts_history[curr_id];
  return seed == NULL ? cum_ext_queue_size : cum_ext_queue_size - (seed->id);
}

void pre_all() {
  switch (fuzzMode) {
    case ConMutateIf:
      return;
    case MutateIf:
      return;
    default:
      delta = get_cur_time();
  }
}

void pre_havoc(u32 curr_id, u8 *curr_seed_path, u8 *curr_buf, u32 curr_len,
               u8 has_new) {
  if (fuzzMode != ConSource) return;
  if (ext_dir == NULL) {
    source_read_info_from_mmap();
  } else {
    if (TsAnswerState != READY) return;

    // if (has_new || !last_buf) {
    //   do_ts = 0;
    //   ck_free(last_buf);
    //   LOGD("Last Seed Triggers New Edge!!!!\n");
    // } else {
    //   do_ts = 1;
    //   ts_query(last_id, last_seed, last_buf, last_len);
    //   cur_id = last_id;
    //   cur_seed = last_seed;
    //   cur_len = last_len;
    //   ck_free(in_buf);
    //   in_buf = last_buf;
    //   LOGD("Use Last Seed to TS-Query\n");
    // }

    if (!last_buf) {
      do_ts = 0;
    } else {
      do_ts = 1;
      ts_query(last_id, last_seed, last_buf, last_len);
      cur_id = last_id;
      cur_seed = last_seed;
      cur_len = last_len;
      ck_free(in_buf);
      in_buf = last_buf;
    }

    last_id = curr_id;
    last_seed = curr_seed_path;
    last_len = curr_len;
    last_buf = ck_memdup(curr_buf, curr_len);
  }

  // in_buf = ck_alloc_nozero(cur_len);
  // memcpy(in_buf, curr_buf, cur_len);
}

u8 pre_splice(u32 curr_id, u8 *curr_seed_path, u8 *curr_buf, u32 curr_len) {
  afl_time += get_cur_time() - delta;
  delta = get_cur_time();
  if ((ext_dir == NULL || do_ts == 0) && fuzzMode == ConSource) return 0;
  u64 time = get_cur_time();

  if (fuzzMode == MutateIf || fuzzMode == ConMutateIf) {
    print_time_count++;
    return 0;
  } 
  else if (fuzzMode == LafTaint) {
      print_time_count++;
      LOGD("LafTaint-> curr_id: %u\n", curr_id);
      in_buf = curr_buf;
      cur_len = curr_len;
      simple_run_target(in_buf, cur_len);
      update_compact_exp_edges_loosely();
      taint_analyze(in_buf, cur_len, SOURCE_TAINT, DTA_argv);
      return 0;
  }
  else if (fuzzMode == ConSource) {
    State state = TsAnswerState;
    switch (state) {
      case INIT:
        return 0;
      case HOLD:
        LOGD("answer state: HOLD\n");
        print_time_count++;
        return 0;
      case READY:

        LOGD("answer state: READY\n");

        pre_splice_time += get_cur_time() - time;
        print_time_count++;
        return 0;
      case NONE:

        LOGD("answer state: NONE\n");

        parse_answer();
        SetTsAnswerState(READY);
        pre_splice_time += get_cur_time() - time;
        print_time_count++;
        return 0;
      default:

        LOGD("answer state: OK, curr seed: %s, %s\n", in_buf, cur_seed);
        parse_answer();
        taint_analyze(in_buf, cur_len, SOURCE_TAINT, DTA_argv);

        ck_free(out_buf);
        out_buf = ck_alloc_nozero(cur_len + max_ext_seed_size + 1);

        SetTsAnswerState(READY);
        print_time_count += 80;
        pre_splice_time += get_cur_time() - time;
        return 1;
    }
  } else {
    cur_id = curr_id;
    curExtSeed = ts_history[curr_id];
    LOGD("---\n curr id: %u, to ext id: %u, cum size: %u \n---\n", curr_id,
         curExtSeed ? curExtSeed->id : 0, cum_ext_queue_size);
    if (curExtSeed && curExtSeed->next == NULL) {
      pre_splice_time += get_cur_time() - time;
      print_time_count++;
      return 0;
    }

    // reset_source_shm();
    simple_run_target(curr_buf, curr_len);
    // tryonce(user_argv, curr_buf, curr_len);
    update_compact_exp_edges();
    if (!source_size) {
      print_time_count++;
      return 0;
    }

    ck_free(in_buf);
    in_buf = ck_alloc_nozero(curr_len);
    memcpy(in_buf, curr_buf, curr_len);

    cur_len = curr_len;

    taint_analyze(curr_buf, curr_len, SOURCE_TAINT, DTA_argv);

    ck_free(out_buf);
    out_buf = ck_alloc_nozero(curr_len + max_ext_seed_size + 1);
    max_size_update = 0;

    print_time_count += 80;

    pre_splice_time += get_cur_time() - time;
    return 1;
  }
}

static inline void print_time() {
  // u64 random_time = 0, dry_time = 0, taint_query_time =0 ,
  // taint_splice_time = 0, query_time = 0, parse_answer_time =0, my_total_time
  // = 0, delta ;
  double CPS = 1000000ULL;
  u8 *time_log = alloc_printf(
      "\n--------------- time statistics --------------\n"
      "pre_splice: %.3lf, random: %.3lf, dry: %.3lf\n"
      "taint_query: %.3lf, taint_splice: %.3lf, con_query: %.3lf\n"
      "parse_answer: %.3lf, DTA: %.3lf, d-mut: %.3lf\n"
      "pre-post: %.3lf, afl: %.3lf\n"
      "----------------------------------------------\n\n",
      pre_splice_time / CPS, random_time / CPS, dry_time / CPS,
      taint_query_time / CPS, taint_splice_time / CPS, query_time / CPS,
      parse_answer_time / CPS, DTA_time / CPS, d_mutate_time / CPS,
      my_total_time / CPS, afl_time / CPS);
  LOGD("%s", time_log);
  FILE *t_log = fopen(time_log_file, "a+");
  fprintf(t_log, "%s", time_log);
  fclose(t_log);
}

void post_splice() {
  ext_queue_tail = NULL;
  my_total_time += get_cur_time() - delta;
  if (print_time_count > 200) {
    print_time_count = 0;
    delta = get_cur_time();
    print_time();
    write_map();
    my_total_time += get_cur_time() - delta;
  }
}

void load_ext_seed(ExtSeed *seed) {
  if (fuzzMode != ConSource) {
    s32 fd = open(seed->bitmap_name, O_RDONLY);
    if (fd < 0) PFATAL("Unable to open '%s'", seed->bitmap_name);

    if (ext_bitmap) {
      munmap((void *)ext_bitmap, BITMAP_SIZE);
    }

    ext_bitmap = (u8 *)mmap(0, BITMAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
  }

  if (ext_buf) {
    munmap((void *)ext_buf, ext_len);
  }
  ext_buf = NULL;

  ext_len = seed->seed_len;

  if (ext_len > cur_len) {
    slen = cur_len;
    llen = ext_len;
  } else {
    slen = ext_len;
    llen = cur_len;
  }
  tlen = ext_len + cur_len + 1;
}

void pre_each_splice(ExtSeed *seed) {
  if (!ext_buf) {
    s32 fd = open(seed->seed_name, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", seed->seed_name);

    ext_buf = mmap(0, ext_len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    close(fd);
    if (fuzzMode != ConSource) {
      load_ext_taint_table(seed);
    }

    if (max_size_update) {
      ck_free(out_buf);
      out_buf = ck_alloc_nozero(cur_len + max_ext_seed_size + 1);
      max_size_update = 0;
    }
    LOGD("---\nCurr id: %u, Get Ext Seed: %s\n", cur_id, seed->seed_name);
  }
}

void do_dry_splice(u32 len) {
  u64 time = get_cur_time();
  if (len > cur_len) {
    /**
     * Do dry splice.
     *
     * If curr input len < ext input len, try splice them directly.
     */
    memcpy(out_buf, in_buf, cur_len);
    memcpy(out_buf + cur_len, ext_buf + cur_len, len - cur_len);
    LOGD("Dry splicing, [:] + [%u:], result: %s\n", cur_len, out_buf);

    tryonce(user_argv, out_buf, len);
  }

  time = get_cur_time() - time;
  dry_time += time;
}

void do_random_splice(u8 times) {
  /**
   * Do random splicing first, as taint analysis is too costly.
   *
   * Make sure the location of section of new seed not changes.
   */
  /* Find a suitable splicing location, somewhere between the first and
 the last differing byte. Bail out if the difference is just a single
 byte or so. */
  u64 time = get_cur_time();
  LOGD("random splicing\n");

  u32 split_at;
  while (times--) {
    /*Curr seed begins, and new seed ends*/
    split_at = TS_R(slen + 1);

    memcpy(out_buf, in_buf, split_at);
    memcpy(out_buf + split_at, ext_buf + split_at, ext_len - split_at);
    if (tryonce(user_argv, out_buf, llen)) {
      break;
    }

    /*New seed begins, and curr seed ends*/

    split_at = TS_R(slen + 1);

    memcpy(out_buf, ext_buf, split_at);
    memcpy(out_buf + split_at, in_buf + split_at, cur_len - split_at);
    if (tryonce(user_argv, out_buf, llen)) {
      break;
    }
  }

  time = get_cur_time() - time;
  random_time += time;
}

static inline void d_splice(u32 cur_min, u32 cur_max, u32 ext_min,
                            u32 ext_max) {
  if (ext_max > ext_len) return;
  u64 time = get_cur_time();

  /*Splice 1 : b[:R2] + a[R1:]*/
  if (cur_max <= cur_len) {
    memcpy(out_buf, ext_buf, ext_max);
    memcpy(out_buf + ext_max, in_buf + cur_max, cur_len - cur_max);
    LOGD("result1: %s\n", out_buf);
    tryonce(user_argv, out_buf, ext_max + cur_len - cur_max);
  }

  /*Splice 2 : a[:L1] + b[L2:]*/
  memcpy(out_buf, in_buf, cur_min < cur_len ? cur_min : cur_len);
  memcpy(out_buf + cur_min, ext_buf + ext_min, ext_len - ext_min);
  LOGD("result2: %s\n", out_buf);
  tryonce(user_argv, out_buf, cur_min + ext_len - ext_min);

  /*Splice 3 : a[:L1] + b[L2:R2] + a[R1:]*/
  if (cur_max <= cur_len) {
    memcpy(out_buf + cur_min + (ext_max - ext_min), in_buf + cur_max,
           cur_len - cur_max);
    LOGD("result3: %s\n", out_buf);
    tryonce(user_argv, out_buf,
            cur_len + cur_min - cur_max + ext_max - ext_min);
  }

  time = get_cur_time() - time;
  taint_splice_time += time;
}

/**
 * 需要考虑正序与尾序， 当前种子污点分析与目标种子污点分析
 */
void do_taint_splice(u32 explore_edge) {
  if (DTA_mode == NO_TAINT) return;
  if (edge_ts_cnt[explore_edge] < SPLICE_EDGE_TIME) edge_ts_cnt[explore_edge]++;
  LOGD("\tEdge %u done %u times!\n", explore_edge, edge_ts_cnt[explore_edge]);
  if (source_edge_passed(explore_edge)) return;
  LOGD("------------------- Get Explore Edge: %d, %d --------------------------\n",
    explore_edge, edge_list_idx);
  if (fuzzMode == ConSource) {
    u32 cur_min = 0, cur_max = 0, ext_min = 0, ext_max = 0;
    // u32 *tainted_loc;
    //    taint_query(explore_edge, &tainted_loc, &taint_num, &cur_min,
    //    &cur_max);
    taint_query(explore_edge, &cur_min, &cur_max, SOURCE_TAINT);
    taint_query(explore_edge, &ext_min, &ext_max, EXT_TAINT);

    LOGD(
        "---\nexplore_edge: %u, cur_min: %u, cur_max: %u, ext_min: %u, "
        "ext_max: %u\n",
        explore_edge, cur_min, cur_max, ext_min, ext_max);

    if (cur_min != ext_min || cur_max != ext_max) {
      if (cur_min < cur_max && ext_min < ext_max) {
        d_splice(cur_min, cur_max, ext_min, ext_max);
      }
    }

    if (source_edge_passed(explore_edge)) {
      LOGD("----------------------- splice state: 1 ------------------------\n\n");
      return;
    }

    if (cur_min < cur_max && cur_max <= ext_len) {
      d_splice(cur_min, cur_max, cur_min, cur_max);
    } else if (ext_min < ext_max && ext_max <= cur_len) {
      d_splice(ext_min, ext_max, ext_min, ext_max);
    } else if (ext_min < ext_max && ext_max > cur_len) {
      do_dry_splice(ext_max);
    }
    LOGD("----------------------- splice state: %u ------------------------\n\n",
           source_edge_passed(explore_edge) );


  } else {
    u32 cur_min = 0, cur_max = 0, ext_min = 0, ext_max = 0;
    // u32 *tainted_loc;
    //    taint_query(explore_edge, &tainted_loc, &taint_num, &cur_min,
    //    &cur_max);
    taint_query(explore_edge, &cur_min, &cur_max, SOURCE_TAINT);

    LOGD(
        "---\ncurr seed: %s\ntarget seed: %s\nexplore_edge: %u, cur_min: %u, "
        "cur_max: %u\n",
        in_buf, ext_buf, explore_edge, cur_min, cur_max);

    if (cur_min < cur_max && cur_max <= ext_len) {
      d_splice(cur_min, cur_max, cur_min, cur_max);
    }

    if (source_edge_passed(explore_edge)) {
      return;
    }

    taint_query(explore_edge, &ext_min, &ext_max, EXT_TAINT);
    LOGD(
        "---\nexplore_edge: %u, cur_min: %u, cur_max: %u, ext_min: %u, "
        "ext_max: %u\n",
        explore_edge, cur_min, cur_max, ext_min, ext_max);

    if (cur_min != ext_min || cur_max != ext_max) {
      if (cur_min < cur_max && ext_min < ext_max) {
        d_splice(cur_min, cur_max, ext_min, ext_max);
      }
    }
  }

  
}

void do_DTA_mutate() {
  if (fuzz_st == RandSplice) return;
  if (fuzzMode != LafTaint && (fuzzMode != ConSource || do_ts == 0)) return;
  if (ts_history[cur_id] != NULL) return;
  LOGD("----\ndeterministic mutate stage\n----\n");
  u32 idx = 0, min_loc = 0, max_loc = 0;
  memset(aug_loc_bitmap, 0, MAP_SIZE);
  while (idx != source_size) {
    u32 source_edge = compact_exp_edges[idx++];
    if (source_edge_passed(source_edge)) {
      continue;
    }

    taint_query(source_edge, &min_loc, &max_loc, SOURCE_TAINT);
    if (max_loc > cur_len) continue;
    // If fuzz strategy is HavocDTA, any max/min pair statisfies max - min > 0 would do havoc in buf[min, max)
    // Otherwise, only those max/min pair statisfies max - min > 1 would do so.
    if ((max_loc - min_loc) > (fuzz_st != HavocDTA)) {
       havoc(in_buf, min_loc, max_loc, cur_len, user_argv);
    }

    if (fuzz_st == HavocDTA) {
      continue;
    }

    if (max_loc - min_loc != 1) {
      continue;
    }
    
    aug_edge_map[source_edge]++;
    if (aug_edge_map[source_edge] > AUG_EDGE_TIMES) {
      LOGD("Aug Times Overflow: %u (times: %u)\n", source_edge, AUG_EDGE_TIMES);
      continue;
    } 

    u32 _loc = min_loc & 0x3ffff;
    if (in_bitmap(aug_loc_bitmap, _loc)) {
      LOGD("Repeative Aug Loc: %u (loc: %u)\n", source_edge, _loc);
      continue;
    }
    u64 time = get_cur_time();
    u8 cache = in_buf[min_loc];
    mutate_deterministic(in_buf, cur_len, min_loc, 0, cur_id, 1);
    LOGD("\tAug Edge: %u, Loc: %u, success: %d\n", source_edge, min_loc, source_edge_passed(source_edge));
    in_buf[min_loc] = cache;
    set_bitmap(aug_loc_bitmap, _loc);
    d_mutate_time += get_cur_time() - time;
  }
  ts_history[cur_id] =
          ext_queue_tail ? ext_queue_tail->last : ext_queue_top;
  LOGD("----------------\n");
}

void deterministic_splice(u32 curr_id, u8 *curr_seed_path, u8 *curr_buf,
                          u32 curr_len, u8 *virgin_bits) {
  ExtSeed *ext_seed = NULL;
  u32 explore_id = 0, explore_edge;
  if (pre_splice(curr_id, curr_seed_path, curr_buf, curr_len)) {
      while (next_ext_seed(&ext_seed)) {
          load_ext_seed(ext_seed);
          if (next_explore_edge(&explore_edge, &explore_id)){
              pre_each_splice(ext_seed);
              do_dry_splice(ext_seed->seed_len);
              do_random_splice(1);
              do {
                  do_taint_splice(explore_edge);
              } while(next_explore_edge(&explore_edge, &explore_id));
          }
      }
      order++;
    }
    do_DTA_mutate();
    post_splice();
}


