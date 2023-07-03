//
// Created by camsyn on 2022/6/24.
//

#ifndef MIRAGE_FUZZER_ENHANCEMENT_H
#define MIRAGE_FUZZER_ENHANCEMENT_H

#include <stdio.h>

#include "types.h"

#define PHANTOM_PREFIX "ext-"
#define SHARE_FILE "shared"
#define SHARE_SIZE 256
#define AUG_EDGE_TIMES 8
#define SPLICE_EDGE_TIME 128

#define TS_QUERY_SHM_SIZE (1 << 18)
#define TS_ANS_SHM_SIZE (1 << 21)

// #define DEBUG_INFO 1

#ifdef DEBUG_INFO
extern char *logfile;
extern FILE *__log;
// #define DEBUG_PRINTF printf
#define LOGD(...)                                   \
  do {                                              \
    if (__log == NULL) __log = fopen(logfile, "w"); \
    fprintf(__log, __VA_ARGS__);                    \
    fflush(__log);                                  \
  } while (0)
#else
#define LOGD(...)
#endif

extern u8 *time_stat;

struct ext_queue_entry {
  u32 id;
  u8 *taintmap_name;
  u8 *bitmap_name; /* Exec Path name for the ext seeds      */
  u8 *seed_name;   /* Seed name for the ext seeds      */
  u8 *name;        /* Name       */
  u32 seed_len;    /* Input length of seed                    */
  u32 path_len;    /* Exec path length of seed                    */
  u32 cnt;         /* The number of times it was ignored */
  u8 zombie;       /* Zombie State, waiting for death */
  struct ext_queue_entry *last; /* Last element, if any             */
  struct ext_queue_entry *next, /* Next element, if any             */
      *next_100;                /* 100 elements ahead               */
};

/* Represent the taint loc */
struct tag_seg {
  u32 begin;
  u32 end;
};

/* Represent the cmp taint log */
struct CondStmt {
  u32 cid;
  u32 context;
  u32 order;
  u32 belong;

  u32 condition;
  u32 level;
  u32 op;
  u32 size;

  u32 lb1;
  u32 lb2;
  u64 arg1;
  u64 arg2;
};

enum taint_mode { NO_TAINT, SOURCE_TAINT, PHANTOM_TAINT, EXT_TAINT };

typedef enum taint_mode TaintMode;

enum fuzz_mode {
  Source,      /* Fuzzing the Source target respectly*/
  MutateIf,    /* Fuzzing the Mutate If target respectly*/
  ConSource,   /* Fuzzing the Source target concurrently*/
  ConMutateIf, /* Fuzzing the Mutate If target concurrently*/
  Integrated,   /* Fuzzing integrated target and get all the information. */
  LafTaint,
  Default
};

typedef enum fuzz_mode FuzzMode;

struct taint_tag {
  u32 len;
  struct tag_seg *segs;
};

struct taint_scope {
  u32 min;
  u32 max;
};
typedef struct taint_scope TaintScope;
typedef struct ext_queue_entry ExtSeed;

typedef u8 (*FuzzBuf)(char **argv, u8 *out_buf, u32 len);
typedef u8 (*ExecTarget)(char **argv, u32 timeout);
typedef void (*Write2TestCase)(void *mem, u32 len);
typedef u8 (*SaveIfInteresting)(char **argv, void *mem, u32 len, u8 fault);

void show_trace_bits(u8 *bits);

void add_2_transfer(u8 *seed_path);

int save_if_meet_new_phantom(void *content, u32 len, char **argv, u8 augment_mode,
                           u32 curr_id);

void reset_phantom_shm();

void reset_source_shm();

/**
 * 初始化设置 fuzzer 增强
 * @param out_fd_ 输出文件的文件描述符
 * @param out_file_  输出文件路径
 * @param out_dir_  输出的目录
 * @param user_argc_  用户args的实际size
 */
void setup_enhancement(s32 dev_null_fd, s32 out_fd_, u8 *out_file_, u8 *out_dir_, u8 *syn_dir_,
                       u32 user_argc_, FuzzMode mode, u8 *taint_target,
                       u32 *queue_size, u32 timeout,
                       SaveIfInteresting save_func, FuzzBuf try_once,
                       ExecTarget exec_target_, Write2TestCase w2tc,
                       char **use_argv);

int set_taint_target(char *target);

void taint_analysis_run(TaintMode mode, char *argv[]);

void taint_analyze(u8 *orig_in, u32 len, TaintMode mode, char **argv);

// void taint_query(u32 bb, u32 **tainted_loc, u32 *taint_num, u32 *min_loc, u32
// *max_loc);
void update_source_virgin_bits();

void read_ext_seed(u8 *ext_dir);

u8 *read_ext_phantom_map(const ExtSeed *seed);

u8 next_ext_seed(ExtSeed **seed);

/**
 * Get the next node to explore.
 *
 * @param explore_node the next explore node
 * @param idx the index of curr source parent
 * @return
 */
u8 next_explore_edge(u32 *explore_node, u32 *idx);

u32 get_ts_cycles(u32 curr_id);

void pre_havoc(u32 curr_id, u8 *curr_seed_path, u8 *curr_buf, u32 curr_len,
               u8 has_new);

u8 pre_splice(u32 curr_id, u8 *curr_seed_path, u8 *curr_buf, u32 curr_len);

void pre_all();

void post_splice();

void load_ext_seed(ExtSeed *seed);

void pre_each_splice(ExtSeed *seed);

void do_dry_splice();

void do_random_splice(u8 times);

void do_taint_splice(u32 explore_node);

void do_DTA_mutate();

void deterministic_splice(u32 curr_id, u8 *curr_seed_path, u8 *curr_buf,
                          u32 curr_len, u8 *virgin_bits);

/** 
 *  Do havoc 
 */
u8 havoc(u8 *out_buf, u32 L, u32 R, u32 total_len, char **argv);

#endif  // MIRAGE_FUZZER_ENHANCEMENT_H
