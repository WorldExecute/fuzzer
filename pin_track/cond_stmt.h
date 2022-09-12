#ifndef COND_STMT_H
#define COND_STMT_H

#include <stdint.h>

typedef int32_t s32;
typedef uint32_t u32;
typedef uint64_t u64;

#define MAX_ORDER 16
#define COND_SW_OP 0x00FF
// #define COND_EXPLOIT_OP 0x4000
#define COND_FN_OP 0x8002
#define COND_LEN_OP 0x8003

#define COND_FALSE_ST 0
#define COND_TRUE_ST 1
#define COND_DONE_ST 2

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

struct _tag_seg_{
  u32 begin;
  u32 end;
};

typedef struct _tag_seg_ TagSeg;


struct BranchStmt {
    u32 thenEdge;
    u32 elseEdge;
    u32 cond;
    u32 op;
    u64 arg1;
    u64 arg2;
    u32 min_loc;
    u32 max_loc;
};
#endif