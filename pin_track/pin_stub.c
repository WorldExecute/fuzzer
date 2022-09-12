#include <stdint.h>
typedef int32_t s32;
typedef uint32_t u32;
#ifdef __x86_64__
typedef unsigned long long u64;
#else
typedef uint64_t u64;
#endif


void __ts_trace_simple_br_cmp_tt(s32 thenEdge, s32 elseEdge, u32 cond, u32 size, u64 arg1, u64 arg2) {}
void __ts_trace_simple_phantom_cmp_tt(s32 thenEdge, s32 elseEdge, u32 cond, u32 size, u64 arg1, u64 arg2) {}

void __ts_trace(u64 arg, u32 size) {}