#include "ins_movzx_op.h"
#include "ins_helper.h"
#include "ins_xfer_op.h"

/**
 * Adds DTA support for movzx instructions. 
 * The original taint propagtion rule for movzx (refer to ins_movsx_op.cpp) causes "over-taint" problem, 
 *    i.e., zero-expanded bytes should not propagate taint.
 */


/* threads context */
extern thread_ctx_t *threads_ctx;

static void PIN_FAST_ANALYSIS_CALL _movzx_r2r_opwb_u(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  /* temporary tag value */
  tag_t src_tag = RTAG[src][1];
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  rtag_dst[0] = src_tag;
  rtag_dst[1] = tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL _movzx_r2r_opwb_l(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  /* temporary tag value */
  tag_t src_tag = RTAG[src][0];
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  rtag_dst[0] = src_tag;
  rtag_dst[1] = tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL _movzx_r2r_oplb_u(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  /* temporary tag value */
  tag_t src_tag = RTAG[src][1];
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  rtag_dst[0] = src_tag;
  for (size_t i = 1; i < 4; i++)
    rtag_dst[i] = tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL _movzx_r2r_oplb_l(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  /* temporary tag value */
  tag_t src_tag = RTAG[src][0];
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  rtag_dst[0] = src_tag;
  for (size_t i = 1; i < 4; i++)
    rtag_dst[i] = tag_traits<tag_t>::cleared_val;

}

static void PIN_FAST_ANALYSIS_CALL _movzx_r2r_opqb_u(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  /* temporary tag value */
  tag_t src_tag = RTAG[src][1];
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  rtag_dst[0] = src_tag;
  for (size_t i = 1; i < 8; i++)
    rtag_dst[i] = tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL _movzx_r2r_opqb_l(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  /* temporary tag value */
  tag_t src_tag = RTAG[src][0];
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  rtag_dst[0] = src_tag;
  for (size_t i = 1; i < 8; i++)
    rtag_dst[i] = tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL _movzx_r2r_oplw(THREADID tid, uint32_t dst,
                                                   uint32_t src) {
  /* temporary tag values */
  tag_t *rtag_src = RTAG[src];
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  rtag_dst[0] = rtag_src[0]; 
  rtag_dst[1] = rtag_src[1];
  rtag_dst[2] = tag_traits<tag_t>::cleared_val;
  rtag_dst[3] = tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL _movzx_r2r_opqw(THREADID tid, uint32_t dst,
                                                   uint32_t src) {
  /* temporary tag values */
  tag_t *rtag_src = RTAG[src];
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  rtag_dst[0] = rtag_src[0]; 
  rtag_dst[1] = rtag_src[1];
  for (size_t i = 2; i < 8; i++)
    rtag_dst[i] = rtag_src[i % 2];
}

// static void PIN_FAST_ANALYSIS_CALL _movzx_r2r_opql(THREADID tid, uint32_t dst,
//                                                    uint32_t src) {
//   /* temporary tag values */
//   tag_t *rtag_src = RTAG[src];
//   tag_t *rtag_dst = RTAG[dst];

//   /* update the destination (xfer) */
//   for (size_t i = 0; i < 4; i++)
//     rtag_dst[i] = rtag_src[i];
//   for (size_t i = 4; i < 8; i++)
//     rtag_dst[i] = tag_traits<tag_t>::cleared_val;
// }

static void PIN_FAST_ANALYSIS_CALL _movzx_m2r_opwb(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
  /* temporary tag value */
  tag_t src_tag = MTAG(src);
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  rtag_dst[0] = src_tag;
  rtag_dst[1] = tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL _movzx_m2r_oplb(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
  /* temporary tag value */
  tag_t src_tag = MTAG(src);
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  rtag_dst[0] = src_tag;
  for (size_t i = 1; i < 4; i++)
    rtag_dst[i] = tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL _movzx_m2r_opqb(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
  /* temporary tag value */
  tag_t src_tag = MTAG(src);
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  rtag_dst[0] = src_tag;
  for (size_t i = 1; i < 8; i++)
    rtag_dst[i] = tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL _movzx_m2r_oplw(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
  /* temporary tag value */
  tag_t src_tags[] = M16TAG(src);
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  rtag_dst[0] = src_tags[0]; 
  rtag_dst[1] = src_tags[1];
  rtag_dst[2] = tag_traits<tag_t>::cleared_val;
  rtag_dst[3] = tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL _movzx_m2r_opqw(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
  /* temporary tag value */
  tag_t src_tags[] = M16TAG(src);
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  rtag_dst[0] = src_tags[0]; 
  rtag_dst[1] = src_tags[1];
  for (size_t i = 2; i < 8; i++)
    rtag_dst[i] = tag_traits<tag_t>::cleared_val;
}

// static void PIN_FAST_ANALYSIS_CALL _movzx_m2r_opql(THREADID tid, uint32_t dst,
//                                                    ADDRINT src) {
//   /* temporary tag value */
//   tag_t src_tags[] = M32TAG(src);

//   tag_t *rtag_dst = RTAG[dst];

//   /* update the destination (xfer) */
//   for (size_t i = 0; i < 4; i++)
//     rtag_dst[i] = src_tags[i];
//   for (size_t i = 4; i < 8; i++)
//     rtag_dst[i] = tag_traits<tag_t>::cleared_val;
// }

void ins_movzx_op(INS ins) {
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr16(reg_dst)) {
      if (REG_is_Upper8(reg_src))
        R2R_CALL(_movzx_r2r_opwb_u, reg_dst, reg_src);
      else
        R2R_CALL(_movzx_r2r_opwb_l, reg_dst, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      if (REG_is_gr64(reg_dst))
        R2R_CALL(_movzx_r2r_opqw, reg_dst, reg_src);
      else if (REG_is_gr32(reg_dst))
        R2R_CALL(_movzx_r2r_oplw, reg_dst, reg_src);
    } else if (REG_is_Upper8(reg_src)) {
      if (REG_is_gr64(reg_dst))
        R2R_CALL(_movzx_r2r_opqb_u, reg_dst, reg_src);
      else if (REG_is_gr32(reg_dst))
        R2R_CALL(_movzx_r2r_oplb_u, reg_dst, reg_src);
    } else { // lower8
      if (REG_is_gr64(reg_dst))
        R2R_CALL(_movzx_r2r_opqb_l, reg_dst, reg_src);
      else if (REG_is_gr32(reg_dst))
        R2R_CALL(_movzx_r2r_oplb_l, reg_dst, reg_src);
    }
  } else {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr16(reg_dst)) {
      M2R_CALL(_movzx_m2r_opwb, reg_dst);
    } else if (INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_WORD_LEN)) {     
      if (REG_is_gr64(reg_dst)) {
        M2R_CALL(_movzx_m2r_opqw, reg_dst);
      } else if (REG_is_gr32(reg_dst)) {
        M2R_CALL(_movzx_m2r_oplw, reg_dst);
      }
    } else {
      if (REG_is_gr64(reg_dst)) {
        M2R_CALL(_movzx_m2r_opqb, reg_dst);
      } else if (REG_is_gr32(reg_dst)) {
        M2R_CALL(_movzx_m2r_oplb, reg_dst);
      }
    }
  }

}

