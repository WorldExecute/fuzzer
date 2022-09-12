#include "ins_special_op.h"
#include "ins_helper.h"

/**
 * Adds DTA support for some special X86 instructions. 
 * Currently only supports bswap instruction.
 */

/* threads context */
extern thread_ctx_t *threads_ctx;




static void PIN_FAST_ANALYSIS_CALL r_bswap_opw(THREADID tid, uint32_t src) {
    std::swap(RTAG[src][0], RTAG[src][1]);
}
static void PIN_FAST_ANALYSIS_CALL r_bswap_opl(THREADID tid, uint32_t src) {
    std::swap(RTAG[src][0], RTAG[src][3]);
    std::swap(RTAG[src][1], RTAG[src][2]);
}
static void PIN_FAST_ANALYSIS_CALL r_bswap_opq(THREADID tid, uint32_t src) {
    tag_t *dst_tags =  RTAG[src];
    std::swap(dst_tags[0], dst_tags[7]);
    std::swap(dst_tags[1], dst_tags[6]);
    std::swap(dst_tags[2], dst_tags[5]);
    std::swap(dst_tags[3], dst_tags[4]);
}
static void PIN_FAST_ANALYSIS_CALL r_bswap_opx(THREADID tid, uint32_t src) {
    tag_t *dst_tags =  RTAG[src];
    std::swap(dst_tags[0], dst_tags[15]);
    std::swap(dst_tags[1], dst_tags[14]);
    std::swap(dst_tags[2], dst_tags[13]);
    std::swap(dst_tags[3], dst_tags[12]);
    std::swap(dst_tags[4], dst_tags[11]);
    std::swap(dst_tags[5], dst_tags[10]);
    std::swap(dst_tags[6], dst_tags[9]);
    std::swap(dst_tags[7], dst_tags[8]);
}
static void PIN_FAST_ANALYSIS_CALL r_bswap_opy(THREADID tid, uint32_t src) {
    tag_t *dst_tags =  RTAG[src];
    std::swap(dst_tags[0], dst_tags[31]);
    std::swap(dst_tags[1], dst_tags[30]);
    std::swap(dst_tags[2], dst_tags[29]);
    std::swap(dst_tags[3], dst_tags[28]);
    std::swap(dst_tags[4], dst_tags[27]);
    std::swap(dst_tags[5], dst_tags[26]);
    std::swap(dst_tags[6], dst_tags[25]);
    std::swap(dst_tags[7], dst_tags[24]);
    std::swap(dst_tags[0], dst_tags[23]);
    std::swap(dst_tags[9], dst_tags[22]);
    std::swap(dst_tags[10], dst_tags[21]);
    std::swap(dst_tags[11], dst_tags[20]);
    std::swap(dst_tags[12], dst_tags[19]);
    std::swap(dst_tags[13], dst_tags[18]);
    std::swap(dst_tags[14], dst_tags[17]);
    std::swap(dst_tags[15], dst_tags[16]);
}

static void PIN_FAST_ANALYSIS_CALL m_bswap_opw(THREADID tid, ADDRINT src) {
  tag_t t1 = MTAG(src);
  tag_t t2 = MTAG(src + 1);

  tagmap_setb(src, t2);
  tagmap_setb(src + 1, t1);
}
static void PIN_FAST_ANALYSIS_CALL m_bswap_opl(THREADID tid, ADDRINT src) {
  tag_t t1 = MTAG(src);
  tag_t t2 = MTAG(src + 1);
  tag_t t3 = MTAG(src + 2);
  tag_t t4 = MTAG(src + 3);

  tagmap_setb(src, t4);
  tagmap_setb(src + 1, t3);
  tagmap_setb(src + 2, t2);
  tagmap_setb(src + 3, t1);
}
static void PIN_FAST_ANALYSIS_CALL m_bswap_opq(THREADID tid, ADDRINT src) {
  tag_t t1 = MTAG(src);
  tag_t t2 = MTAG(src + 1);
  tag_t t3 = MTAG(src + 2);
  tag_t t4 = MTAG(src + 3);
  tag_t t5 = MTAG(src + 4);
  tag_t t6 = MTAG(src + 5);
  tag_t t7 = MTAG(src + 6);
  tag_t t8 = MTAG(src + 7);

  tagmap_setb(src, t8);
  tagmap_setb(src + 1, t7);
  tagmap_setb(src + 2, t6);
  tagmap_setb(src + 3, t5);
  tagmap_setb(src + 4, t4);
  tagmap_setb(src + 5, t3);
  tagmap_setb(src + 6, t2);
  tagmap_setb(src + 7, t1);
}


// 这是 反转指令
void ins_bswap(INS ins) {

  if (INS_OperandIsMemory(ins, OP_0))
    switch (INS_MemoryWriteSize(ins)) {
    case BIT2BYTE(MEM_64BIT_LEN):
      M_CALL_R(m_bswap_opq);
      break;
    case BIT2BYTE(MEM_LONG_LEN):
      M_CALL_R(m_bswap_opl);
      break;
    case BIT2BYTE(MEM_WORD_LEN):
      M_CALL_R(m_bswap_opw);
      break;
    default:
      break;
    }
  else {
    REG reg_src = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_src))
      R_CALL(r_bswap_opq, reg_src);
    else if (REG_is_gr32(reg_src))
      R_CALL(r_bswap_opl, reg_src);
    else if (REG_is_gr16(reg_src))
      R_CALL(r_bswap_opw, reg_src);
    else if (REG_is_xmm(reg_src)) 
      R_CALL(r_bswap_opx, reg_src);
    else if (REG_is_ymm(reg_src))
      R_CALL(r_bswap_opy, reg_src);
    else if (REG_is_mm(reg_src))
      R_CALL(r_bswap_opq, reg_src);
  }
}
