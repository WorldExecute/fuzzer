// #include "ins_binary_op.h"
#include "ins_shift_op.h"
#include "ins_helper.h"
#include "tag_traits.h"

/**
 * Adds DTA support for X86 shift instructions. 
 * Not yet stable and complete.
 */

/* threads context */
extern thread_ctx_t *threads_ctx;

static inline int gcd(int m, int n)
{
  while (n != 0)
  {
    int t = n;
    n = m % n;
    m = t;
  }
  return m;
}

static inline void rotate_recyle(tag_t *begin, tag_t *end, tag_t *initial, int shift)
{
  int t = *initial;
  int len = end - begin;
  tag_t *p1 = initial;    
  tag_t *p2 = p1 + shift; 
  while (p2 != initial)
  {
    *p1 = *p2;
    p1 = p2;
    p2 = begin + (p2 - begin + shift) % len; 
  }
  *p1 = t;
}

static inline void rotate(tag_t *begin, tag_t *mid, tag_t *end)
{
  if (begin == mid || mid == end)
    return;
  int n = gcd(mid - begin, end - begin);
  while (n--)
  {
    rotate_recyle(begin, end, begin + n, mid - begin);
  }
}

static inline void loop_shift(tag_t *arr, int len, int shift)
{
  if (shift == 0 || shift == len)
    return;
  int n = gcd(shift, len);
  while (n--)
  {
    rotate_recyle(arr, arr + len, arr + n, shift);
  }
}

static void PIN_FAST_ANALYSIS_CALL i2r_ror_opw(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];

  tag_t tag_ = dst_tags[0];
  dst_tags[0] = (sh_len & 2) == 0 ? tag_ : dst_tags[1];
  dst_tags[1] = (sh_len & 2) == 0 ? dst_tags[1] : tag_;
}

static void PIN_FAST_ANALYSIS_CALL i2r_ror_opl(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 delta = (sh_len >> 3) & 3;
  loop_shift(dst_tags, 4, delta);
}

static void PIN_FAST_ANALYSIS_CALL i2r_ror_opq(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 delta = (sh_len >> 3) & 7;
  loop_shift(dst_tags, 8, delta);
}

static void PIN_FAST_ANALYSIS_CALL i2r_ror_opx(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 delta = (sh_len >> 3) & 15;
  loop_shift(dst_tags, 16, delta);
}

static void PIN_FAST_ANALYSIS_CALL i2r_ror_opy(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 delta = (sh_len >> 3) & 31;
  loop_shift(dst_tags, 32, delta);
}

static void PIN_FAST_ANALYSIS_CALL i2r_rol_opw(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  tag_t tag_ = dst_tags[1];
  dst_tags[1] = (sh_len & 2) == 0 ? tag_ : dst_tags[0];
  dst_tags[0] = (sh_len & 2) == 0 ? dst_tags[0] : tag_;
}

static void PIN_FAST_ANALYSIS_CALL i2r_rol_opl(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 delta = (sh_len >> 3) & 3;
  loop_shift(dst_tags, 4, 4 - delta);
}

static void PIN_FAST_ANALYSIS_CALL i2r_rol_opq(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 delta = (sh_len >> 3) & 7;
  loop_shift(dst_tags, 8, 8 - delta);
}

static void PIN_FAST_ANALYSIS_CALL i2r_rol_opx(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 delta = (sh_len >> 3) & 15;
  loop_shift(dst_tags, 16, 16 - delta);
}

static void PIN_FAST_ANALYSIS_CALL i2r_rol_opy(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 delta = (sh_len >> 3) & 31;
  loop_shift(dst_tags, 32, 32 - delta);
}

static void PIN_FAST_ANALYSIS_CALL i2r_shr_opb_u(THREADID tid, uint32_t dst,
                                                 UINT8 sh_len)
{
  tag_t dst_tag = RTAG[dst][1];
  RTAG[dst][1] = sh_len >= 8 ? tag_traits<tag_t>::cleared_val : dst_tag;
}

static void PIN_FAST_ANALYSIS_CALL i2r_shr_opb_l(THREADID tid, uint32_t dst,
                                                 UINT8 sh_len)
{
  tag_t dst_tag = RTAG[dst][0];
  RTAG[dst][0] = sh_len >= 8 ? tag_traits<tag_t>::cleared_val : dst_tag;
}

static void PIN_FAST_ANALYSIS_CALL i2r_shr_opw(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  dst_tags[0] = sh_len >= 16 ? tag_traits<tag_t>::cleared_val
                             : (sh_len >= 8 ? dst_tags[1] : dst_tags[0]);
  dst_tags[1] = sh_len >= 8 ? tag_traits<tag_t>::cleared_val : dst_tags[1];
}

static void PIN_FAST_ANALYSIS_CALL i2r_shr_opl(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 sh_bytes = sh_len >> 3;
  for (size_t i = 0; i < 4; i++)
    dst_tags[i] = (i + sh_bytes < 4) ? dst_tags[i + sh_bytes] : tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL i2r_shr_opq(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 sh_bytes = sh_len >> 3;
  for (size_t i = 0; i < 8; i++)
    dst_tags[i] = (i + sh_bytes < 8) ? dst_tags[i + sh_bytes] : tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL i2r_shr_opx(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 sh_bytes = sh_len >> 3;
  for (size_t i = 0; i < 16; i++)
    dst_tags[i] = (i + sh_bytes < 16) ? dst_tags[i + sh_bytes] : tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL i2r_shr_opy(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 sh_bytes = sh_len >> 3;
  for (size_t i = 0; i < 32; i++)
    dst_tags[i] = (i + sh_bytes < 4) ? dst_tags[i + sh_bytes] : tag_traits<tag_t>::cleared_val;
}


static void PIN_FAST_ANALYSIS_CALL i2r_sar_opw(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  dst_tags[0] = sh_len >= 8 ? dst_tags[1] : dst_tags[0];
}

static void PIN_FAST_ANALYSIS_CALL i2r_sar_opl(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 sh_bytes = sh_len >> 3;
  tag_t sign_tag = dst_tags[3];
  for (size_t i = 0; i < 3; i++)
    dst_tags[i] = (i + sh_bytes < 3) ? dst_tags[i + sh_bytes] : sign_tag;
}

static void PIN_FAST_ANALYSIS_CALL i2r_sar_opq(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 sh_bytes = sh_len >> 3;
  tag_t sign_tag = dst_tags[7];
  for (size_t i = 0; i < 7; i++)
    dst_tags[i] = (i + sh_bytes < 7) ? dst_tags[i + sh_bytes] : sign_tag;
}

static void PIN_FAST_ANALYSIS_CALL i2r_sar_opx(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 sh_bytes = sh_len >> 3;
  tag_t sign_tag = dst_tags[15];
  for (size_t i = 0; i < 15; i++)
    dst_tags[i] = (i + sh_bytes < 15) ? dst_tags[i + sh_bytes] : sign_tag;
}

static void PIN_FAST_ANALYSIS_CALL i2r_sar_opy(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 sh_bytes = sh_len >> 3;
  tag_t sign_tag = dst_tags[31];
  for (size_t i = 0; i < 31; i++)
    dst_tags[i] = (i + sh_bytes < 31) ? dst_tags[i + sh_bytes] : sign_tag;
}

static void PIN_FAST_ANALYSIS_CALL i2r_shl_opb_u(THREADID tid, uint32_t dst,
                                                 UINT8 sh_len)
{
  tag_t dst_tag = RTAG[dst][1];
  RTAG[dst][1] = sh_len >= 8 ? tag_traits<tag_t>::cleared_val : dst_tag;
}

static void PIN_FAST_ANALYSIS_CALL i2r_shl_opb_l(THREADID tid, uint32_t dst,
                                                 UINT8 sh_len)
{
  tag_t dst_tag = RTAG[dst][0];
  RTAG[dst][0] = sh_len >= 8 ? tag_traits<tag_t>::cleared_val : dst_tag;
}

static void PIN_FAST_ANALYSIS_CALL i2r_shl_opw(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  dst_tags[1] = sh_len >= 16 ? tag_traits<tag_t>::cleared_val
                             : (sh_len >= 8 ? dst_tags[0] : dst_tags[1]);
  dst_tags[0] = sh_len >= 8 ? tag_traits<tag_t>::cleared_val : dst_tags[0];
}

static void PIN_FAST_ANALYSIS_CALL i2r_shl_opl(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 sh_bytes = sh_len >> 3;
  for (size_t i = 3; i < 4; i--)
    dst_tags[i] = (i - sh_bytes >= 0) ? dst_tags[i - sh_bytes] : tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL i2r_shl_opq(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 sh_bytes = sh_len >> 3;
  for (size_t i = 7; i < 8; i--)
    dst_tags[i] = (i - sh_bytes >= 0) ? dst_tags[i - sh_bytes] : tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL i2r_shl_opx(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 sh_bytes = sh_len >> 3;
  for (size_t i = 15; i < 16; i--)
    dst_tags[i] = (i - sh_bytes >= 0) ? dst_tags[i - sh_bytes] : tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL i2r_shl_opy(THREADID tid, uint32_t dst,
                                               UINT8 sh_len)
{
  tag_t *dst_tags = RTAG[dst];
  UINT8 sh_bytes = sh_len >> 3;
  for (size_t i = 31; i < 32; i--)
    dst_tags[i] = (i - sh_bytes >= 0) ? dst_tags[i - sh_bytes] : tag_traits<tag_t>::cleared_val;
}

static inline void ins_rol_op(INS ins)
{
  if (!INS_OperandIsImmediate(ins, OP_1))
    return;
  /* use XED to decode the instruction and extract its opcode */
  UINT8 sh_len = INS_OperandImmediate(ins, 1);

  if (!INS_OperandIsMemory(ins, OP_0))
  {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst))
    {
      I2R_CALL(i2r_rol_opq, reg_dst, sh_len);
    }
    else if (REG_is_gr32(reg_dst))
    {
      I2R_CALL(i2r_rol_opl, reg_dst, sh_len);
    }
    else if (REG_is_gr16(reg_dst))
    {
      I2R_CALL(i2r_rol_opw, reg_dst, sh_len);
    }
    else if (REG_is_xmm(reg_dst))
    {
      I2R_CALL(i2r_rol_opx, reg_dst, sh_len);
    }
    else if (REG_is_ymm(reg_dst))
    {
      I2R_CALL(i2r_rol_opy, reg_dst, sh_len);
    }
    else if (REG_is_mm(reg_dst))
    {
      I2R_CALL(i2r_rol_opq, reg_dst, sh_len);
    }
  }
}

static inline void ins_ror_op(INS ins)
{
  if (!INS_OperandIsImmediate(ins, OP_1))
    return;
  /* use XED to decode the instruction and extract its opcode */
  UINT8 sh_len = INS_OperandImmediate(ins, 1);

  if (!INS_OperandIsMemory(ins, OP_0))
  {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst))
    {
      I2R_CALL(i2r_ror_opq, reg_dst, sh_len);
    }
    else if (REG_is_gr32(reg_dst))
    {
      I2R_CALL(i2r_ror_opl, reg_dst, sh_len);
    }
    else if (REG_is_gr16(reg_dst))
    {
      I2R_CALL(i2r_ror_opw, reg_dst, sh_len);
    }
    else if (REG_is_xmm(reg_dst))
    {
      I2R_CALL(i2r_ror_opx, reg_dst, sh_len);
    }
    else if (REG_is_ymm(reg_dst))
    {
      I2R_CALL(i2r_ror_opy, reg_dst, sh_len);
    }
    else if (REG_is_mm(reg_dst))
    {
      I2R_CALL(i2r_ror_opq, reg_dst, sh_len);
    }
  }
}

static inline void ins_shr_op(INS ins)
{
  if (!INS_OperandIsImmediate(ins, OP_1))
    return;
  /* use XED to decode the instruction and extract its opcode */
  UINT8 sh_len = INS_OperandImmediate(ins, 1);

  if (!INS_OperandIsMemory(ins, OP_0))
  {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst))
    {
      I2R_CALL(i2r_shr_opq, reg_dst, sh_len);
    }
    else if (REG_is_gr32(reg_dst))
    {
      I2R_CALL(i2r_shr_opl, reg_dst, sh_len);
    }
    else if (REG_is_gr16(reg_dst))
    {
      I2R_CALL(i2r_shr_opw, reg_dst, sh_len);
    }
    else if (REG_is_xmm(reg_dst))
    {
      I2R_CALL(i2r_shr_opx, reg_dst, sh_len);
    }
    else if (REG_is_ymm(reg_dst))
    {
      I2R_CALL(i2r_shr_opy, reg_dst, sh_len);
    }
    else if (REG_is_mm(reg_dst))
    {
      I2R_CALL(i2r_shr_opq, reg_dst, sh_len);
    }
    else if (REG_is_Upper8(reg_dst))
    {
      I2R_CALL(i2r_shr_opb_u, reg_dst, sh_len);
    }
    else
    {
      I2R_CALL(i2r_shr_opb_l, reg_dst, sh_len);
    }
  }
}

static inline void ins_sar_op(INS ins)
{
  if (!INS_OperandIsImmediate(ins, OP_1))
    return;
  /* use XED to decode the instruction and extract its opcode */
  UINT8 sh_len = INS_OperandImmediate(ins, 1);

  if (!INS_OperandIsMemory(ins, OP_0))
  {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst))
    {
      I2R_CALL(i2r_sar_opq, reg_dst, sh_len);
    }
    else if (REG_is_gr32(reg_dst))
    {
      I2R_CALL(i2r_sar_opl, reg_dst, sh_len);
    }
    else if (REG_is_gr16(reg_dst))
    {
      I2R_CALL(i2r_sar_opw, reg_dst, sh_len);
    }
    else if (REG_is_xmm(reg_dst))
    {
      I2R_CALL(i2r_sar_opx, reg_dst, sh_len);
    }
    else if (REG_is_ymm(reg_dst))
    {
      I2R_CALL(i2r_sar_opy, reg_dst, sh_len);
    }
    else if (REG_is_mm(reg_dst))
    {
      I2R_CALL(i2r_sar_opq, reg_dst, sh_len);
    }
    // else if (REG_is_Upper8(reg_dst))
    // {
    //   I2R_CALL(i2r_sar_opb_u, reg_dst, sh_len);
    // }
    // else
    // {
    //   I2R_CALL(i2r_sar_opb_l, reg_dst, sh_len);
    // }
  }
}

static inline void ins_shl_op(INS ins)
{
  if (!INS_OperandIsImmediate(ins, OP_1))
    return;
  /* use XED to decode the instruction and extract its opcode */
  UINT8 sh_len = INS_OperandImmediate(ins, 1);

  if (!INS_OperandIsMemory(ins, OP_0))
  {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst))
    {
      I2R_CALL(i2r_shl_opq, reg_dst, sh_len);
    }
    else if (REG_is_gr32(reg_dst))
    {
      I2R_CALL(i2r_shl_opl, reg_dst, sh_len);
    }
    else if (REG_is_gr16(reg_dst))
    {
      I2R_CALL(i2r_shl_opw, reg_dst, sh_len);
    }
    else if (REG_is_xmm(reg_dst))
    {
      I2R_CALL(i2r_shl_opx, reg_dst, sh_len);
    }
    else if (REG_is_ymm(reg_dst))
    {
      I2R_CALL(i2r_shl_opy, reg_dst, sh_len);
    }
    else if (REG_is_mm(reg_dst))
    {
      I2R_CALL(i2r_shl_opq, reg_dst, sh_len);
    }
    else if (REG_is_Upper8(reg_dst))
    {
      I2R_CALL(i2r_shl_opb_u, reg_dst, sh_len);
    }
    else
    {
      I2R_CALL(i2r_shl_opb_l, reg_dst, sh_len);
    }
  }
}

void ins_shift_op(INS ins)
{
  xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
  switch (ins_indx)
  {
  case XED_ICLASS_RCL:
  case XED_ICLASS_RCR:
    break;
  case XED_ICLASS_ROL:
    ins_rol_op(ins);
    break;
  case XED_ICLASS_ROR:
    ins_ror_op(ins);
    break;
  case XED_ICLASS_SHL:
    ins_shl_op(ins);
    break;
  case XED_ICLASS_SAR:
    ins_sar_op(ins);
    break;
  case XED_ICLASS_SHR:
    ins_shr_op(ins);
    break;
  case XED_ICLASS_SHLD:
  case XED_ICLASS_SHRD:
    break;
  default:
    break;
  }
}
