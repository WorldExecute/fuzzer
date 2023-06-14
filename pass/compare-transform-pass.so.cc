/*
 * Copyright 2016 laf-intel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * Modified from LafIntel.
 */

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/Casting.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <cstddef>
#include <set>
#include <utility>

#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/CGSCCPassManager.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/InferFunctionAttrs.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/Scalar/EarlyCSE.h"
#include "llvm/Transforms/Scalar/LICM.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Mem2Reg.h"
#include "utils.h"

using namespace llvm;
static ConstantInt *ZERO;
static ConstantInt *ZERO_8;
static ConstantInt *ONE;
static ConstantInt *M_ONE;
static PointerType *Int8Ptr;
static ConstantPointerNull *Null;
static IntegerType *Int8Ty;
static IntegerType *Int32Ty;
static IntegerType *Int64Ty;
static IntegerType *SizeTTy;

static inline bool isReadOnlyCall(Instruction *insn) {
  if (CallInst *callInst = dyn_cast<CallInst>(insn)) {
    Function *F = callInst->getCalledFunction();
    return F->hasFnAttribute(Attribute::ReadOnly);
  }
  return false;
}

/**
 * const char *c3 = "asd";
 * const char c4[] = "asd";
 * def func() {
 *      const char *const c1 = "asd";
 *      const char c2[] = "asd";
 * }
 * @return
 */
[[maybe_unused]]
static inline Value *getActualConstantValue() { return nullptr; }

static bool isRootAtMainArgv(Instruction *insn, Argument *target) {
  // 函数调用不算， 因为open， fopen ...
  if (!isReadOnlyCall(insn)) return false;
  for (auto &op : insn->operands()) {
    if (op == target) return true;
    if (Instruction *opInsn = dyn_cast<Instruction>(op)) {
      if (isRootAtMainArgv(opInsn, target)) return true;
    }
  }
  return false;
}
// 只做简单过滤，如果深度过滤需要做内存依赖分析，我不想在
// phantom外的其他pass做此分析
static bool isFromMainArgv(Value *val) {
  if (val->getType() != Int8Ptr) return false;

  // 暂时无法识别全局变量的情况
  Instruction *insn = dyn_cast<Instruction>(val);
  if (!insn) return false;
  FunctionType *FT = insn->getFunction()->getFunctionType();

  if (insn->getFunction()->getName() != "main" || FT->getNumParams() != 2 ||
      !FT->getParamType(0)->isIntegerTy(32) ||
      FT->getParamType(1) != Int8Ptr->getPointerTo())
    return false;
  Argument *arg = insn->getFunction()->getArg(1);

  return isRootAtMainArgv(insn, arg);
}

typedef std::function<Value *(uint64_t idx, IRBuilder<> &IRB)> NextCmpGen;

static BasicBlock *splitCmp(uint64_t constLen, Value *VarStr, bool ConstFirst,
                            Instruction *repl, NextCmpGen nextCmp) {
  /* split before the call instruction */
  LLVMContext &C = repl->getContext();

  if (constLen == 0) {
    BasicBlock *curBB = repl->getParent();
    BasicBlock::iterator ii(repl);
    ReplaceInstWithValue(repl->getParent()->getInstList(), ii, ZERO);
    return curBB;
  } else {
    /* split before the call instruction */
    BasicBlock *bb = repl->getParent();
    BasicBlock *end_bb = bb->splitBasicBlock(BasicBlock::iterator(repl));

    PHINode *PN = PHINode::Create(Int32Ty, constLen + 1, "cmp_phi");

    Value *sext = nullptr;

    BasicBlock *cur_bb = bb;
    IRBuilder<> IRB(bb->getTerminator());

    for (uint64_t i = 0; i < constLen; i++) {
      Value *cmpTo = nextCmp(i, IRB);

      Value *v = ConstantInt::get(Int64Ty, i);
      Value *ele = IRB.CreateInBoundsGEP(VarStr, v, "empty");
      SetMetadata(ele, CMP_OP);

      Value *load = IRB.CreateLoad(ele);
      SetNoSanitize(load);
      Value *isub;
      if (ConstFirst)
        isub = IRB.CreateSub(cmpTo, load);
      else
        isub = IRB.CreateSub(load, cmpTo);

      sext = IRB.CreateSExt(isub, Int32Ty);
      PN->addIncoming(sext, cur_bb);

      BasicBlock *next_bb =
          BasicBlock::Create(C, "cmp_added", end_bb->getParent(), end_bb);
      BranchInst::Create(end_bb, next_bb);

      auto *term = cur_bb->getTerminator();
      Value *icmp = IRB.CreateICmpEQ(isub, ConstantInt::get(Int8Ty, 0));
      IRB.CreateCondBr(icmp, next_bb, end_bb);
      term->eraseFromParent();
      SetBBMetadata(cur_bb, CMP_SPLIT);

      cur_bb = next_bb;
      BasicBlock::iterator IP = next_bb->getFirstInsertionPt();
      IRB.SetInsertPoint(&*IP);

      // add offset to varstr
      // create load
      // create signed isub
      // create icmp
      // create jcc
      // create next_bb
    }
    if (sext) PN->addIncoming(sext, cur_bb);
    /* since the call is the first instruction of the bb it is save to
     * replace it with a phi instruction */
    BasicBlock::iterator ii(repl);
    ReplaceInstWithInst(repl->getParent()->getInstList(), ii, PN);
    return end_bb;
  }
}

static bool transformStrstr(Module &M) {
  std::vector<CallInst *> calls;
  LLVMContext &C = M.getContext();

  /* iterate over all functions, bbs and instruction and add suitable calls to
   * strcmp/memcmp */
  for (auto &F : M) {
    if (isSanitizeFunc(&F)) continue;
    for (auto &BB : F) {
      for (auto &IN : BB) {
        if (isSanitizeInsn(&IN)) continue;
        CallInst *callInst = nullptr;

        if ((callInst = dyn_cast<CallInst>(&IN))) {
          bool isStrstr;
          Function *Callee = callInst->getCalledFunction();
          if (!Callee) continue;
          if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
          StringRef FuncName = Callee->getName();
          isStrstr = !FuncName.compare(StringRef("strstr"));

          /* Verify the strcmp/memcmp function prototype */
          FunctionType *FT = Callee->getFunctionType();
          isStrstr &= FT->getNumParams() == 2 &&
                      FT->getReturnType() == Int8Ptr &&
                      FT->getParamType(0) == FT->getParamType(1) &&
                      FT->getParamType(0) == Int8Ptr;

          if (!isStrstr) continue;

          /* is a strcmp/memcmp, check is we have strcmp(x, "const") or
           * strcmp("const", x)
           * memcmp(x, "const", ..) or memcmp("const", x, ..) */
          Value *Str1P = callInst->getArgOperand(0);
          Value *Str2P = callInst->getArgOperand(1);
          StringRef Str2;
          bool HasStr2 = getConstantStringInfo(Str2P, Str2);
          if (HasStr2 && isFromMainArgv(Str1P)) {
            callInst->setMetadata(ARGV_RELATED, MDNode::get(C, None));
            continue;
          }
          if (!Str2.size() || GetStringLength(Str2P) < 2) continue;

          /* one string const, one string variable */
          if (!HasStr2) continue;

          calls.push_back(callInst);
        }
      }
    }
  }

  if (!calls.size()) return false;
  errs() << "Replacing " << calls.size() << " calls to strstr\n";

  ConstantInt *One64 = ConstantInt::get(C, APInt(64, 1));
  for (auto &callInst : calls) {
    Value *Str2P = callInst->getArgOperand(1);
    StringRef ConstStr;
    if (!getConstantStringInfo(Str2P, ConstStr)) {
      continue;
    }

    // uint64_t constLen  = GetStringLength(Str1P);
    uint64_t constLen = ConstStr.size();
    if (constLen == 0) continue;

    uint64_t cmpLen = constLen - 1;
    StringRef CmpStr = ConstStr.substr(1);
    ConstantInt *FirstChr = ConstantInt::get(C, APInt(8, ConstStr[0]));

    errs() << "strstr, strict-len " << constLen << ": " << ConstStr << "\n";

    /* split before the call instruction */
    BasicBlock *cur_bb = callInst->getParent();
    BasicBlock *end_bb =
        cur_bb->splitBasicBlock(BasicBlock::iterator(callInst));
    BasicBlock *bb1 =
        BasicBlock::Create(C, "cmp_added", end_bb->getParent(), end_bb);
    BasicBlock *bb2 =
        BasicBlock::Create(C, "cmp_added", end_bb->getParent(), end_bb);
    BasicBlock *bb3 =
        BasicBlock::Create(C, "cmp_added", end_bb->getParent(), end_bb);

    PHINode *PN3 = PHINode::Create(Int8Ptr, 3, "res_phi");

    Value *haystack = callInst->getArgOperand(0);
    IRBuilder<> IRB(cur_bb->getTerminator());
    auto val = IRB.CreateLoad(haystack, "init_load");
    SetNoSanitize(val);
    auto cond = IRB.CreateICmpEQ(val, ZERO_8);
    cur_bb->getTerminator()->eraseFromParent();
    BranchInst::Create(end_bb, bb1, cond, cur_bb);

    IRB.SetInsertPoint(bb1);
    auto PN1 = IRB.CreatePHI(Int8Ty, 2, "loop_phi_1");
    auto PN2 = IRB.CreatePHI(Int8Ptr, 2, "loop_phi_2");
    auto ptr = IRB.CreateGEP(PN2, One64);
    cond = IRB.CreateICmpEQ(PN1, FirstChr);
    BranchInst::Create(bb2, bb3, cond, bb1);

    IRB.SetInsertPoint(bb2);
    // todo
    auto repl = IRB.CreateZExt(PN1, Int32Ty);
    cond = IRB.CreateICmpNE(repl, ZERO);
    BranchInst::Create(bb3, end_bb, cond, bb2);

    BasicBlock *split_end_bb = splitCmp(
        cmpLen, ptr, false, dyn_cast<Instruction>(repl),
        [CmpStr](uint64_t idx, auto) {
          return idx == CmpStr.size() ? ConstantInt::get(Int8Ty, 0)
                                      : ConstantInt::get(Int8Ty, CmpStr[idx]);
        });

    IRB.SetInsertPoint(bb3);
    auto val2 = IRB.CreateLoad(ptr, "sec_load");
    SetNoSanitize(val2);
    cond = IRB.CreateICmpEQ(val2, ZERO_8);
    BranchInst::Create(end_bb, bb1, cond, bb3);

    PN1->addIncoming(val, cur_bb);
    PN1->addIncoming(val2, bb3);

    PN2->addIncoming(haystack, cur_bb);
    PN2->addIncoming(ptr, bb3);

    PN3->addIncoming(Null, cur_bb);
    PN3->addIncoming(Null, bb3);
    PN3->addIncoming(PN2, split_end_bb);

    /* since the call is the first instruction of the bb it is save to
     * replace it with a phi instruction */
    BasicBlock::iterator ii(callInst);
    ReplaceInstWithInst(callInst->getParent()->getInstList(), ii, PN3);
    if (llvm::verifyModule(M, &llvm::errs())) {
      M.print(llvm::errs(), nullptr);
      llvm::report_fatal_error("Bad function");
    }
  }
  return true;
}
static Constant * constExprDewrap(ConstantExpr *constExpr) {
    // constExpr->getAsInstruction()
    switch (constExpr->getOpcode()) {
        case Instruction::BitCast:
        case Instruction::GetElementPtr:
        Constant *value = constExpr->getOperand(0);
        if (auto c_expr = dyn_cast<ConstantExpr>(value)) {
            return constExprDewrap(c_expr);
        } else {
            return value;
        }
    }
    return nullptr;
}

static inline int getConstArgIdx(CallInst *callInst) {
  StringRef str;
  for (size_t i = 0; i != callInst->getNumArgOperands(); i++) {
    auto operand = callInst->getArgOperand(i);
    if (getConstantStringInfo(operand, str)) {
      return i;
    }
    
    
    Value *global;
    if (auto constExpr = dyn_cast<ConstantExpr>(operand)){
        global = constExprDewrap(constExpr);
    } else {
        global = operand;
    }

    if (auto gv = dyn_cast<GlobalVariable>(global)) {
      if (gv->isConstant()) {
        return i;
      }
    }
  }

  return -1;
}

static bool transformCmps(Module &M, const bool processStrcmp,
                          const bool processStrncmp, const bool processMemcmp) {
  std::vector<std::pair<CallInst *, int>> calls;
  LLVMContext &C = M.getContext();

  /* iterate over all functions, bbs and instruction and add suitable calls to
   * strcmp/memcmp */
  for (auto &F : M) {
    if (isSanitizeFunc(&F)) continue;
    for (auto &BB : F) {
      for (auto &IN : BB) {
        if (isSanitizeInsn(&IN)) continue;
        CallInst *callInst = nullptr;

        if ((callInst = dyn_cast<CallInst>(&IN))) {
          bool isStrcmp = processStrcmp;
          bool isStrncmp = processStrncmp;
          bool isMemcmp = processMemcmp;

          Function *Callee = callInst->getCalledFunction();
          if (!Callee) continue;
          if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
          StringRef FuncName = Callee->getName();
          isStrcmp &= !FuncName.compare(StringRef("strcmp"));
          isStrncmp &= !FuncName.compare(StringRef("strncmp"));
          isMemcmp &= !(FuncName.compare(StringRef("memcmp")) &&
                        FuncName.compare(StringRef("bcmp")));

          /* Verify the strcmp/memcmp function prototype */
          FunctionType *FT = Callee->getFunctionType();
          isStrcmp &= FT->getNumParams() == 2 &&
                      FT->getReturnType()->isIntegerTy(32) &&
                      FT->getParamType(0) == FT->getParamType(1) &&
                      FT->getParamType(0) == Int8Ptr;

          isMemcmp &= FT->getNumParams() == 3 &&
                      FT->getParamType(0)->isPointerTy() &&
                      FT->getParamType(1)->isPointerTy() &&
                      FT->getReturnType()->isIntegerTy(32);

          isStrncmp &= FT->getNumParams() == 3 &&
                       FT->getParamType(0) == Int8Ptr &&
                       FT->getParamType(1) == Int8Ptr &&
                       FT->getReturnType()->isIntegerTy(32);
          if (!isStrcmp && !isMemcmp && !isStrncmp) continue;

          /* is a strcmp/memcmp, check is we have strcmp(x, "const") or
           * strcmp("const", x)
           * memcmp(x, "const", ..) or memcmp("const", x, ..) */

          int constIdx = getConstArgIdx(callInst);
          if (constIdx == -1) {
            continue;
          }

          Value *constArg = callInst->getArgOperand(constIdx);

          if (isFromMainArgv(constArg)) {
            callInst->setMetadata(ARGV_RELATED, MDNode::get(C, None));
            continue;
          }

          if (isMemcmp | isStrncmp) {
            /* check if third operand is a constant integer
             * strlen("constStr") and sizeof() are treated as constant */
            Value *op2 = callInst->getArgOperand(2);
            ConstantInt *ilen = dyn_cast<ConstantInt>(op2);
            if (!ilen) continue;
            /* final precaution: if size of compare is larger than constant
             * string skip it*/
            // uint64_t literalLenght = GetStringLength(constArg);
            // if (literalLenght < ilen->getZExtValue() && isMemcmp) continue;
          }

          calls.push_back(std::make_pair(callInst, constIdx));
        }
      }
    }
  }

  if (!calls.size()) return false;
  errs() << "Replacing " << calls.size() << " calls to strcmp/memcmp\n";

  // todo : 怎么做memcmp
  for (auto &pair : calls) {
    CallInst *callInst = pair.first;
    int constIdx = pair.second;
    bool ConstFirst = constIdx == 0;

    auto funcName = callInst->getCalledFunction()->getName();
    bool isMemcmp = !(funcName.compare(StringRef("memcmp")) &&
                      funcName.compare(StringRef("bcmp")));
    bool isStrncmp = !funcName.compare(StringRef("strncmp"));

    if (isStrncmp || !isMemcmp) {
      Value *VarArg = callInst->getArgOperand(ConstFirst ? 1 : 0),
            *ConstArg = callInst->getArgOperand(constIdx);
      StringRef ConstStr;
      if (!getConstantStringInfo(ConstArg, ConstStr)) {
        continue;
      }
      uint64_t constLen = GetStringLength(ConstArg);
      if (isStrncmp) {
        Value *op2 = callInst->getArgOperand(2);
        ConstantInt *ilen = dyn_cast<ConstantInt>(op2);
        uint64_t specifiedLen = ilen->getZExtValue();
        constLen = std::min(constLen, specifiedLen);
      }
      errs() << "str, len " << constLen << ": " << ConstStr << "\n";
      splitCmp(constLen, VarArg, ConstFirst, callInst,
               [ConstStr](uint64_t idx, auto) {
                 return (idx == ConstStr.size()
                             ? ConstantInt::get(Int8Ty, 0)
                             : ConstantInt::get(Int8Ty, ConstStr[idx]));
               });
    } else {
      Value *VarArg = callInst->getArgOperand(ConstFirst ? 1 : 0),
            *ConstArg = callInst->getArgOperand(constIdx);
      ConstantDataArraySlice ConstSlice;
      Value *op2 = callInst->getArgOperand(2);
      ConstantInt *ilen = dyn_cast<ConstantInt>(op2);
      uint64_t specifiedLen = ilen->getZExtValue();
      errs() << "mem, " << *ConstArg << "\n";
      if (getConstantDataArrayInfo(ConstArg, ConstSlice, 8, 0)) {
        splitCmp(specifiedLen, VarArg, ConstFirst, callInst,
                 [ConstSlice](uint64_t idx, auto) {
                   return ConstantInt::get(Int8Ty, ConstSlice[idx]);
                 });
      } else {
        splitCmp(specifiedLen, VarArg, ConstFirst, callInst,
                 [ConstArg](uint64_t idx, IRBuilder<> &IRB) {
                   // This is not an instruction, but a ConstExpression
                   auto ele = IRB.CreateInBoundsGEP(
                       ConstArg, ConstantInt::get(Int64Ty, idx));
                   SetMetadata(ele, CMP_OP);
                   Value *load = IRB.CreateLoad(ele);
                   SetNoSanitize(load);
                   return load;
                 });
      }
    }

    // Value *Str1P = callInst->getArgOperand(0),
    //       *Str2P = callInst->getArgOperand(1);
    // StringRef Str1, Str2, ConstStr;
    // ConstantDataArraySlice Slice1, Slice2, ConstSlice;
    // Value *VarStr;

    // uint64_t constLen, specifiedLen = 0;

    // bool useSpecifiedLen = isMemcmp | isStrncmp;

    // if (useSpecifiedLen) {
    //   Value *op2 = callInst->getArgOperand(2);
    //   ConstantInt *ilen = dyn_cast<ConstantInt>(op2);
    //   specifiedLen = ilen->getZExtValue();
    // }

    // if (isMemcmp) {
    //   ConstFirst = getConstantDataArrayInfo(Str1P, Slice1, 8, 0);
    //   getConstantDataArrayInfo(Str2P, Slice2, 8, 0);
    //   if (ConstFirst) {
    //     ConstSlice = Slice1;
    //     VarStr = Str2P;
    //     constLen = specifiedLen;
    //   } else {
    //     ConstSlice = Slice2;
    //     VarStr = Str1P;
    //     constLen = specifiedLen;
    //   }
    // } else {
    //   ConstFirst = getConstantStringInfo(Str1P, Str1);
    //   getConstantStringInfo(Str2P, Str2);
    //   if (ConstFirst) {
    //     ConstStr = Str1;
    //     VarStr = Str2P;
    //     constLen = GetStringLength(Str1P);
    //   } else {
    //     ConstStr = Str2;
    //     VarStr = Str1P;
    //     constLen = GetStringLength(Str2P);
    //   }

    //   if (useSpecifiedLen) {
    //     constLen = std::min(constLen, specifiedLen);
    //   }
    // }

    // if (isMemcmp) {
    //   errs() << "mem, ";
    //   ConstSlice.Array->print(errs());
    //   errs() << "\n";
    // } else {
    //   errs() << "str, len " << constLen << ": " << ConstStr << "\n";
    // }

    // splitCmp(constLen, VarStr, ConstFirst, callInst,
    //          [isMemcmp, ConstSlice, ConstStr](uint64_t idx) {
    //            return isMemcmp
    //                       ? ConstantInt::get(Int8Ty, ConstSlice[idx])
    //                       : (idx == ConstStr.size()
    //                              ? ConstantInt::get(Int8Ty, 0)
    //                              : ConstantInt::get(Int8Ty, ConstStr[idx]));
    //          });

    // if (constLen == 0)
    // {
    //     auto zero = BinaryOperator::Create(Instruction::And, ZERO, ZERO);
    //     BasicBlock::iterator ii(callInst);
    //     ReplaceInstWithInst(callInst->getParent()->getInstList(), ii, zero);
    // }
    // else
    // {
    //     /* split before the call instruction */
    //     BasicBlock *bb = callInst->getParent();
    //     BasicBlock *end_bb =
    //     bb->splitBasicBlock(BasicBlock::iterator(callInst));

    //     PHINode *PN = PHINode::Create(Int32Ty, constLen + 1, "cmp_phi");

    //     Value *sext = nullptr;

    //     BasicBlock *cur_bb = bb;
    //     IRBuilder<> IRB(bb->getTerminator());

    //     for (uint64_t i = 0; i < constLen; i++)
    //     {

    //         char c = isMemcmp ? ConstSlice[i] : (i == ConstStr.size() ?
    //         '\x00' : ConstStr[i]);

    //         Value *v = ConstantInt::get(Int64Ty, i);
    //         Value *ele = IRB.CreateInBoundsGEP(VarStr, v, "empty");
    //         SetMetadata(ele, CMP_OP);

    //         Value *load = IRB.CreateLoad(ele);
    //         SetNoSanitize(load);
    //         Value *isub;
    //         if (ConstFirst)
    //             isub = IRB.CreateSub(ConstantInt::get(Int8Ty, c), load);
    //         else
    //             isub = IRB.CreateSub(load, ConstantInt::get(Int8Ty, c));

    //         sext = IRB.CreateSExt(isub, Int32Ty);
    //         PN->addIncoming(sext, cur_bb);

    //         BasicBlock *next_bb = BasicBlock::Create(C, "cmp_added",
    //         end_bb->getParent(), end_bb); BranchInst::Create(end_bb,
    //         next_bb);

    //         auto *term = cur_bb->getTerminator();
    //         Value *icmp = IRB.CreateICmpEQ(isub, ConstantInt::get(Int8Ty,
    //         0)); IRB.CreateCondBr(icmp, next_bb, end_bb);
    //         term->eraseFromParent();
    //         SetBBMetadata(cur_bb, CMP_SPLIT);

    //         cur_bb = next_bb;
    //         BasicBlock::iterator IP = next_bb->getFirstInsertionPt();
    //         IRB.SetInsertPoint(&*IP);

    //         // add offset to varstr
    //         // create load
    //         // create signed isub
    //         // create icmp
    //         // create jcc
    //         // create next_bb
    //     }
    //     if (sext)
    //         PN->addIncoming(sext, cur_bb);
    //     /* since the call is the first instruction of the bb it is save to
    //      * replace it with a phi instruction */
    //     BasicBlock::iterator ii(callInst);
    //     ReplaceInstWithInst(callInst->getParent()->getInstList(), ii, PN);
    // }

    //        if (llvm::verifyModule(M, &llvm::errs())) {
    //            M.print(llvm::errs(), nullptr);
    //            llvm::report_fatal_error("Bad function");
    //        }
  }

  return true;
}

static void compare_transform(Module &M) {
  llvm::errs() << "Running compare-transform-pass, from laf.intel@gmail.com, "
                  "modified by me\n";
  LLVMContext &C = M.getContext();
  ZERO = ConstantInt::get(C, APInt(32, 0));
  ZERO_8 = ConstantInt::get(C, APInt(8, 0));
  ONE = ConstantInt::get(C, APInt(32, 1));
  M_ONE = ConstantInt::get(C, APInt(32, -1));
  Int8Ty = IntegerType::getInt8Ty(C);
  Int32Ty = IntegerType::getInt32Ty(C);
  Int64Ty = IntegerType::getInt64Ty(C);
  Int8Ptr = IntegerType::getInt8PtrTy(C);
  Null = ConstantPointerNull::get(Int8Ptr);
  SizeTTy = IntegerType::get(C, (int)sizeof(size_t));

  transformCmps(M, true, true, true);
  transformStrstr(M);
  verifyModule(M);
}

PreservedAnalyses SplitFuncCmpPass::run(Module &M, ModuleAnalysisManager &AM) {
  compare_transform(M);
  return PreservedAnalyses::none();
}
