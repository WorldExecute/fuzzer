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

#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/Module.h"

#include "llvm/IR/IRBuilder.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "utils.h"

using namespace llvm;

static bool isFunctionCmpReturn(Value *val)
{
    PointerType *Int8Ptr = IntegerType::getInt8PtrTy(val->getContext());
    if (CallInst *call = dyn_cast<CallInst>(val))
    {
        bool isStrcmp = true;
        bool isStrncmp = true;
        bool isMemcmp = true;

        Function *Callee = call->getCalledFunction();
        if (!Callee)
            return false;
        if (call->getCallingConv() != llvm::CallingConv::C)
            return false;

        StringRef FuncName = Callee->getName();
        isStrcmp &= !FuncName.compare(StringRef("strcmp"));

        /* Verify the strcmp/memcmp function prototype */
        FunctionType *FT = Callee->getFunctionType();
        isStrcmp &= FT->getNumParams() == 2 &&
                    FT->getReturnType()->isIntegerTy(32) &&
                    FT->getParamType(0) == FT->getParamType(1) &&
                    FT->getParamType(0) == Int8Ptr;
        if (isStrcmp)
            return true;
        isMemcmp &= !(FuncName.compare(StringRef("memcmp")) && FuncName.compare(StringRef("bcmp")));
        isMemcmp &= FT->getNumParams() == 3 &&
                    FT->getParamType(0)->isPointerTy() &&
                    FT->getParamType(1)->isPointerTy() &&
                    FT->getReturnType()->isIntegerTy(32);
        if (isMemcmp)
            return true;
        isStrncmp &= !FuncName.compare(StringRef("strncmp"));
        isStrncmp &= FT->getNumParams() == 3 &&
                     FT->getParamType(0)->isPointerTy() &&
                     FT->getParamType(1)->isPointerTy() &&
                     FT->getReturnType()->isIntegerTy(32);
        return isStrncmp;
    }
    return false;
}

static void preHandleCmpInst(Module &M)
{
    LLVMContext &C = M.getContext();
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

    SmallVector<std::pair<Instruction *, Instruction *>, 256> replacePairs;
    for (auto &F : M)
    {
        if (F.isDeclaration())
            continue;
        if(isSanitizeFunc(&F)) continue;
        DominatorTree DT(F);
        LoopInfo LI;
        LI.analyze(DT);
        for (auto &BB : F)
        {
            for (auto &IN : BB)
            {
                if (isSanitizeInsn(&IN)) continue;
                
                CmpInst *selectcmpInst = dyn_cast<CmpInst>(&IN);
                if (!selectcmpInst)
                    continue;


                auto op0 = selectcmpInst->getOperand(0);
                auto op1 = selectcmpInst->getOperand(1);
                if (isFunctionCmpReturn(op0) || isFunctionCmpReturn(op1))
                {
                    SetMetadata(selectcmpInst, SKIP);
                }

                // Transforms fcmp -> icmp
                bool isEq = selectcmpInst->getPredicate() == CmpInst::FCMP_OEQ;
                bool isNe = selectcmpInst->getPredicate() == CmpInst::FCMP_UNE;
                if (!isEq && !isNe)
                    continue;
                auto pred = isEq ? ICmpInst::Predicate::ICMP_EQ : ICmpInst::Predicate::ICMP_NE;
                Instruction *icmp = nullptr;
                if (op0->getType()->isFloatTy() && op1->getType()->isFloatTy())
                {
                    // 不属于任何 BB 的 Instruction 不能move
                    Instruction *i_op0 = CastInst::Create(Instruction::BitCast, op0, Int32Ty, "", &BB);
                    Instruction *i_op1 = CastInst::Create(Instruction::BitCast, op1, Int32Ty, "", &BB);
                    i_op0->moveBefore(selectcmpInst);
                    i_op1->moveBefore(selectcmpInst);
                    icmp = CmpInst::Create(Instruction::ICmp, pred, i_op0, i_op1);
                }
                else if (op0->getType()->isDoubleTy() && op1->getType()->isDoubleTy())
                {
                    Instruction *i_op0 = CastInst::Create(Instruction::BitCast, op0, Int64Ty, "", &BB);
                    Instruction *i_op1 = CastInst::Create(Instruction::BitCast, op1, Int64Ty, "", &BB);
                    i_op0->moveBefore(selectcmpInst);
                    i_op1->moveBefore(selectcmpInst);
                    icmp = CmpInst::Create(Instruction::ICmp, pred, i_op0, i_op1);
                }
                if (icmp)
                    replacePairs.push_back(std::make_pair(selectcmpInst, icmp));
            }
        }
    }

    for (auto pair : replacePairs)
    {
        Instruction *from = pair.first;
        Instruction *to = pair.second;
        ReplaceInstWithInst(from, to);
    }
}


/* splits icmps of size bitw into two nested icmps with bitw/2 size each */
[[maybe_unused]]
static bool splitCompares(Module &M, unsigned bitw)
{
    LLVMContext &C = M.getContext();

    IntegerType *Int1Ty = IntegerType::getInt1Ty(C);
    IntegerType *OldIntType = IntegerType::get(C, bitw);
    IntegerType *NewIntType = IntegerType::get(C, bitw / 2);

    std::vector<Instruction *> icomps;

    if (bitw % 2)
    {
        return false;
    }

    /* not supported yet */
    if (bitw > 64)
    {
        return false;
    }

    /* get all EQ, NE, UGT, and ULT icmps of width bitw. if the other two
     * unctions were executed only these four predicates should exist */
    for (auto &F : M)
    {
        for (auto &BB : F)
        {
            for (auto &IN : BB)
            {
                CmpInst *selectcmpInst = nullptr;

                if ((selectcmpInst = dyn_cast<CmpInst>(&IN)))
                {
                    if (isInsnOwnMetadata(selectcmpInst, SKIP))
                    {
                        continue;
                    }
                    if (selectcmpInst->getPredicate() != CmpInst::ICMP_EQ &&
                        selectcmpInst->getPredicate() != CmpInst::ICMP_NE &&
                        selectcmpInst->getPredicate() != CmpInst::ICMP_UGT &&
                        selectcmpInst->getPredicate() != CmpInst::ICMP_ULT)
                    {
                        continue;
                    }

                    auto op0 = selectcmpInst->getOperand(0);
                    auto op1 = selectcmpInst->getOperand(1);

                    IntegerType *intTyOp0 = dyn_cast<IntegerType>(op0->getType());
                    IntegerType *intTyOp1 = dyn_cast<IntegerType>(op1->getType());

                    if (!intTyOp0 || !intTyOp1)
                    {
                        continue;
                    }

                    /* check if the bitwidths are the one we are looking for */
                    if (intTyOp0->getBitWidth() != bitw || intTyOp1->getBitWidth() != bitw)
                    {
                        continue;
                    }

                    icomps.push_back(selectcmpInst);
                }
            }
        }
    }

    if (!icomps.size())
    {
        return false;
    }

    for (auto &IcmpInst : icomps)
    {
        BasicBlock *bb = IcmpInst->getParent();

        auto op0 = IcmpInst->getOperand(0);
        auto op1 = IcmpInst->getOperand(1);

        auto pred = dyn_cast<CmpInst>(IcmpInst)->getPredicate();

        BasicBlock *end_bb = bb->splitBasicBlock(BasicBlock::iterator(IcmpInst));

        /* create the comparison of the top halfs of the original operands */
        Instruction *s_op0, *op0_high, *s_op1, *op1_high, *icmp_high;
        s_op0 = BinaryOperator::Create(Instruction::LShr, op0, ConstantInt::get(OldIntType, bitw / 2));
        bb->getInstList().insert(bb->getTerminator()->getIterator(), s_op0);
        op0_high = new TruncInst(s_op0, NewIntType);
        bb->getInstList().insert(bb->getTerminator()->getIterator(), op0_high);

        s_op1 = BinaryOperator::Create(Instruction::LShr, op1, ConstantInt::get(OldIntType, bitw / 2));
        bb->getInstList().insert(bb->getTerminator()->getIterator(), s_op1);
        op1_high = new TruncInst(s_op1, NewIntType);
        bb->getInstList().insert(bb->getTerminator()->getIterator(), op1_high);

        icmp_high = CmpInst::Create(Instruction::ICmp, pred, op0_high, op1_high);
        bb->getInstList().insert(bb->getTerminator()->getIterator(), icmp_high);

        /* now we have to destinguish between == != and > < */
        if (pred == CmpInst::ICMP_EQ || pred == CmpInst::ICMP_NE)
        {
            /* transformation for == and != icmps */

            /* create a compare for the lower half of the original operands */
            Instruction *op0_low, *op1_low, *icmp_low;
            BasicBlock *cmp_low_bb = BasicBlock::Create(C, "injected", end_bb->getParent(), end_bb);

            op0_low = new TruncInst(op0, NewIntType);
            cmp_low_bb->getInstList().push_back(op0_low);

            op1_low = new TruncInst(op1, NewIntType);
            cmp_low_bb->getInstList().push_back(op1_low);

            icmp_low = CmpInst::Create(Instruction::ICmp, pred, op0_low, op1_low);
            cmp_low_bb->getInstList().push_back(icmp_low);
            BranchInst::Create(end_bb, cmp_low_bb);

            /* dependant on the cmp of the high parts go to the end or go on with
             * the comparison */
            auto term = bb->getTerminator();
            if (pred == CmpInst::ICMP_EQ)
            {
                BranchInst::Create(cmp_low_bb, end_bb, icmp_high, bb);
            }
            else
            {
                /* CmpInst::ICMP_NE */
                BranchInst::Create(end_bb, cmp_low_bb, icmp_high, bb);
            }
            term->eraseFromParent();

            /* create the PHI and connect the edges accordingly */
            PHINode *PN = PHINode::Create(Int1Ty, 2, "");
            PN->addIncoming(icmp_low, cmp_low_bb);
            if (pred == CmpInst::ICMP_EQ)
            {
                PN->addIncoming(ConstantInt::get(Int1Ty, 0), bb);
            }
            else
            {
                /* CmpInst::ICMP_NE */
                PN->addIncoming(ConstantInt::get(Int1Ty, 1), bb);
            }

            /* replace the old icmp with the new PHI */
            BasicBlock::iterator ii(IcmpInst);
            ReplaceInstWithInst(IcmpInst->getParent()->getInstList(), ii, PN);
        }
        else
        {
            /* CmpInst::ICMP_UGT and CmpInst::ICMP_ULT */
            /* transformations for < and > */

            /* create a basic block which checks for the inverse predicate.
             * if this is true we can go to the end if not we have to got to the
             * bb which checks the lower half of the operands */
            Instruction *icmp_inv_cmp, *op0_low, *op1_low, *icmp_low;
            BasicBlock *inv_cmp_bb = BasicBlock::Create(C, "inv_cmp", end_bb->getParent(), end_bb);
            if (pred == CmpInst::ICMP_UGT)
            {
                icmp_inv_cmp = CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_ULT, op0_high, op1_high);
            }
            else
            {
                icmp_inv_cmp = CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_UGT, op0_high, op1_high);
            }
            inv_cmp_bb->getInstList().push_back(icmp_inv_cmp);

            auto term = bb->getTerminator();
            term->eraseFromParent();
            BranchInst::Create(end_bb, inv_cmp_bb, icmp_high, bb);

            /* create a bb which handles the cmp of the lower halfs */
            BasicBlock *cmp_low_bb = BasicBlock::Create(C, "injected", end_bb->getParent(), end_bb);
            op0_low = new TruncInst(op0, NewIntType);
            cmp_low_bb->getInstList().push_back(op0_low);
            op1_low = new TruncInst(op1, NewIntType);
            cmp_low_bb->getInstList().push_back(op1_low);

            icmp_low = CmpInst::Create(Instruction::ICmp, pred, op0_low, op1_low);
            cmp_low_bb->getInstList().push_back(icmp_low);
            BranchInst::Create(end_bb, cmp_low_bb);

            BranchInst::Create(end_bb, cmp_low_bb, icmp_inv_cmp, inv_cmp_bb);

            PHINode *PN = PHINode::Create(Int1Ty, 3);
            PN->addIncoming(icmp_low, cmp_low_bb);
            PN->addIncoming(ConstantInt::get(Int1Ty, 1), bb);
            PN->addIncoming(ConstantInt::get(Int1Ty, 0), inv_cmp_bb);

            BasicBlock::iterator ii(IcmpInst);
            ReplaceInstWithInst(IcmpInst->getParent()->getInstList(), ii, PN);
        }
    }
    return true;
}

/**
 * Modified from splitCompares.
 * 64 -> 56 -> 48 -> 40 -> 40 -> 32 -> 24 -> 16 -> 8
 */
static bool splitCompare(Module &M, unsigned bitw)
{
    LLVMContext &C = M.getContext();

    IntegerType *Int1Ty = IntegerType::getInt1Ty(C);
    IntegerType *OldIntType = IntegerType::get(C, bitw);
    IntegerType *NewIntType = IntegerType::get(C, 8);

    std::vector<Instruction *> icomps;

    if (bitw & 1)
    {
        return false;
    }

    /* not supported yet */
    if (bitw > 64)
    {
        return false;
    }

    /* get all EQ, NE, UGT, and ULT icmps of width bitw. if the other two
     * unctions were executed only these four predicates should exist */
    for (auto &F : M)
    {
        if(isSanitizeFunc(&F)) continue;
        for (auto &BB : F)
        {
            
            for (auto &IN : BB)
            {
                if (isSanitizeInsn(&IN)) continue;

                CmpInst *selectcmpInst = nullptr;

                if ((selectcmpInst = dyn_cast<CmpInst>(&IN)))
                {

                    if (isInsnOwnMetadata(selectcmpInst, SKIP))
                    {
                        continue;
                    }

                    if (selectcmpInst->getPredicate() != CmpInst::ICMP_EQ &&
                        selectcmpInst->getPredicate() != CmpInst::ICMP_NE
                        // &&
                        // selectcmpInst->getPredicate() != CmpInst::ICMP_UGT &&
                        // selectcmpInst->getPredicate() != CmpInst::ICMP_ULT
                    )
                    {
                        continue;
                    }

                    auto op0 = selectcmpInst->getOperand(0);
                    auto op1 = selectcmpInst->getOperand(1);
        
                    IntegerType *intTyOp0 = dyn_cast<IntegerType>(op0->getType());
                    IntegerType *intTyOp1 = dyn_cast<IntegerType>(op1->getType());
    

                    if (!intTyOp0 || !intTyOp1)
                    {
                        continue;
                    }

                    /* check if the bitwidths are the one we are looking for */
                    if (intTyOp0->getBitWidth() != bitw || intTyOp1->getBitWidth() != bitw)
                    {
                        continue;
                    }

                    icomps.push_back(selectcmpInst);
                }
            }
        }
    }

    if (!icomps.size())
    {
        return false;
    }

    Value *ZERO = ConstantInt::get(Int1Ty, 0);
    Value *ONE = ConstantInt::get(Int1Ty, 1);

    for (auto &IcmpInst : icomps)
    {
        BasicBlock *bb = IcmpInst->getParent();

        auto op0 = IcmpInst->getOperand(0);
        auto op1 = IcmpInst->getOperand(1);

        auto pred = dyn_cast<CmpInst>(IcmpInst)->getPredicate();

        BasicBlock *end_bb = bb->splitBasicBlock(BasicBlock::iterator(IcmpInst)),
                   *cmp_low_bb;
        auto *orig_term = bb->getTerminator();

        PHINode *PN = PHINode::Create(Int1Ty, 2, "rep");
        /* create the comparison of the top halfs of the original operands */
        Value *s_op0, *new_op0, *s_op1, *new_op1, *icmp;
        // 能从低位开始比较，就从地位开始比较

        unsigned shift_len = bitw;
        while (shift_len)
        {
            IRBuilder<> IRB(bb);
            if (shift_len != 8)
            {
                s_op0 = IRB.CreateLShr(op0, ConstantInt::get(OldIntType, shift_len - 8));
                new_op0 = IRB.CreateTrunc(s_op0, NewIntType);

                s_op1 = IRB.CreateLShr(op1, ConstantInt::get(OldIntType, shift_len - 8));
                new_op1 = IRB.CreateTrunc(s_op1, NewIntType);

                // 若是指令，说明不是常量
                SetMetadata(s_op0, CMP_OP);

                // 若是指令，说明不是常量
                SetMetadata(s_op1, CMP_OP);
            }
            else
            {
                new_op0 = IRB.CreateTrunc(op0, NewIntType);
                new_op1 = IRB.CreateTrunc(op1, NewIntType);

                SetMetadata(new_op0, CMP_OP);

                // 若是指令，说明不是常量
                SetMetadata(new_op1, CMP_OP);
            }

            cmp_low_bb = BasicBlock::Create(C, "injected", end_bb->getParent(), end_bb);

            icmp = IRB.CreateICmp(pred, new_op0, new_op1);
            shift_len -= 8;

            if (pred == CmpInst::ICMP_EQ)
            {
                BranchInst::Create(cmp_low_bb, end_bb, icmp, bb);
                PN->addIncoming(ZERO, bb);
            }
            else if (pred == CmpInst::ICMP_NE)
            {
                /* CmpInst::ICMP_NE */
                BranchInst::Create(end_bb, cmp_low_bb, icmp, bb);
                PN->addIncoming(ONE, bb);
            }
            else
            {
                if (shift_len)
                {
                    auto eq = IRB.CreateICmpEQ(new_op0, new_op1);
                    BranchInst::Create(cmp_low_bb, end_bb, eq, bb);
                    PN->addIncoming(icmp, bb);
                }
                else
                {
                    BranchInst::Create(cmp_low_bb, end_bb, icmp, bb);
                    PN->addIncoming(ZERO, bb);
                }
            }
            SetBBMetadata(bb, CMP_SPLIT);

            bb = cmp_low_bb;
        }

        BranchInst::Create(end_bb, bb);
        if (pred == CmpInst::ICMP_NE)
        {
            /* CmpInst::ICMP_NE */
            PN->addIncoming(ZERO, bb);
        }
        else
        {
            PN->addIncoming(ONE, bb);
        }
        SetBBMetadata(bb, CMP_SPLIT);
        orig_term->eraseFromParent();
        /* replace the old icmp with the new PHI */
        BasicBlock::iterator ii(IcmpInst);
        ReplaceInstWithInst(IcmpInst->getParent()->getInstList(), ii, PN);
    }
    return true;
}



static void split_compare(Module &M)
{
    int bitw = 64;
    char *bitw_env = getenv("LAF_SPLIT_COMPARES_BITW");
    if (bitw_env)
    {
        bitw = atoi(bitw_env);
    }

    preHandleCmpInst(M);


    errs() << "Split-compare-pass, from laf.intel@gmail.com, modified by me\n";

    switch (bitw)
    {
    case 64:
        errs() << "Running split-compare-pass " << 64 << "\n";
        splitCompare(M, 64);
    case 32:
        errs() << "Running split-compare-pass " << 32 << "\n";
        splitCompare(M, 32);
    case 16:
        errs() << "Running split-compare-pass " << 16 << "\n";
        splitCompare(M, 16);
        break;

    default:
        errs() << "NOT Running split-compare-pass \n";
        return;
    }

    verifyModule(M);
}

PreservedAnalyses SplitNByteCmpPass::run(Module &M, ModuleAnalysisManager &AM)
{
    split_compare(M);
    return PreservedAnalyses::none();
}