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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "llvm/ADT/Statistic.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/ValueTracking.h"

#include "utils.h"
#include "Pass.h"
#include <fcntl.h>

#include <set>

using namespace llvm;
struct CaseExpr
{
  ConstantInt *Val;
  BasicBlock *BB;
  CaseExpr(ConstantInt *val = nullptr, BasicBlock *bb = nullptr) : Val(val), BB(bb) {}
};

typedef std::vector<CaseExpr> CaseVector;

static void boolSwitch2br(SwitchInst *SI)
{
  assert(SI->getNumCases() == 2 && "Not a boolean switch!");
  BasicBlock *thenBB = NULL, *elseBB = NULL;
  SmallVector<CaseExpr, 2> cases;
  for (SwitchInst::CaseIt i = SI->case_begin(), e = SI->case_end(); i != e; ++i)
  {

    assert(i->getCaseValue()->getBitWidth() == 1 && "Not a boolean switch");
    if (i->getCaseValue()->getSExtValue() == 0)
    {
      elseBB = i->getCaseSuccessor();
    }
    else
    {
      thenBB = i->getCaseSuccessor();
    }
  }
  assert(thenBB != NULL && elseBB != NULL && "thenBB and elseBB are assigned.");
  BasicBlock *curBB = SI->getParent();
  Value *cond = SI->getCondition();
  BasicBlock *defaultDest = SI->getDefaultDest();
  for (auto &phi : defaultDest->phis())
  {
    int idx = phi.getBasicBlockIndex(curBB);
    if (idx != -1)
    {
      phi.removeIncomingValue(idx);
    }
  }
  // SI->removeFromParent();
  curBB->getInstList().erase(SI);
  BranchInst::Create(thenBB, elseBB, cond, curBB);

}
/* switchConvert - Transform simple list of Cases into list of CaseRange's */
static BasicBlock *switchConvert(CaseVector Cases, std::vector<bool> bytesChecked,
                                 BasicBlock *OrigBlock, BasicBlock *NewDefault,
                                 Value *Val, unsigned level)
{

  unsigned ValTypeBitWidth = Cases[0].Val->getBitWidth();
  IntegerType *ValType = IntegerType::get(OrigBlock->getContext(), ValTypeBitWidth);
  IntegerType *ByteType = IntegerType::get(OrigBlock->getContext(), 8);
  unsigned BytesInValue = bytesChecked.size();
  std::vector<uint8_t> setSizes;
  std::vector<std::set<uint8_t>> byteSets(BytesInValue, std::set<uint8_t>());

  /* for each of the possible cases we iterate over all bytes of the values
   * build a set of possible values at each byte position in byteSets */
  for (CaseExpr &Case : Cases)
  {
    for (unsigned i = 0; i < BytesInValue; i++)
    {
      uint8_t byte = (Case.Val->getZExtValue() >> (i * 8)) & 0xFF;
      byteSets[i].insert(byte);
    }
  }

  unsigned smallestIndex = 0;
  unsigned smallestSize = 257;

  for (unsigned i = 0; i < byteSets.size(); i++)
  {
    if (bytesChecked[i])
      continue;
    if (byteSets[i].size() < smallestSize)
    {
      smallestIndex = i;
      smallestSize = byteSets[i].size();
    }
  }
  assert(bytesChecked[smallestIndex] == false);

  /* there are only smallestSize different bytes at index smallestIndex */

  Instruction *Shift, *Trunc;
  Function *F = OrigBlock->getParent();
  BasicBlock *NewNode = BasicBlock::Create(Val->getContext(), "NodeBlock", F);
  Shift = BinaryOperator::Create(Instruction::LShr, Val, ConstantInt::get(ValType, smallestIndex * 8));
  NewNode->getInstList().push_back(Shift);

  if (ValTypeBitWidth > 8)
  {
    Trunc = new TruncInst(Shift, ByteType);
    NewNode->getInstList().push_back(Trunc);
  }
  else
  {
    /* not necessary to trunc */
    Trunc = Shift;
  }

  /* this is a trivial case, we can directly check for the byte,
   * if the byte is not found go to default. if the byte was found
   * mark the byte as checked. if this was the last byte to check
   * we can finally execute the block belonging to this case */

  if (smallestSize == 1)
  {
    uint8_t byte = *(byteSets[smallestIndex].begin());

    /* insert instructions to check whether the value we are switching on is equal to byte */
    ICmpInst *Comp = new ICmpInst(ICmpInst::ICMP_EQ, Trunc, ConstantInt::get(ByteType, byte), "byteMatch");
    NewNode->getInstList().push_back(Comp);

    bytesChecked[smallestIndex] = true;
    if (std::all_of(bytesChecked.begin(), bytesChecked.end(), [](bool b)
                    { return b; }))
    {
      assert(Cases.size() == 1);
      BranchInst::Create(Cases[0].BB, NewDefault, Comp, NewNode);

      /* we have to update the phi nodes! */
      for (BasicBlock::iterator I = Cases[0].BB->begin(); I != Cases[0].BB->end(); ++I)
      {
        if (!isa<PHINode>(&*I))
        {
          continue;
        }
        PHINode *PN = cast<PHINode>(I);

        /* Only update the first occurence. */
        unsigned Idx = 0, E = PN->getNumIncomingValues();
        for (; Idx != E; ++Idx)
        {
          if (PN->getIncomingBlock(Idx) == OrigBlock)
          {
            PN->setIncomingBlock(Idx, NewNode);
            break;
          }
        }
      }
    }
    else
    {
      BasicBlock *BB = switchConvert(Cases, bytesChecked, OrigBlock, NewDefault, Val, level + 1);
      BranchInst::Create(BB, NewDefault, Comp, NewNode);
    }
  }
  /* there is no byte which we can directly check on, split the tree */
  else
  {

    std::vector<uint8_t> byteVector;
    std::copy(byteSets[smallestIndex].begin(), byteSets[smallestIndex].end(), std::back_inserter(byteVector));
    std::sort(byteVector.begin(), byteVector.end());
    uint8_t pivot = byteVector[byteVector.size() / 2];

    /* we already chose to divide the cases based on the value of byte at index smallestIndex
     * the pivot value determines the threshold for the decicion; if a case value
     * is smaller at this byte index move it to the LHS vector, otherwise to the RHS vector */

    CaseVector LHSCases, RHSCases;

    for (CaseExpr &Case : Cases)
    {
      uint8_t byte = (Case.Val->getZExtValue() >> (smallestIndex * 8)) & 0xFF;

      if (byte < pivot)
      {
        LHSCases.push_back(Case);
      }
      else
      {
        RHSCases.push_back(Case);
      }
    }
    BasicBlock *LBB, *RBB;
    LBB = switchConvert(LHSCases, bytesChecked, OrigBlock, NewDefault, Val, level + 1);
    RBB = switchConvert(RHSCases, bytesChecked, OrigBlock, NewDefault, Val, level + 1);

    /* insert instructions to check whether the value we are switching on is equal to byte */
    ICmpInst *Comp = new ICmpInst(ICmpInst::ICMP_ULT, Trunc, ConstantInt::get(ByteType, pivot), "byteMatch");
    NewNode->getInstList().push_back(Comp);
    BranchInst::Create(LBB, RBB, Comp, NewNode);
  }
  return NewNode;
}

static bool splitSwitches(Module &M)
{
  std::vector<SwitchInst *> switches;

  /* iterate over all functions, bbs and instruction and add
   * all switches to switches vector for later processing */
  for (auto &F : M)
  {
    if (isSanitizeFunc(&F))
      continue;

    for (auto &BB : F)
    {
      SwitchInst *switchInst = nullptr;
      if ((switchInst = dyn_cast<SwitchInst>(BB.getTerminator())))
      {
        if (isSanitizeInsn(switchInst))
          continue;

        if (switchInst->getNumCases() < 1)
          continue;
        switches.push_back(switchInst);
      }
    }
  }

  if (!switches.size())
    return false;
  errs() << "Rewriting " << switches.size() << " switch statements "
         << "\n";
  for (auto &SI : switches)
  {
    BasicBlock *CurBlock = SI->getParent();
    BasicBlock *OrigBlock = CurBlock;
    Function *F = CurBlock->getParent();
    /* this is the value we are switching on */
    Value *Val = SI->getCondition();
    BasicBlock *Default = SI->getDefaultDest();

    /* If there is only the default destination, don't bother with the code below. */
    if (!SI->getNumCases())
    {
      continue;
    }

    /* Prepare cases vector. */
    CaseVector Cases;
    for (SwitchInst::CaseIt i = SI->case_begin(), e = SI->case_end(); i != e; ++i)
      Cases.push_back(CaseExpr(i->getCaseValue(), i->getCaseSuccessor()));

    uint32_t bytewidth = (Cases[0].Val->getBitWidth()) >> 3;
    if (!bytewidth)
    {
      boolSwitch2br(SI);
      continue;
    }

    /* Create a new, empty default block so that the new hierarchy of
     * if-then statements go to this and the PHI nodes are happy.
     * if the default block is set as an unreachable we avoid creating one
     * because will never be a valid target.*/
    BasicBlock *NewDefault = nullptr;
    NewDefault = BasicBlock::Create(SI->getContext(), "NewDefault");
    NewDefault->insertInto(F, Default);
    BranchInst::Create(Default, NewDefault);


    std::vector<bool> bytesChecked(bytewidth, false);
    BasicBlock *SwitchBlock = switchConvert(Cases, bytesChecked, OrigBlock, NewDefault, Val, 0);


    /* Branch to our shiny new if-then stuff... */
    BranchInst::Create(SwitchBlock, OrigBlock);

    /* We are now done with the switch instruction, delete it. */
    CurBlock->getInstList().erase(SI);

    /* we have to update the phi nodes! */
    for (BasicBlock::iterator I = Default->begin(); I != Default->end(); ++I)
    {
      if (!isa<PHINode>(&*I))
      {
        continue;
      }
      PHINode *PN = cast<PHINode>(I);

      /* Only update the first occurence. */
      unsigned Idx = 0, E = PN->getNumIncomingValues();
      for (; Idx != E; ++Idx)
      {
        if (PN->getIncomingBlock(Idx) == OrigBlock)
        {
          PN->setIncomingBlock(Idx, NewDefault);
          break;
        }
      }
    }
  }

  verifyModule(M);
  return true;
}

static void split_switch(Module &M)
{
  llvm::errs() << "Running split-switches-pass, modified based on version of laf.intel@gmail.com\n";
  splitSwitches(M);
  verifyModule(M);

}

PreservedAnalyses SplitSwitchPass::run(Module &M, ModuleAnalysisManager &AM)
{
  split_switch(M);
  return PreservedAnalyses::none();
}
