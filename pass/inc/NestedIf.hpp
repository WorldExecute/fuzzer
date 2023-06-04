#pragma once

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
namespace llvm {

class NestedIfNode;

using u32 = uint32_t;

using BB2Cond = DenseMap<BasicBlock *, Value *>;
using NestedIfNodeList = SmallVector<NestedIfNode *, 4>;

class NestedIfNode {
  NestedIfNode *parent;
  NestedIfNode *root;
  /**
   * The calculation of predicate of current NI is dependent on the Ni.
   */
  NestedIfNode *hoistBorder;

  NestedIfNodeList ifThens;
  NestedIfNodeList ifElses;

  BasicBlock *bb;
  BasicBlock *entry;
  BranchInst *br;
  Instruction *cond;

  ConstantInt *brSrc;
  ConstantInt *thenEdge;
  ConstantInt *elseEdge;


  bool thenBranch;
  bool cmpSplit;

  SmallVector<Value *, 8> directDepVals;

  NestedIfNode(BasicBlock *bb, BranchInst *br, Instruction *cond);

  NestedIfNode(NestedIfNode *parent, NestedIfNode *root, BasicBlock *bb,
               BasicBlock *entry, BranchInst *br, Instruction *cond,
               bool isThen);

public:
  static NestedIfNode *createRootNode(BasicBlock *root);

  bool empty() { return ifElses.empty() && ifThens.empty(); }

  bool isRoot() { return parent == nullptr; }

  bool justOneChildBranch() { return ifElses.empty() ^ ifThens.empty(); }

  void extractDirectDepVals();

  void extractHoistedInsnDepVals(SmallPtrSetImpl<Value *> &set);

  NestedIfNode *getParent() const { return parent; }

  void setParent(NestedIfNode *parent) { NestedIfNode::parent = parent; }

  bool isCompareSplit() const;

  ConstantInt *getBrSrc() const;

  ConstantInt *getThenEdge() const;

  ConstantInt *getElseEdge() const;

  NestedIfNode *getHoistBorder() const;

  void setHoistBorder(NestedIfNode *hoistBorder);

  NestedIfNode *getRoot() const;

  BasicBlock *getBB() const { return bb; }

  void setBb(BasicBlock *bb) { NestedIfNode::bb = bb; }

  Instruction *getCond() const { return cond; }

  void setCond(Instruction *cond) { NestedIfNode::cond = cond; }

  BasicBlock *getEntry() const { return entry; }

  void setEntry(BasicBlock *entry) { NestedIfNode::entry = entry; }

  const NestedIfNodeList &getIfThens() const { return ifThens; }

  const NestedIfNodeList &getIfElses() const { return ifElses; }

  bool isThen() const { return thenBranch; }

  BranchInst *getBranchInsn() const;

  const SmallVector<Value *, 8> &getDirectDepVals() const;

  void addToThen(NestedIfNode *parent) { parent->ifThens.push_back(this); }

  void addToElse(NestedIfNode *parent) { parent->ifElses.push_back(this); }

  NestedIfNode *addIfThen(BasicBlock *bb) {
    BranchInst *br;
    if (!(br = dyn_cast<BranchInst>(bb->getTerminator()))) {
      return nullptr;
    }
    if (!br->isConditional()) {
      return nullptr;
    }
    Instruction *cond = dyn_cast<Instruction>(br->getCondition());
    if (!cond)
      return nullptr;
    BasicBlock *entry = this->br->getSuccessor(0);
    NestedIfNode *ni =
        new NestedIfNode(this, this->root, bb, entry, br, cond, true);
    this->ifThens.push_back(ni);
    return ni;
  }

  NestedIfNode *addIfElse(BasicBlock *bb) {
    BranchInst *br;
    if (!(br = dyn_cast<BranchInst>(bb->getTerminator()))) {
      return nullptr;
    }
    if (!br->isConditional()) {
      return nullptr;
    }
    Instruction *cond = dyn_cast<Instruction>(br->getCondition());
    if (!cond)
      return nullptr;
    BasicBlock *entry = this->br->getSuccessor(1);
    NestedIfNode *ni =
        new NestedIfNode(this, this->root, bb, entry, br, cond, false);
    this->ifElses.push_back(ni);
    return ni;
  }

  NestedIfNode *getNestedIfHead();

  virtual ~NestedIfNode();
};

/**
 * 嵌套If 的表示形式
 *
 * 约束：
 *      1. 嵌套if不得跨越 loop
 *      2. 嵌套if不得跨越LoopExiting
 *      3. 嵌套if需标标记含强依赖关系的边
 */
class NestedIf {
  NestedIfNode *root;

  void modifyCovInstArg(BasicBlock *curBB, Value *cond, bool isThen);

  void processCmpForTaintSink(CmpInst *Cmp, ConstantInt *thenEdge,
                              ConstantInt *elseEdge, Instruction *InsertPoint1,
                              Instruction *InsertPoint2);
  void processBoolCmpForTaintSink(Value *Cond, ConstantInt *thenEdge,
                                  ConstantInt *elseEdge,
                                  Instruction *InsertPoint,
                                  Instruction *InsertPoint2);

  void taintSinkForBranch(NestedIfNode *ni);

public:
  NestedIf(NestedIfNode *root);

  virtual ~NestedIf();

  virtual void markHoistBarrier();

  void doMutateIf();

  void doRootHoist();

  void doSinkInstr();

  NestedIfNode *getRoot() const;
};


std::vector<NestedIf *>  extractNestedIfs(DominatorTree *DT);

} // namespace llvm
