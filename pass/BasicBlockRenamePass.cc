#include "Pass.h"
#include "debug.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IntrinsicInst.h"
#include <llvm/Support/raw_ostream.h>
#include <string>

#define INLINE_SIGN "@"
#define DUP_SIGN "_"

// TODO: too many bb without name in jhead!

namespace llvm {

static inline bool isBlacklisted(const Function *F) {
  static const SmallVector<std::string, 8> Blacklist = {
      "asan.", "llvm.",  "sancov.", "__ubsan_handle_",
      "free",  "malloc", "calloc",  "realloc"};

  for (auto const &BlacklistFunc : Blacklist) {
    if (F->getName().startswith(BlacklistFunc)) {
      return true;
    }
  }

  return false;
}

static void getDebugLoc(const Instruction *I, std::string &Filename,
                        unsigned &Line, std::string &inlinedFile,
                        unsigned &inlinedAt) {
#ifdef LLVM_OLD_DEBUG_API
  DebugLoc Loc = I->getDebugLoc();
  if (!Loc.isUnknown()) {
    llvm::DILocation cDILoc(Loc.getAsMDNode(M.getContext()));
    llvm::DILocation oDILoc = cDILoc.getOrigLocation();

    Line = oDILoc.getLineNumber();
    Filename = oDILoc.getFilename().str();

    if (filename.empty()) {
      Line = cDILoc.getLineNumber();
      Filename = cDILoc.getFilename().str();
    }
  }
#else
  if (llvm::DILocation *Loc = I->getDebugLoc()) {
    Line = Loc->getLine();
    Filename = Loc->getFilename().str();

    if (Filename.empty()) {
      llvm::DILocation *oDILoc = Loc->getInlinedAt();
      if (oDILoc) {
        Line = oDILoc->getLine();
        Filename = oDILoc->getFilename().str();
      }
    } else {
      // If Loc is inlined
      llvm::DILocation *oDILoc = Loc->getInlinedAt();
      if (oDILoc) {
        inlinedAt = oDILoc->getLine();
        auto fn = oDILoc->getFilename().str();
        if (Filename != fn) {
          inlinedFile = fn;
        }
      }
    }

    // todo: some bugs might be caused by this. make clear of inline and
    // optimization. Line = 0, caused by optimization. Use DILocalVariable to
    // get the line number. eg: the metadata `!16` in `call void
    // @llvm.dbg.value(metadata i32 %0, metadata !16, metadata
    // !DIExpression())`

    if (Line == 0 && I->isDebugOrPseudoInst()) {
      if (auto *MD = dyn_cast<llvm::DbgValueInst>(I)) {
        if (auto *Var = dyn_cast<llvm::DILocalVariable>(MD->getVariable())) {
          Line = Var->getLine();
          Filename = Var->getFilename().str();
        }
      }
    }
  }
#endif /* LLVM_OLD_DEBUG_API */
}

static bool getDbgLocation(std::string &loc, const Instruction *I,
                      bool worryAboutExternalLibs = false) {
  std::string filename, inlinedFile;
  unsigned line = 0, inlinedAt = 0;
  getDebugLoc(I, filename, line, inlinedFile, inlinedAt);

  /* Don't worry about external libs */
  static const std::string Xlibs("/usr/");
  if (filename.empty() || line == 0 ||
      (worryAboutExternalLibs && !filename.compare(0, Xlibs.size(), Xlibs)))
    return false;

  std::size_t found = filename.find_last_of("/\\");
  if (found != std::string::npos)
    filename = filename.substr(found + 1);
  loc = filename + ":" + std::to_string(line);
  if (inlinedAt != 0) {
    if (!inlinedFile.empty())
      loc += INLINE_SIGN + inlinedFile + ":" + std::to_string(inlinedAt);
    else
      loc += INLINE_SIGN + std::to_string(inlinedAt);
  }
  return true;
}

static void updateBBName(std::string &bb_name) {
  static llvm::StringMap<unsigned> dup_bbname_cnt;
  if (dup_bbname_cnt.find(bb_name) == dup_bbname_cnt.end()) {
    dup_bbname_cnt[bb_name] = 0;
  } else {
    dup_bbname_cnt[bb_name] += 1;
    bb_name += DUP_SIGN + std::to_string(dup_bbname_cnt[bb_name]);
  }
}



[[maybe_unused]]
static void setNameForBB(BasicBlock *bb, std::string name) {
    bb->setName(name);
    if (!bb->hasName()) {

      std::string newname = name;
      Twine t(newname);
      SmallString<256> NameData;
      StringRef NameRef = t.toStringRef(NameData);
      MallocAllocator Allocator;
      bb->setValueName(ValueName::Create(NameRef, Allocator));
    }
}

PreservedAnalyses BasicBlockRenamePass::run(Module &M, ModuleAnalysisManager &MAM) {
  // renameBasicBlock(&M);

  
  SAYF(cCYA "rename-basicblock-pass (yeah!) " cBRI VERSION 
      cRST ": BB name with such format (filename:line)\n"
  );

  for (auto &F : M) {
    if (F.isDeclaration())
      continue;
    std::string funcName = F.getName().str();

    /* Black list of function names */
    if (isBlacklisted(&F)) {
      continue;
    }

    for (auto &BB : F) {

      std::string bb_name(""), available_bb_name("");

      for (auto &I : BB) {
        // One BB may have multiple lines, i.e., multiple names
        if (!getDbgLocation(available_bb_name, &I, true))
          continue;
        // The first available BB name is the one we use
        if (bb_name.empty() 
            && !available_bb_name.empty() 
            // the debug info of optimizated instructions 
            // is not suitable as bb name
            && !I.isDebugOrPseudoInst()) {
          bb_name = available_bb_name;
          updateBBName(bb_name);
          setNameForBB(&BB, bb_name);
          // BB.setName(bb_name);
          break;
        }

      }
    }
  }
  return PreservedAnalyses::all();
}

}