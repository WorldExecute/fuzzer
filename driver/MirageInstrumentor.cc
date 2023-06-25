/*
  An entrypoint to do instrumentation and transformation.
 
  Author: Kunqiu Chen
 */

#include "Pass.h"

#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/Transforms/IPO/InferFunctionAttrs.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar/EarlyCSE.h>
#include <llvm/Transforms/Scalar/LICM.h>
#include <llvm/Transforms/Utils/Mem2Reg.h>
#include <cstddef>
#include <cstdlib>
#include <functional>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/raw_ostream.h>
#include <string>

#include <llvm/IR/PassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Transforms/Utils/UnifyFunctionExitNodes.h>
#include <llvm/Transforms/Scalar/SimplifyCFG.h>
#include <llvm/IRReader/IRReader.h>
#include <utility>
#include <vector>
// #include <header>

namespace llvm {

static cl::opt<bool> NoLaf("nolaf", cl::ZeroOrMore,
                               cl::desc("No LafIntel Mode. Default: false"),
                               cl::value_desc("nolaf"), cl::init(false));

static cl::opt<bool> NoCov("nocov", cl::ZeroOrMore,
                                cl::desc("No Coverage Instrumentation. Default: false"),
                                cl::value_desc("nocov"), cl::init(false));

static cl::opt<bool> NoSource("nosource", cl::ZeroOrMore,
                                cl::desc("No Source Instrumentation. Default: false"),
                                cl::value_desc("nosource"), cl::init(false));

static cl::opt<bool> NoTaint("notaint", cl::ZeroOrMore,
                                cl::desc("No Taint Instrumentation. Default: false"),
                                cl::value_desc("notaint"), cl::init(false));

static cl::opt<bool> NoPhantom("nophantom", cl::ZeroOrMore,
                                cl::desc("No Phantom Instrumentation. Default: false"),
                                cl::value_desc("nophantom"), cl::init(false));

static llvm::cl::opt<std::string> InputFilename(llvm::cl::Positional,
        llvm::cl::desc("<input bitcode>"), llvm::cl::init("-"));
// static cl::opt<std::string>
//     OutDirectory("outdir", cl::ZeroOrMore,
//                  cl::desc("Output directory where Ftargets.txt, Fnames.txt, "
//                           "and BBnames.txt are generated."),
//                  cl::value_desc("outdir"), cl::init(""));

// static cl::opt<bool> ReduceICFG("reduce", cl::ZeroOrMore,
//                                 cl::desc("Enable SimpleICFG reduction."),
//                                 cl::value_desc("reduce"), cl::init(false));

// static cl::opt<bool> AFLGo("aflgo", cl::ZeroOrMore,
//                            cl::desc("Do AFLGo preprocessing."),
//                            cl::value_desc("aflgo"), cl::init(false));

// static cl::opt<std::string>
//     InputFilename(cl::Positional, cl::desc("<input bitcode>"), cl::init("-"));
} // namespace llvm

using namespace llvm;

static void writeLLVMModuleToFile(llvm::Module &M, std::string suffix) {
        std::string moduleName = M.getName().str();
        std::string OutputFilename;
        std::size_t pos = moduleName.rfind('.');
        if (pos != std::string::npos)
            OutputFilename = moduleName.substr(0, pos) + suffix;
        else
            OutputFilename = moduleName + suffix;

        std::error_code EC;
        llvm::raw_fd_ostream OS(OutputFilename.c_str(), EC, llvm::sys::fs::OF_None);
        
#if (LLVM_VERSION_MAJOR >= 7)
        WriteBitcodeToFile(M, OS);
#else
        WriteBitcodeToFile(&M, OS);
#endif


}


static inline __pid_t emitChildPipeline(llvm::ModulePassManager &MPM, 
                      llvm::ModuleAnalysisManager &MAM,
                      llvm::Module &M,
                      const char *suffix,
                      bool use_fork = true) {
  __pid_t pid = -1;
  if (use_fork) {
    pid = fork();
  }
  
  if (!use_fork || pid == 0) {
    // Child process
    MPM.run(M, MAM);
    llvm::verifyModule(M, &llvm::errs());
    writeLLVMModuleToFile(M, suffix);

    if (use_fork) {
      exit(0);
    }
  } 


  return pid;
}

static __pid_t instrumentTaint(llvm::ModuleAnalysisManager &MAM,
                              llvm::Module &M,
                              bool use_fork) {
  // Parent process
  llvm::ModulePassManager MPM;

  // TaintSink Pass
  llvm::errs() << "Running TaintSink Pass\n";
  MPM.addPass(llvm::TaintSinkPass());

  auto pid = emitChildPipeline(MPM, MAM, M, ".taint.bc", use_fork);
  llvm::errs() << "Taint Sink Pass finished\n";

  return pid;
}

static __pid_t instrumentSource(llvm::ModuleAnalysisManager &MAM,
                              llvm::Module &M,
                              bool use_fork) {
  // Parent process
  llvm::ModulePassManager MPM;

  // SourceSink Pass
  llvm::errs() << "Running Source Pass\n";
  MPM.addPass(llvm::SourcePass());
  if (!NoCov) {
    MPM.addPass(AFLCoveragePass());
  }

  auto pid = emitChildPipeline(MPM, MAM, M, ".source.bc", use_fork);
  llvm::errs() << "Source Sink Pass finished\n";

  return pid;
}

static __pid_t instrumentPhantom(llvm::ModuleAnalysisManager &MAM,
                              llvm::Module &M,
                              bool use_fork) {
  // Parent process
  llvm::ModulePassManager MPM;

  // PhantomPass
  llvm::errs() << "Running Phantom Pass\n";
  MPM.addPass(llvm::PhantomPass());
  if (!NoCov) {
    MPM.addPass(AFLCoveragePass());
  }

  auto pid = emitChildPipeline(MPM, MAM, M, ".phantom.bc", use_fork);
  llvm::errs() << "Phantom Pass finished\n";

  return pid;
}

using InstrFunc = std::function<__pid_t(llvm::ModuleAnalysisManager &MAM,
                                        llvm::Module &M,
                                        bool use_fork)>;

int main(int argc, char **argv) {
  cl::ParseCommandLineOptions(argc, argv);

  // SVFModule *svfModule =
  //     LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(moduleNameVec);

  // svfModule->buildSymbolTableInfo();
  LLVMContext C;
  SMDiagnostic Err;
  std::unique_ptr<Module> mod = parseIRFile(InputFilename, Err, C);


  llvm::PassBuilder PB;

  // Create the analysis managers.
  llvm::LoopAnalysisManager LAM;
  llvm::FunctionAnalysisManager FAM;
  llvm::CGSCCAnalysisManager CGAM;
  llvm::ModuleAnalysisManager MAM;

  // Register all the basic analyses with the managers.
  PB.registerModuleAnalyses(MAM);
  PB.registerCGSCCAnalyses(CGAM);
  PB.registerFunctionAnalyses(FAM);
  PB.registerLoopAnalyses(LAM);
  PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

  llvm::ModulePassManager MPM;
  llvm::FunctionPassManager FPM;

  // MPM.addPass(createModuleToFunctionPassAdaptor(llvm::SimplifyCFGPass()));
  FPM.addPass(PromotePass());
  // Let splitCmp Pass identify the constant value
  FPM.addPass(InstCombinePass(true));
  FPM.addPass(EarlyCSEPass(true));
  FPM.addPass(createFunctionToLoopPassAdaptor(LICMPass(), true));
  llvm::errs() << "Running simple-simplify-CFG-passe\n";
  // FPM.addPass(SimpleSimplifyCFGPass());

  MPM.addPass(BasicBlockRenamePass());
  MPM.addPass(InferFunctionAttrsPass());
  MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
  FPM.addPass(llvm::SimpleSimplifyCFGPass());
  if (!NoLaf) {
      MPM.addPass(SplitNByteCmpPass());
      MPM.addPass(SplitFuncCmpPass());
      MPM.addPass(SplitSwitchPass());
  }
  MPM.addPass(createModuleToFunctionPassAdaptor(PromotePass()));

  
  // Trigger NestedIf extractor in advance
  MPM.addPass(RequireAnalysisPass<NestedIfAnalysis, Module>());

  MAM.registerPass([] { return NestedIfAnalysis(); });

  MPM.run(*mod, MAM);

  writeLLVMModuleToFile(*mod, ".raw.bc");

  // Forks 3 processes to share the analysis and do the following:
  //  1. Phantom Pass
  //  2. AFLSource Pass
  //  3. TaintSink Pass

  std::vector<std::pair<InstrFunc, const char *>> instrumentations;
  if (!NoSource) {
    instrumentations.push_back({instrumentSource, "Source Pass"});
  }

  if (!NoPhantom) {
    instrumentations.push_back({instrumentPhantom, "Phantom Pass"});
  }

  if (!NoTaint) {
    instrumentations.push_back({instrumentTaint, "Taint Pass"});
  }

  if (instrumentations.empty()) {
    llvm::errs() << "No instrumentation is enabled\n";
    return 0;
  }

  std::vector<std::pair<__pid_t, const char *>> childToWait;
  // pop the final one
  auto [lastInstr, lastInstrName] = instrumentations.back();
  instrumentations.pop_back();

  for (auto [instr, instrName] : instrumentations) {
    auto pid = instr(MAM, *mod, true);
    childToWait.push_back({pid, instrName});
  }

  lastInstr(MAM, *mod, false);

  for (auto [pid, instrName] : childToWait) {
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
      llvm::errs() << instrName << " failed\n";
      return 1;
    } else {
      llvm::errs() << instrName << " finished\n";
    }
  }

  return 0;
}

