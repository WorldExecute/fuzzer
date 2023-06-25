include_directories(./inc)

set( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -Wall --std=c++11 -O3 -fPIC" )
set( CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -Wall -O3 -fPIC" )

# forbid rtti, keep the same with llvm
set( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -fno-rtti" )


# Analysis Pass
add_llvm_library(
        NestedIfPass SHARED
        NestedIfAnalysis.cc
        NestedIf.cc
        utils.cc
)



#  Transformation Pass
add_llvm_library(
        BBRenamePass SHARED
        BasicBlockRenamePass.cc
)

add_llvm_library(
        SimplifyCFGPass SHARED
        SimpleSimplifyCFG.cc
        utils.cc
)

add_llvm_library(
        SplitSwitchesPass SHARED
        split-switches-pass.so.cc
        utils.cc
)

add_llvm_library(
        SplitComparesPass SHARED
        split-compares-pass.so.cc
        utils.cc
)

add_llvm_library(
        CompareTransformPass SHARED
        compare-transform-pass.so.cc
        utils.cc
)

# For afl-like coverage instrument
add_llvm_library(
        CovPass SHARED
        afl-llvm-pass.cc
)

# For source PUT
add_llvm_library(
        SourcePass SHARED
        SourcePass.cc
        utils.cc
)

# For phantom PUT
add_llvm_library(
        PhantomPass SHARED
        PhantomPass.cc
        utils.cc
)

# For DTA
add_llvm_library(
        SinkPass SHARED
        TaintSinkPass.cc
        utils.cc
)



add_definitions("-Wall -g")


install (TARGETS NestedIfPass               DESTINATION ${MIRAGE_PASS_DIR})
install (TARGETS BBRenamePass               DESTINATION ${MIRAGE_PASS_DIR})
install (TARGETS SimplifyCFGPass            DESTINATION ${MIRAGE_PASS_DIR})
install (TARGETS SplitSwitchesPass          DESTINATION ${MIRAGE_PASS_DIR})
install (TARGETS SplitComparesPass          DESTINATION ${MIRAGE_PASS_DIR})
install (TARGETS CompareTransformPass       DESTINATION ${MIRAGE_PASS_DIR})
install (TARGETS SourcePass                 DESTINATION ${MIRAGE_PASS_DIR})
install (TARGETS PhantomPass                DESTINATION ${MIRAGE_PASS_DIR})
install (TARGETS SinkPass                   DESTINATION ${MIRAGE_PASS_DIR})