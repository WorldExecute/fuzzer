# forbid rtti, keep the same with llvm
set( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -fno-rtti" )

add_executable(
    mirage-ins
    MirageInstrumentor.cc
)


# Link all the pass.so to mirage-ins, the driver to invoke all the passes
target_link_libraries(mirage-ins 
    NestedIfPass
    BBRenamePass
    SimplifyCFGPass     
    SplitSwitchesPass   
    SplitComparesPass   
    CompareTransformPass
    SourcePass          
    PhantomPass         
    SinkPass   
    CovPass         
)

# If not complied into a library, we need to link the LLVM libraries
target_link_libraries(mirage-ins
    LLVMCore LLVMPasses LLVMIRReader LLVMSupport LLVMOption
)

install (TARGETS mirage-ins  DESTINATION ${MIRAGE_BIN_DIR})
