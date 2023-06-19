include_directories(./inc)

set( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -Wall --std=c++11 -O3 -fPIC" )
set( CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -Wall -O3 -fPIC" )

add_library(TRANSFORM STATIC
        compare-transform-pass.so.cc
        split-switches-pass.so.cc
        split-compares-pass.so.cc
        SimpleSimplifyCFG.cc
        utils.cc
        )

add_library(
    IntegratedCovPhantom MODULE
        IntegratedCovPhantom.cpp
)
target_link_libraries(IntegratedCovPhantom TRANSFORM)
set_target_properties(IntegratedCovPhantom PROPERTIES OUTPUT_NAME "IntegPass")



# Use C++11 to compile our pass (i.e., supply -std=c++11).
target_compile_features(IntegratedCovPhantom PRIVATE cxx_range_for cxx_auto_type)


# LLVM is (typically) built with no C++ RTTI. We need to match that;
# otherwise, we'll get linker errors about missing RTTI data.
set_target_properties(IntegratedCovPhantom PROPERTIES
        COMPILE_FLAGS "-fno-rtti"
        )

# Get proper shared-library behavior (where symbols are not necessarily
# resolved when the shared library is linked) on OS X.
#include_directories(/usr/include/llvm-10/llvm)

if(APPLE)
    set_target_properties(IntegratedCovPhantom PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
            )
endif(APPLE)

add_definitions("-Wall -g")


install (TARGETS IntegratedCovPhantom DESTINATION ${MIRAGE_PASS_DIR})