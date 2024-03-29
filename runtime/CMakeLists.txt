add_library(
    AFL_RT STATIC
    afl-llvm-rt.o.c
)
set_target_properties(AFL_RT PROPERTIES OUTPUT_NAME "afl-rt")

add_library(
    SOURCE_RT STATIC
    source-rt.o.c
)
set_target_properties(SOURCE_RT PROPERTIES OUTPUT_NAME "source-rt")

add_library(
    DTA_RT STATIC
    dta-rt.c
)
set_target_properties(DTA_RT PROPERTIES OUTPUT_NAME "dta-rt")



add_library(
    PHANTOM_RT STATIC
    phantom-rt.o.c
)
set_target_properties(PHANTOM_RT PROPERTIES OUTPUT_NAME "phantom-rt")

add_library(
    Driver STATIC
    afl_driver.cpp
)


add_library(
    AFL STATIC
    afl_driver.cpp
    afl-llvm-rt.o.c
)

add_library(
    Source STATIC
    afl_driver.cpp
    source-rt.o.c
)

add_library(
    Phantom STATIC
    afl_driver.cpp
    phantom-rt.o.c
)

add_library(
    DTA STATIC
    dta_driver.cpp
    dta-rt.c
)

# Use libc++ instead of libstdc++ for drivers
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # compile
    set_target_properties(AFL     PROPERTIES COMPILE_FLAGS "-stdlib=libc++")
    set_target_properties(Source  PROPERTIES COMPILE_FLAGS "-stdlib=libc++")
    set_target_properties(Phantom PROPERTIES COMPILE_FLAGS "-stdlib=libc++")
    set_target_properties(DTA     PROPERTIES COMPILE_FLAGS "-stdlib=libc++") 

    # link
    set_target_properties(AFL     PROPERTIES LINK_FLAGS "-stdlib=libc++")
    set_target_properties(Source  PROPERTIES LINK_FLAGS "-stdlib=libc++")
    set_target_properties(Phantom PROPERTIES LINK_FLAGS "-stdlib=libc++")
    set_target_properties(DTA     PROPERTIES LINK_FLAGS "-stdlib=libc++")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -Wno-pointer-sign")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -Wno-pointer-sign")

install (TARGETS AFL_RT      DESTINATION ${MIRAGE_LIB_DIR})
install (TARGETS SOURCE_RT   DESTINATION ${MIRAGE_LIB_DIR})
install (TARGETS DTA_RT      DESTINATION ${MIRAGE_LIB_DIR})
install (TARGETS PHANTOM_RT  DESTINATION ${MIRAGE_LIB_DIR})
install (TARGETS AFL         DESTINATION ${MIRAGE_LIB_DIR})
install (TARGETS Source      DESTINATION ${MIRAGE_LIB_DIR})
install (TARGETS DTA         DESTINATION ${MIRAGE_LIB_DIR})
install (TARGETS Phantom     DESTINATION ${MIRAGE_LIB_DIR})
