add_executable(
    MirageClang
    mirage_clang.c
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-pointer-sign")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-pointer-sign")

set_target_properties(MirageClang PROPERTIES OUTPUT_NAME "mirage-clang")

add_custom_command(TARGET MirageClang POST_BUILD
        COMMAND ln -sf "mirage-clang" "mirage-clang++")

install (TARGETS MirageClang DESTINATION ${MIRAGE_BIN_DIR})
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/mirage-clang++ DESTINATION ${MIRAGE_BIN_DIR})
