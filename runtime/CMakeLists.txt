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
# set_target_properties(DTA_RT PROPERTIES OUTPUT_NAME "dta-rt_tmp")
# target_link_libraries(DTA_RT udis86)
set_target_properties(DTA_RT PROPERTIES OUTPUT_NAME "dta-rt")

# if (APPLE)
#     add_custom_command(TARGET DTA_RT POST_BUILD
#             COMMAND libtool -static -o ${CMAKE_CURRENT_BINARY_DIR}/libdta-rt.a $<TARGET_FILE:DTA_RT> ${CMAKE_CURRENT_SOURCE_DIR}/libudis86.a)

# else()
#     add_custom_command(TARGET DTA_RT POST_BUILD
#         COMMAND ar crsT ${CMAKE_CURRENT_BINARY_DIR}/libdta-rt.a $<TARGET_FILE:DTA_RT> ${CMAKE_CURRENT_SOURCE_DIR}/libudis86.a )
# endif()


add_library(
    PHANTOM_RT STATIC
    phantom-rt.o.c
)

# target_link_libraries(PHANTOM_RT udis86)
set_target_properties(PHANTOM_RT PROPERTIES OUTPUT_NAME "phantom-rt")
# set_target_properties(PHANTOM_RT PROPERTIES OUTPUT_NAME "tmp-rt")
# set_target_properties(PHANTOM_RT PROPERTIES OUTPUT_NAME "phantom-rt-tmp")



# if (APPLE)
#     add_custom_command(TARGET PHANTOM_RT POST_BUILD
#             COMMAND libtool -static -o ${CMAKE_CURRENT_BINARY_DIR}/libphantom-rt.a $<TARGET_FILE:PHANTOM_RT> ${CMAKE_CURRENT_SOURCE_DIR}/libudis86.a)
# #    add_custom_command(OUTPUT libphantom-rt.a
# #            COMMAND libtool -static -o ${CMAKE_CURRENT_BINARY_DIR}/libphantom-rt.a $<TARGET_FILE:PHANTOM_RT> ${CMAKE_CURRENT_SOURCE_DIR}/libudis86.a
# #            DEPENDS PHANTOM_RT)
# else()
#     add_custom_command(TARGET PHANTOM_RT POST_BUILD
#         COMMAND ar crsT ${CMAKE_CURRENT_BINARY_DIR}/libphantom-rt.a $<TARGET_FILE:PHANTOM_RT> ${CMAKE_CURRENT_SOURCE_DIR}/libudis86.a )
# # add_custom_command(OUTPUT libphantom-rt.a
# #            COMMAND ar crsT ${CMAKE_CURRENT_BINARY_DIR}/libphantom-rt.a $<TARGET_FILE:PHANTOM_RT> ${CMAKE_CURRENT_SOURCE_DIR}/libudis86.a
# #            DEPENDS PHANTOM_RT)
# endif()
# add_custom_target(phantom_merge ALL DEPENDS libphantom-rt.a)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

install (TARGETS AFL_RT DESTINATION ${MIRAGE_LIB_DIR})
install (TARGETS SOURCE_RT DESTINATION ${MIRAGE_LIB_DIR})
install (TARGETS DTA_RT DESTINATION ${MIRAGE_LIB_DIR})
install (TARGETS PHANTOM_RT DESTINATION ${MIRAGE_LIB_DIR})