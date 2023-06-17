
# Get the relative path from the bin dir to the current src dir
file(RELATIVE_PATH RELATIVE_PATH_TO_SOURCE ${CMAKE_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR} )
message(STATUS "source dir: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "binary dir: ${CMAKE_BINARY_DIR}")
message(STATUS "Relative path to source: ${RELATIVE_PATH_TO_SOURCE}")

add_custom_command(OUTPUT ${CMAKE_BINARY_DIR}/pin_track.so
    POST_BUILD
    COMMAND env CC=gcc CXX=g++ make -C ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND ln -s ${RELATIVE_PATH_TO_SOURCE}/obj-intel64/pin_track.so ${CMAKE_BINARY_DIR}/pin_track.so
)

add_custom_target(PIN_TRACK ALL DEPENDS ${CMAKE_BINARY_DIR}/pin_track.so)

install (FILES ${CMAKE_BINARY_DIR}/pin_track.so DESTINATION ${MIRAGE_BIN_DIR})
