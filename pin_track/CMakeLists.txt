
add_custom_command(OUTPUT ${CMAKE_BINARY_DIR}/pin_track.so
    POST_BUILD
    COMMAND make -C ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND ln -s ${CMAKE_CURRENT_SOURCE_DIR}/obj-intel64/pin_track.so ${CMAKE_BINARY_DIR}/pin_track.so
)

add_custom_target(PIN_TRACK ALL DEPENDS ${CMAKE_BINARY_DIR}/pin_track.so)

install (FILES ${CMAKE_BINARY_DIR}/pin_track.so DESTINATION ${MIRAGE_BIN_DIR})
