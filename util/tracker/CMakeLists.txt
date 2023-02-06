# ------------------------------------------------------------------------------
# add install headers
# ------------------------------------------------------------------------------
LIST(APPEND INST_HDRS ${HDRS})
# ------------------------------------------------------------------------------
# include paths
# ------------------------------------------------------------------------------
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}/ext
    ${CMAKE_SOURCE_DIR}/ext/farmhash
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
# ------------------------------------------------------------------------------
# sources
# ------------------------------------------------------------------------------
SET(SRCS
    tracker.cc
)
# ------------------------------------------------------------------------------
# headers
# ------------------------------------------------------------------------------
SET(HDRS)
# ------------------------------------------------------------------------------
# flags
# ------------------------------------------------------------------------------
set(CMAKE_C_FLAGS "-std=c99")
set(CMAKE_CXX_FLAGS "-std=c++11")
# ------------------------------------------------------------------------------
# exe
# ------------------------------------------------------------------------------
add_executable(tracker_cmd ${HDRS} ${SRCS})
add_dependencies(tracker_cmd ntrnt)
SET_TARGET_PROPERTIES(tracker_cmd PROPERTIES OUTPUT_NAME "tracker")
target_link_libraries(tracker_cmd
    ${DEBUG_LIBRARIES}
    ${CMAKE_BINARY_DIR}/src/libntrntcore.a
    ${LIBRARIES}
    # TODO make configurable
    ssl
    crypto
)
# ------------------------------------------------------------------------------
# install
# ------------------------------------------------------------------------------
install(TARGETS tracker_cmd
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin/
    COMPONENT Executables
)
