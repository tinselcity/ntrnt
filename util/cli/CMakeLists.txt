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
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
# ------------------------------------------------------------------------------
# sources
# ------------------------------------------------------------------------------
SET(SRCS
    cli.cc
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
add_executable(ntrnt_cmd ${HDRS} ${SRCS})
add_dependencies(ntrnt_cmd ntrnt)
SET_TARGET_PROPERTIES(ntrnt_cmd PROPERTIES OUTPUT_NAME "ntrnt")
target_link_libraries(ntrnt_cmd
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
install(TARGETS ntrnt
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin/
    COMPONENT Executables
)
