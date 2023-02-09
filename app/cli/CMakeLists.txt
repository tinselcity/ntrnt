# ------------------------------------------------------------------------------
# build is2 (optionally)
# ------------------------------------------------------------------------------
if(BUILD_IS2)
  set(LIBRARIES ${LIBRARIES} is2)
  add_definitions(-DENABLE_IS2)
endif()
# ------------------------------------------------------------------------------
# add install headers
# ------------------------------------------------------------------------------
LIST(APPEND INST_HDRS ${HDRS})
# ------------------------------------------------------------------------------
# include paths
# ------------------------------------------------------------------------------
include_directories(
    # ------------------------------------------------------
    # brew support
    # ------------------------------------------------------
    /usr/local/opt/openssl/include
    /usr/local/opt/miniupnpc/include
    /usr/local/opt/rapidjson/include
    /opt/homebrew/opt/openssl/include
    /opt/homebrew/opt/miniupnpc/include
    /opt/homebrew/opt/rapidjson/include
    # ------------------------------------------------------
    # project
    # ------------------------------------------------------
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}/ext
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/ext/farmhash
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
# brew hacking
target_link_directories(ntrnt_cmd PUBLIC
    /usr/local/opt/openssl/lib
    /usr/local/opt/miniupnpc/lib
    /opt/homebrew/opt/openssl/lib
    /opt/homebrew/opt/miniupnpc/lib
)
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
