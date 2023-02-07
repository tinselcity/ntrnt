# ------------------------------------------------------------------------------
# Fortify Options
# ------------------------------------------------------------------------------
if (FORTIFY)
    add_definitions(-D_FORTIFY_SOURCE=2 -O1 -Wl,-z,relro,-z,now)
endif()
if(DEBUG_MODE)
    add_definitions(-O0 -g3)
else()
    add_definitions(-O2)
endif()
if(BUILD_SYMBOLS)
    add_definitions(-g3)
endif()
add_definitions(-DHAVE_CONFIG_H)
# ------------------------------------------------------------------------------
# flags
# ------------------------------------------------------------------------------
set(CMAKE_C_FLAGS "-std=c99")
#set(CMAKE_CXX_FLAGS "-Wall -Weffc++ -Werror -std=c++11")
# ------------------------------------------------------------------------------
# header files to install
# ------------------------------------------------------------------------------
LIST(APPEND INST_HDRS ${HDRS})
# ------------------------------------------------------------------------------
# include paths
# ------------------------------------------------------------------------------
include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}
    # ------------------------------------------------------
    # brew support
    # ------------------------------------------------------
    /opt/homebrew/opt/openssl/include
    /opt/homebrew/opt/miniupnpc/include
    # ------------------------------------------------------
    # sub
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/sub
    ${CMAKE_SOURCE_DIR}/sub/libutp
    # ------------------------------------------------------
    # ntrnt include
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    # ------------------------------------------------------
    # ext
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext
    ${CMAKE_SOURCE_DIR}/ext/uri
    ${CMAKE_SOURCE_DIR}/ext/farmhash
    ${CMAKE_SOURCE_DIR}/ext/libmaxminddb/src
)
# ------------------------------------------------------------------------------
# libutp source files
# ------------------------------------------------------------------------------
SET(LIBUTP_SRCS
    # ------------------------------------------------------
    # libutp
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/sub/libutp/utp_internal.cpp
    ${CMAKE_SOURCE_DIR}/sub/libutp/utp_utils.cpp
    ${CMAKE_SOURCE_DIR}/sub/libutp/utp_hash.cpp
    ${CMAKE_SOURCE_DIR}/sub/libutp/utp_callbacks.cpp
    ${CMAKE_SOURCE_DIR}/sub/libutp/utp_api.cpp
    ${CMAKE_SOURCE_DIR}/sub/libutp/utp_packedsockaddr.cpp
)
#set_source_files_properties(${LIBUTP_SRCS} PROPERTIES COMPILE_FLAGS "-DUTP_DEBUG_LOGGING -DPOSIX -Wall -fno-exceptions")
set_source_files_properties(${LIBUTP_SRCS} PROPERTIES COMPILE_FLAGS "-DPOSIX -Wall -fno-exceptions")
# ------------------------------------------------------------------------------
# libutp source files
# ------------------------------------------------------------------------------
SET(LIBMAXMIND_SRCS
    # ------------------------------------------------------
    # libutp
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/libmaxminddb/src/data-pool.c
    ${CMAKE_SOURCE_DIR}/ext/libmaxminddb/src/maxminddb.c
)
set_source_files_properties(${LIBMAXMIND_SRCS} PROPERTIES COMPILE_FLAGS "-O2 -ggdb -DPOSIX -Wall -Werror")
# ------------------------------------------------------------------------------
# source files
# ------------------------------------------------------------------------------
SET(SRCS
    # ------------------------------------------------------
    # farmhash
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/farmhash/farmhash.cc
    # ------------------------------------------------------
    # base64
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/base64/base64.cc
    # ------------------------------------------------------
    # hostcheck
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/hostcheck/hostcheck.cc
    # ------------------------------------------------------
    # http-parse
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/http_parser/http_parser.cc
    # ------------------------------------------------------
    # support
    # ------------------------------------------------------
    support/ndebug.cc
    support/trace.cc
    support/util.cc
    support/nbq.cc
    support/time_util.cc
    support/tls_util.cc
    support/net_util.cc
    support/string_util.cc
    support/btfield.cc
    support/geoip2_mmdb.cc
    support/peer_id.cc
    # ------------------------------------------------------
    # evr
    # ------------------------------------------------------
    evr/evr.cc
    evr/evr_select.cc
    # ------------------------------------------------------
    # nconn
    # ------------------------------------------------------
    conn/host_info.cc
    conn/nconn.cc
    conn/nconn_tcp.cc
    conn/nconn_tls.cc
    conn/scheme.cc
    # ------------------------------------------------------
    # lan
    # ------------------------------------------------------
    lan/upnp.cc
    # ------------------------------------------------------
    # dns
    # ------------------------------------------------------
    dns/ai_cache.cc
    dns/nlookup.cc
    dns/nresolver.cc
    # ------------------------------------------------------
    # http
    # ------------------------------------------------------
    http/http_cb.cc
    http/http_msg.cc
    http/http_resp.cc
    # ------------------------------------------------------
    # dht
    # ------------------------------------------------------
    dht/dhsco.cc
    # ------------------------------------------------------
    # bencode
    # ------------------------------------------------------
    bencode/bencode.cc
    # ------------------------------------------------------
    # tracker
    # ------------------------------------------------------
    core/stub.cc
    core/tracker.cc
    core/tracker_tcp.cc
    core/tracker_udp.cc
    core/phe.cc
    core/peer.cc
    core/peer_mgr.cc
    core/info_pickr.cc
    core/pickr.cc
    core/ntrnt.cc
    core/dht_mgr.cc
    core/session.cc
    core/api.cc
)
set_source_files_properties(${SRCS} PROPERTIES COMPILE_FLAGS "-std=c++11")
# ------------------------------------------------------------------------------
# Linux Specific
# ------------------------------------------------------------------------------
IF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    # Linux specific code
    SET(OperatingSystem "Linux")
    set (SRCS ${SRCS} ./evr/evr_epoll.cc)
ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
# ------------------------------------------------------------------------------
# c source
# ------------------------------------------------------------------------------
SET_SOURCE_FILES_PROPERTIES(
    # ------------------------------------------------------
    # libmaxminddb
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/libmaxminddb/src/data-pool.c
    ${CMAKE_SOURCE_DIR}/ext/libmaxminddb/src/maxminddb.c
    # ------------------------------------------------------
    # udns
    # ------------------------------------------------------
    ${UDNS_SRCS}
    # ------------------------------------------------------
    # properties
    # ------------------------------------------------------
    PROPERTIES LANGUAGE C
)
# ------------------------------------------------------------------------------
# headers
# ------------------------------------------------------------------------------
SET(HDRS
)
# ------------------------------------------------------------------------------
# library
# ------------------------------------------------------------------------------
add_library(ntrnt_obj OBJECT ${LIBUTP_SRCS} ${LIBMAXMIND_SRCS} ${SRCS})
# ------------------------------------------------------------------------------
# properties
# ------------------------------------------------------------------------------
set(CMAKE_C_FLAGS "-std=c99")
add_library(ntrntcore STATIC $<TARGET_OBJECTS:ntrnt_obj>)
add_library(ntrnt SHARED $<TARGET_OBJECTS:ntrnt_obj>)
# ------------------------------------------------------------------------------
# lib settings
# ------------------------------------------------------------------------------
target_include_directories(ntrnt PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_BINARY_DIR}
)
target_link_libraries(ntrnt
	pcre
    ssl
    crypto
)
# ------------------------------------------------------------------------------
# properties
# ------------------------------------------------------------------------------
SET_TARGET_PROPERTIES(ntrnt_obj
    PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)
# ------------------------------------------------------------------------------
# Create symlink for libntrnt.so.<soversion>
# ------------------------------------------------------------------------------
SET_TARGET_PROPERTIES(ntrnt
    PROPERTIES
    SOVERSION 0
)
# ------------------------------------------------------------------------------
# install
# ------------------------------------------------------------------------------
# Add install target for the library
install(TARGETS ntrnt
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    COMPONENT Libraries
)
# Add install target for header files
install(FILES ${HDRS}
    DESTINATION include/ntrnt
    COMPONENT Headers
)

