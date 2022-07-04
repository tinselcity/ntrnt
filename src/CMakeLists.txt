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
    # ext
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext
    # ------------------------------------------------------
    # ext
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/dht/include
    ${CMAKE_SOURCE_DIR}/ext/uri
    # ------------------------------------------------------
    # ntrnt include
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
# ------------------------------------------------------------------------------
# source files
# ------------------------------------------------------------------------------
SET(SRCS
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
    # ext/dht
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/dht/src/dht.c
    # ------------------------------------------------------
    # support
    # ------------------------------------------------------
    support/ndebug.cc
    support/nconn_pool.cc
    support/trace.cc
    support/util.cc
    support/nbq.cc
    support/time_util.cc
    support/tls_util.cc
    support/net_util.cc
    support/string_util.cc
    # ------------------------------------------------------
    # evr
    # ------------------------------------------------------
    evr/evr.cc
    # TODO OS X support...
    #evr/evr_kqueue.cc
    evr/evr_select.cc
    evr/evr_epoll.cc
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
    dht/dht_cb.cc
    dht/kdm.cc
    # ------------------------------------------------------
    # bencode
    # ------------------------------------------------------
    bencode/bencode.cc
    # ------------------------------------------------------
    # tracker
    # ------------------------------------------------------
    tracker/tracker.cc
    tracker/tracker_http.cc
    tracker/tracker_http_rqst.cc
    # ------------------------------------------------------
    # tracker
    # ------------------------------------------------------
    peer/peer.cc
    # ------------------------------------------------------
    # core
    # ------------------------------------------------------
    core/ntrnt.cc
    core/torrent.cc
    core/session.cc
)
# ------------------------------------------------------------------------------
# properties
# ------------------------------------------------------------------------------
set(CMAKE_C_FLAGS "-std=c99")
set_source_files_properties(${SRCS} PROPERTIES COMPILE_FLAGS -Wall)
set_source_files_properties(${SRCS} PROPERTIES COMPILE_FLAGS -Weffc++)
set_source_files_properties(${SRCS} PROPERTIES COMPILE_FLAGS -Wcast-qual)
set_source_files_properties(${SRCS} PROPERTIES COMPILE_FLAGS -Wno-nonnull-compare)
set_source_files_properties(${SRCS} PROPERTIES COMPILE_FLAGS -Werror)
# ------------------------------------------------------------------------------
# c source
# ------------------------------------------------------------------------------
SET_SOURCE_FILES_PROPERTIES(
    ${UDNS_SRCS}
    # ------------------------------------------------------
    # ext/dht
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/dht/src/dht.c
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
add_library(ntrnt_obj OBJECT ${SRCS})
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

