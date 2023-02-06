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
# ------------------------------------------------------------------------------
# flags
# ------------------------------------------------------------------------------
set(CMAKE_C_FLAGS "-std=c99")
set(CMAKE_CXX_FLAGS "-Wall -Weffc++ -Wcast-qual -Werror -std=c++11")
# ------------------------------------------------------------------------------
# include directories
# ------------------------------------------------------------------------------
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/ext
    ${CMAKE_SOURCE_DIR}/ext/farmhash
)
# ------------------------------------------------------------------------------
# macros
# ------------------------------------------------------------------------------
macro (add_ntrnt_wb_test test_name)
    SET(SRCS "wb_${test_name}.cc")
    add_executable("wb_${test_name}" ${SRCS})
	target_compile_definitions("wb_${test_name}" PUBLIC TEST_RESOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data/")
    target_link_libraries("wb_${test_name}"
        ${DEBUG_LIBRARIES}
        ntrnt_compiled_catch
        ntrnt
        ${LIBRARIES}
    )
    add_test(${test_name} "wb_${test_name}")
    set_property(TEST ${test_name} PROPERTY ENVIRONMENT "ASAN_OPTIONS=detect_odr_violation=0")
endmacro()
# ------------------------------------------------------------------------------
# build catch
# ------------------------------------------------------------------------------
add_library(ntrnt_compiled_catch STATIC ${CMAKE_SOURCE_DIR}/ext/catch/catch.hpp _catch.cc)
# ------------------------------------------------------------------------------
# build tests
# ------------------------------------------------------------------------------
add_subdirectory(bencode)
add_subdirectory(core)
add_subdirectory(dns)
add_subdirectory(support)
