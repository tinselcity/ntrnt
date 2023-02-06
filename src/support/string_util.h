#ifndef _NTRNT_STRING_UTIL_H
#define _NTRNT_STRING_UTIL_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <string>
#include <stdint.h>
#include <limits.h>
#include "data.h"
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! prototypes
//! ----------------------------------------------------------------------------
int32_t break_header_string(const std::string &a_header_str,
                            std::string &ao_header_key,
                            std::string &ao_header_val);
std::string get_file_wo_path(const std::string &a_filename);
std::string get_file_path(const std::string &a_filename);
std::string get_base_filename(const std::string &a_filename);
std::string get_file_ext(const std::string &a_filename);
std::string get_file_wo_ext(const std::string &a_filename);
int32_t convert_hex_to_uint(uint64_t &ao_val, const char *a_str);
int32_t parse_cookies(arg_list_t &ao_cookie_list, const char *a_buf, uint32_t a_len);
int32_t urldecode_ns(char **ao_buf, uint32_t &ao_len, uint32_t &ao_invalid_count, const char *a_buf, uint32_t a_len);
int32_t parse_args(mutable_arg_list_t &ao_arg_list, uint32_t &ao_invalid_cnt, const char *a_buf, uint32_t a_len, char a_arg_sep);
} //namespace ns_ntrnt {
#endif
