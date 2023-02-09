#ifndef _NTRNT_UTIL_H
#define _NTRNT_UTIL_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "ntrnt/types.h"
#include <stddef.h>
#include <stdint.h>
#include <string>
//! ----------------------------------------------------------------------------
//! methods
//! ----------------------------------------------------------------------------
namespace ns_ntrnt
{
int32_t write_file(const char *a_file, const char *a_buf, size_t a_len);
int32_t read_file(const char* a_file, char** a_buf, size_t* a_len);
int32_t ensure_dir(const std::string& a_dir);
int32_t b64_encode(char** ao_out, const unsigned char* a_in, size_t a_in_len);
int32_t b64_encode(std::string& ao_out, const unsigned char* a_in, size_t a_in_len);
int32_t bin2hex(char** ao_out, const uint8_t* a_bin, size_t a_len);
int32_t bin2hex_str(std::string& ao_out, const uint8_t* a_bin, size_t a_len);
int32_t hex2bin(uint8_t* ao_bin, size_t& ao_bin_len, const char* a_hex, const size_t a_hex_len);
std::string id2str(const id_t& a_id);
std::string rand_str(const size_t a_len);
std::string epoch_to_str(uint64_t a_ts);
}
#endif
