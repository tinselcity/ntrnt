#ifndef _NTRNT_TIME_UTIL_H
#define _NTRNT_TIME_UTIL_H
//! ----------------------------------------------------------------------------
//! Includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! Prototypes
//! ----------------------------------------------------------------------------
const char *get_date_str(void);
uint64_t get_time_s(void);
uint64_t get_time_ms(void);
uint64_t get_time_us(void);
uint64_t get_delta_time_ms(uint64_t a_start_time_ms);
uint64_t get_delta_time_us(uint64_t a_start_time_us);
} //namespace ns_ntrnt {
#endif
