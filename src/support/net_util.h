#ifndef _NTRNT_NET_UTIL_H
#define _NTRNT_NET_UTIL_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <arpa/inet.h>
#include <stdint.h>
#include <string>
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! byteswapping
//! ----------------------------------------------------------------------------
#ifndef bswap_16
#define bswap_16(value) ((((value) & 0xff) << 8) | ((value) >> 8))
#endif
#ifndef bswap_32
#define bswap_32(value)                                       \
  (((uint32_t)bswap_16((uint16_t)((value) & 0xffff)) << 16) | \
   (uint32_t)bswap_16((uint16_t)((value) >> 16)))
#endif

#ifndef bswap_64
#define bswap_64(value)                                           \
  (((uint64_t)bswap_32((uint32_t)((value) & 0xffffffff)) << 32) | \
   (uint64_t)bswap_32((uint32_t)((value) >> 32)))
#endif
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! inline
//! ----------------------------------------------------------------------------
// TODO -feels like there must be a builtin macro for this???
inline size_t sas_size(const sockaddr_storage& a_sas) {
  if (a_sas.ss_family == AF_INET) {
    return sizeof(sockaddr_in);
  } else if (a_sas.ss_family == AF_INET6) {
    return sizeof(sockaddr_in6);
  }
  return 0;
}
//! ----------------------------------------------------------------------------
//! prototypes
//! ----------------------------------------------------------------------------
int32_t display_public_address(void);
const char* get_public_address_v6_str(void);
std::string sas_to_str(const struct sockaddr_storage& a_ss);
std::string sas_to_ip_str(const struct sockaddr_storage& a_ss);
int32_t str_to_sas(const std::string& a_str, struct sockaddr_storage& a_sas);
}  // namespace ns_ntrnt
#endif
