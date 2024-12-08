#ifndef _NTRNT_GEOIP2_MMDB_H_
#define _NTRNT_GEOIP2_MMDB_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <string>
#include <cstdint>
#include "ntrnt/def.h"
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
struct MMDB_s;
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! geoip2_mmdb
//! ----------------------------------------------------------------------------
class geoip2_mmdb {
 public:
  // -------------------------------------------------
  // public methods
  // -------------------------------------------------
  geoip2_mmdb();
  ~geoip2_mmdb();
  int32_t init(const std::string& a_city_mmdb_path);
  int32_t get_geoip_data(const char** ao_cn_name, uint32_t& ao_cn_name_len,
                         const char** ao_city_name, uint32_t& ao_city_name_len,
                         double& ao_lat, double& ao_longit, const char* a_ip,
                         uint32_t a_ip_len);

 private:
  // -------------------------------------------------
  // Private methods
  // -------------------------------------------------
  // Disallow copy/assign
  geoip2_mmdb(const geoip2_mmdb&);
  geoip2_mmdb& operator=(const geoip2_mmdb&);
  // -------------------------------------------------
  // Private members
  // -------------------------------------------------
  bool m_init;
  MMDB_s* m_city_mmdb;
};
}  // namespace ns_ntrnt
#endif
