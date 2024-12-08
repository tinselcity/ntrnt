#ifndef _NTRNT_NRESOLVER_H
#define _NTRNT_NRESOLVER_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <pthread.h>
#include <stdint.h>
#include <list>
#include <map>
#include <queue>  // for std::priority_queue
#include <string>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define NRESOLVER_DEFAULT_AI_CACHE_FILE "/tmp/addr_info_cache.json"
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class nconn;
struct host_info;
class ai_cache;
//! ----------------------------------------------------------------------------
//! \details: TODO
//! ----------------------------------------------------------------------------
class nresolver {
 public:
  // -------------------------------------------------
  // Types
  // -------------------------------------------------
  typedef std::list<std::string> resolver_host_list_t;
  // -------------------------------------------------
  // Const
  // -------------------------------------------------
  static const uint32_t S_MIN_TTL_S = 10;
  // -------------------------------------------------
  // Public methods
  // -------------------------------------------------
  nresolver();
  ~nresolver();
  int32_t init(bool a_use_cache = true, const std::string& a_ai_cache_file =
                                            NRESOLVER_DEFAULT_AI_CACHE_FILE);
  void add_resolver_host(const std::string& a_server);
  void set_port(uint16_t a_port) { m_port = a_port; }
  bool get_use_cache(void) { return m_use_cache; }
  ai_cache* get_ai_cache(void) { return m_ai_cache; }
  // Lookups
  int32_t lookup_tryfast(const std::string& a_host, uint16_t a_port,
                         host_info& ao_host_info);
  int32_t lookup_sync(const std::string& a_host, uint16_t a_port,
                      host_info& ao_host_info);

 private:
  // -------------------------------------------------
  // Private methods
  // -------------------------------------------------
  // Disallow copy/assign
  nresolver& operator=(const nresolver&);
  nresolver(const nresolver&);
  int32_t lookup_inline(const std::string& a_host, uint16_t a_port,
                        host_info& ao_host_info);
  // -------------------------------------------------
  // Private members
  // -------------------------------------------------
  bool m_is_initd;
  resolver_host_list_t m_resolver_host_list;
  uint16_t m_port;
  uint32_t m_use_cache;
  pthread_mutex_t m_cache_mutex;
  ai_cache* m_ai_cache;
};
//! ----------------------------------------------------------------------------
//! cache key helper
//! ----------------------------------------------------------------------------
std::string get_cache_key(const std::string& a_host, uint16_t a_port);
bool is_valid_ip_address(const char* a_str);
}  // namespace ns_ntrnt
#endif
