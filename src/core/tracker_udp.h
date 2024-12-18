#ifndef _NTRNT_TRACKER_UDP_H
#define _NTRNT_TRACKER_UDP_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <arpa/inet.h>
#include <stdint.h>
#include <string>
#include "core/session.h"
#include "core/tracker.h"
#include "ntrnt/types.h"
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class http_resp;
class tracker_udp_rqst;
class session;
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::list<tracker_udp_rqst*> tracker_udp_rqst_list_t;
//! ----------------------------------------------------------------------------
//! \class: tracker_udp
//! ----------------------------------------------------------------------------
class tracker_udp : public tracker {
 public:
  // -------------------------------------------------
  // public types
  // -------------------------------------------------
  typedef std::list<tracker_udp_rqst*> udp_rqst_list_t;
  // -------------------------------------------------
  // public methods
  // -------------------------------------------------
  tracker_udp(session& a_session);
  ~tracker_udp(void);
  int32_t init(const char* a_str, size_t a_str_len);
  virtual int32_t announce(void);
  virtual int32_t scrape(void);
  // -------------------------------------------------
  // static public methods
  // -------------------------------------------------
  static int32_t handle_resp(tid_tracker_udp_map_t& a_map, uint8_t* a_msg,
                             uint32_t a_msg_len);

 private:
  // -------------------------------------------------
  // private methods
  // -------------------------------------------------
  // disallow copy/assign
  tracker_udp(const tracker_udp&);
  tracker_udp& operator=(const tracker_udp&);
  // -------------------------------------------------
  // private members
  // -------------------------------------------------
  tracker_udp_rqst_list_t m_gc_udp_rqst_list;
};
}  // namespace ns_ntrnt
#endif
