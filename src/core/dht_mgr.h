#ifndef _NTRNT_DHT_MGR_H
#define _NTRNT_DHT_MGR_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "core/session.h"
#include "dht/dhsco.h"
//! ----------------------------------------------------------------------------
//! ext fwd decl's
//! ----------------------------------------------------------------------------
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \class: dht_mgr
//! ----------------------------------------------------------------------------
class dht_mgr {
 public:
  // -------------------------------------------------
  // public methods
  // -------------------------------------------------
  dht_mgr(session& a_session);
  ~dht_mgr(void);
  int32_t init(void);
  int32_t recv_msg(struct sockaddr_storage& a_ss, socklen_t& a_ss_len,
                   uint8_t* a_msg, uint32_t a_msg_len);
  int32_t ping(struct sockaddr_storage& a_sas);
  session& get_session(void) { return m_session; }
  // -------------------------------------------------
  // dht cb helpers
  // -------------------------------------------------
  int32_t bootstrap_dq(void);
  int32_t announce(void);
  int32_t periodic(void);
  // -------------------------------------------------
  // public static methods
  // -------------------------------------------------
  static void dht_cb(void* a_vself, dht_event_t a_event,
                     unsigned char const* a_info_hash, void const* a_data,
                     size_t a_data_len);
  // -------------------------------------------------
  // public members
  // -------------------------------------------------
 private:
  // -------------------------------------------------
  // private methods
  // -------------------------------------------------
  // disallow copy/assign
  dht_mgr(const dht_mgr&);
  dht_mgr& operator=(const dht_mgr&);
  // -------------------------------------------------
  // private members
  // -------------------------------------------------
  session& m_session;
  dhsco* m_dhsco;
  id_t m_id;
};
}  // namespace ns_ntrnt
#endif
