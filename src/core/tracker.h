#ifndef _NTRNT_TRACKER_H
#define _NTRNT_TRACKER_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include <string>
#include "conn/scheme.h"
#include "ntrnt/types.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class torrent;
class session;
//! ----------------------------------------------------------------------------
//! \class: tracker
//! ----------------------------------------------------------------------------
class tracker {
 public:
  // -------------------------------------------------
  // public methods
  // -------------------------------------------------
  tracker(session& a_session);
  virtual ~tracker(void);
  virtual int32_t announce(void) = 0;
  virtual int32_t scrape(void) = 0;
  void display(void);
  std::string str(void);
  // -------------------------------------------------
  // public members
  // -------------------------------------------------
  session& m_session;
  std::string m_announce;
  scheme_t m_scheme;
  std::string m_host;
  uint16_t m_port;
  std::string m_root;
  size_t m_stat_announce_num;
  size_t m_stat_scrape_num;
  uint64_t m_next_announce_s;
  uint64_t m_next_scrape_s;
  size_t m_stat_last_announce_time_s;
  size_t m_stat_last_announce_num_peers;
  size_t m_stat_last_announce_num_peers6;
  size_t m_stat_last_scrape_time_s;
  size_t m_stat_last_scrape_num_complete;
  size_t m_stat_last_scrape_num_downloaded;
  size_t m_stat_last_scrape_num_incomplete;

 private:
  // -------------------------------------------------
  // private methods
  // -------------------------------------------------
  // -------------------------------------------------
  // disallow copy/assign
  // -------------------------------------------------
  tracker(const tracker&);
  tracker& operator=(const tracker&);
};
//! ----------------------------------------------------------------------------
//! prototypes
//! ----------------------------------------------------------------------------
int32_t init_tracker_w_url(tracker** ao_tracker, session& a_session,
                           const char* a_url, size_t a_url_len);
void http_escape(std::string& ao_out, std::string a_in, bool a_escp_rsvd);
void encode_digest(char* a_out, const uint8_t* a_digest, size_t a_digest_len);
}  // namespace ns_ntrnt
#endif
