#ifndef _NTRNT_HTTP_RESP_H
#define _NTRNT_HTTP_RESP_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "http/http_msg.h"
#include "http/http_status.h"
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! ----------------------------------------------------------------------------
class http_resp : public http_msg {
 public:
  // -------------------------------------------------
  // public methods
  // -------------------------------------------------
  http_resp();
  ~http_resp();
  // Getters
  uint16_t get_status(void);
  // Setters
  void set_status(http_status_t a_code);
  void clear(void);
  void init(void);
  // Debug
  void show();
  // -------------------------------------------------
  // public members
  // -------------------------------------------------
  // -------------------------------------------------
  // raw http request offsets
  // -------------------------------------------------
  cr_t m_p_status;

 private:
  // -------------------------------------------------
  // private methods
  // -------------------------------------------------
  // Disallow copy/assign
  http_resp& operator=(const http_resp&);
  http_resp(const http_resp&);
  // -------------------------------------------------
  // private members
  // -------------------------------------------------
  http_status_t m_status;
};
}  // namespace ns_ntrnt
#endif
