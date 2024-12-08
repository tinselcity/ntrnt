#ifndef _NTRNT_HTTP_RQST_H
#define _NTRNT_HTTP_RQST_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <list>
#include <string>
#include "http/http_msg.h"
#include "support/data.h"
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! ----------------------------------------------------------------------------
class http_rqst : public http_msg {
 public:
  // -------------------------------------------------
  // public methods
  // -------------------------------------------------
  http_rqst();
  ~http_rqst();
  void clear(void);
  void init(void);
  const data_t& get_url();
  const data_t& get_url_uri();
  const data_t& get_url_path();
  const data_t& get_url_query();
  const data_t& get_url_fragment();
  const data_t& get_url_host();
  const char* get_method_str();
  const mutable_arg_list_t& get_query_list();
  const mutable_data_map_list_t& get_query_map();
  // Debug
  void show();
  // -------------------------------------------------
  // public members
  // -------------------------------------------------
  // -------------------------------------------------
  // raw http request offsets
  // -------------------------------------------------
  cr_t m_p_url;
  int m_method;
  bool m_expect;

 private:
  // -------------------------------------------------
  // private methods
  // -------------------------------------------------
  int32_t parse_uri(void);
  // Disallow copy/assign
  http_rqst& operator=(const http_rqst&);
  http_rqst(const http_rqst&);
  // -------------------------------------------------
  // private members
  // -------------------------------------------------
  bool m_url_parsed;
  char* m_url_buf;
  uint32_t m_url_buf_len;
  data_t m_url;
  data_t m_url_uri;
  data_t m_url_host;
  data_t m_url_path;
  data_t m_url_query;
  data_t m_url_fragment;
  mutable_arg_list_t* m_query_list;
  mutable_data_map_list_t* m_query_map;
};
}  // namespace ns_ntrnt
#endif
