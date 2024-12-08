//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "http/http_resp.h"
#include "http/http_cb.h"
#include "http_parser/http_parser.h"
#include "ntrnt/def.h"
#include "support/nbq.h"
#include "support/ndebug.h"
#include "support/trace.h"
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
http_resp::http_resp(void) : http_msg(), m_p_status(), m_status() {
  init();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
http_resp::~http_resp(void) {}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void http_resp::clear(void) {
  init();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void http_resp::init(void) {
  http_msg::init();
  m_type = http_msg::TYPE_RESP;
  m_p_status.clear();
  m_status = HTTP_STATUS_NONE;
  if (m_http_parser_settings) {
    m_http_parser_settings->on_status = hp_on_status;
    m_http_parser_settings->on_message_complete = hp_on_message_complete;
    m_http_parser_settings->on_message_begin = hp_on_message_begin;
    m_http_parser_settings->on_url = hp_on_url;
    m_http_parser_settings->on_header_field = hp_on_header_field;
    m_http_parser_settings->on_header_value = hp_on_header_value;
    m_http_parser_settings->on_headers_complete = hp_on_headers_complete;
    m_http_parser_settings->on_body = hp_on_body;
  }
  if (m_http_parser_settings) {
    m_http_parser->data = this;
    http_parser_init(m_http_parser, HTTP_RESPONSE);
  }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
uint16_t http_resp::get_status(void) {
  return m_status;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void http_resp::set_status(http_status_t a_code) {
  m_status = a_code;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void http_resp::show(void) {
  m_q->reset_read();
  TRC_OUTPUT("HTTP/%d.%d %u ", m_http_major, m_http_minor, m_status);
  print_part(*m_q, m_p_status.m_off, m_p_status.m_len);
  TRC_OUTPUT("\r\n");
  cr_list_t::const_iterator i_k = m_p_h_list_key.begin();
  cr_list_t::const_iterator i_v = m_p_h_list_val.begin();
  for (; i_k != m_p_h_list_key.end() && i_v != m_p_h_list_val.end();
       ++i_k, ++i_v) {
    print_part(*m_q, i_k->m_off, i_k->m_len);
    TRC_OUTPUT(": ");
    print_part(*m_q, i_v->m_off, i_v->m_len);
    TRC_OUTPUT("\r\n");
  }
  TRC_OUTPUT("\r\n");
  print_part(*m_q, m_p_body.m_off, m_p_body.m_len);
  TRC_OUTPUT("\r\n");
}
}  // namespace ns_ntrnt
