//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "support/ndebug.h"
#include "http/http_cb.h"
#include "http/http_rqst.h"
#include "http/http_resp.h"
#include "support/trace.h"
#include "ntrnt/def.h"
#include <string.h>
//! ----------------------------------------------------------------------------
//! Macros
//! ----------------------------------------------------------------------------
#define CALC_OFFSET(_hmsg, _at) \
        ((_at - _hmsg->m_cur_buf) + _hmsg->m_cur_off)
#define CHECK_FOR_NULL_OK(_data) \
        do {\
                if (!_data) {\
                        return 0;\
                }\
        } while(0);
#define CHECK_FOR_NULL_ERROR(_data) \
        do {\
                if (!_data) {\
                        return NTRNT_STATUS_ERROR;\
                }\
        } while(0);
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int hp_on_message_begin(http_parser* a_parser)
{
        http_msg *l_hmsg = static_cast <http_msg *>(a_parser->data);
        CHECK_FOR_NULL_OK(l_hmsg);
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int hp_on_url(http_parser* a_parser, const char *a_at, size_t a_length)
{
        http_msg *l_hmsg = static_cast <http_msg *>(a_parser->data);
        CHECK_FOR_NULL_OK(l_hmsg);
        if ((l_hmsg->get_type() == http_msg::TYPE_RQST))
        {
                http_rqst *l_rqst = static_cast<http_rqst *>(l_hmsg);
                l_rqst->m_p_url.m_off = CALC_OFFSET(l_hmsg, a_at);
                l_rqst->m_p_url.m_len = a_length;
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int hp_on_status(http_parser* a_parser, const char *a_at, size_t a_length)
{
        http_msg *l_hmsg = static_cast <http_msg *>(a_parser->data);
        CHECK_FOR_NULL_OK(l_hmsg);
        //l_clnt->m_status_code = a_parser->status_code;
        if (l_hmsg->get_type() == http_msg::TYPE_RESP)
        {
                http_resp *l_resp = static_cast<http_resp *>(l_hmsg);
                l_resp->set_status((http_status_t)a_parser->status_code);
                l_resp->m_p_status.m_off = CALC_OFFSET(l_hmsg, a_at);
                l_resp->m_p_status.m_len = a_length;
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int hp_on_header_field(http_parser* a_parser, const char *a_at, size_t a_length)
{
        http_msg *l_hmsg = static_cast <http_msg *>(a_parser->data);
        CHECK_FOR_NULL_OK(l_hmsg);
        cr_struct l_cr;
        l_cr.m_off = CALC_OFFSET(l_hmsg, a_at);
        l_cr.m_len = a_length;
        l_hmsg->m_p_h_list_key.push_back(l_cr);
        // signalling for expect headers
        if (l_hmsg->get_type() == http_msg::TYPE_RQST)
        {
                const char l_exp[] = "Expect";
                if ((a_length == (sizeof(l_exp)-1)) && (a_at[0] == 'E'))
                {
                        if (strncasecmp(l_exp, a_at, a_length) == 0)
                        {
                                http_rqst *l_rqst = static_cast<http_rqst *>(l_hmsg);
                                l_rqst->m_expect = true;
                        }
                }
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int hp_on_header_value(http_parser* a_parser, const char *a_at, size_t a_length)
{
        http_msg *l_hmsg = static_cast <http_msg *>(a_parser->data);
        CHECK_FOR_NULL_OK(l_hmsg);
        cr_struct l_cr;
        l_cr.m_off = CALC_OFFSET(l_hmsg, a_at);
        l_cr.m_len = a_length;
        l_hmsg->m_p_h_list_val.push_back(l_cr);
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int hp_on_headers_complete(http_parser* a_parser)
{
        http_msg *l_hmsg = static_cast <http_msg *>(a_parser->data);
        CHECK_FOR_NULL_OK(l_hmsg);
        l_hmsg->m_http_major = a_parser->http_major;
        l_hmsg->m_http_minor = a_parser->http_minor;
        if (l_hmsg->get_type() == http_msg::TYPE_RQST)
        {
                http_rqst *l_rqst = static_cast<http_rqst *>(l_hmsg);
                l_rqst->m_method = a_parser->method;
        }
        if (l_hmsg->get_type() == http_msg::TYPE_RESP)
        {
                if (!l_hmsg->m_expect_resp_body_flag)
                {
                        return 1;
                }
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int hp_on_body(http_parser* a_parser, const char *a_at, size_t a_length)
{
        http_msg *l_hmsg = static_cast <http_msg *>(a_parser->data);
        CHECK_FOR_NULL_OK(l_hmsg);
        if (!l_hmsg->m_p_body.m_off)
        {
                l_hmsg->m_p_body.m_off = CALC_OFFSET(l_hmsg, a_at);
                l_hmsg->m_p_body.m_len = a_length;
        }
        else
        {
                l_hmsg->m_p_body.m_len += a_length;
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int hp_on_message_complete(http_parser* a_parser)
{
        http_msg *l_hmsg = static_cast <http_msg *>(a_parser->data);
        CHECK_FOR_NULL_OK(l_hmsg);
        l_hmsg->m_complete = true;
        l_hmsg->m_supports_keep_alives = http_should_keep_alive(a_parser);
        return 0;
}
} //namespace ns_ntrnt {
