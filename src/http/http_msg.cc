//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "ntrnt/def.h"
#include "http/http_msg.h"
#include "support/nbq.h"
#include "support/ndebug.h"
#include "http_parser/http_parser.h"
#include <stdlib.h>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
http_msg::http_msg(void):
        m_http_parser_settings(NULL),
        m_http_parser(NULL),
        m_expect_resp_body_flag(true),
        m_cur_off(0),
        m_cur_buf(NULL),
        m_p_h_list_key(),
        m_p_h_list_val(),
        m_p_body(),
        m_http_major(),
        m_http_minor(),
        m_complete(false),
        m_supports_keep_alives(false),
        m_type(TYPE_NONE),
        m_q(NULL),
        m_body_q(NULL),
        m_idx(0),
        m_header_list(NULL),
        m_header_map(NULL)
{
        m_http_parser_settings = (http_parser_settings *)calloc(1, sizeof(http_parser_settings));
        m_http_parser = (http_parser *)calloc(1, sizeof(http_parser));
        init();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
http_msg::~http_msg(void)
{
        if (m_http_parser_settings) { free(m_http_parser_settings); m_http_parser_settings = NULL; }
        if (m_http_parser) { free(m_http_parser); m_http_parser = NULL; }
        if (m_header_list)
        {
                for(mutable_arg_list_t::iterator i_q = m_header_list->begin();
                    i_q != m_header_list->end();
                    ++i_q)
                {
                        if (i_q->m_key) { free(i_q->m_key); i_q->m_key = NULL; }
                        if (i_q->m_val) { free(i_q->m_val); i_q->m_val = NULL; }
                }
                if (m_header_list) { delete m_header_list; m_header_list = NULL; }
        }
        if (m_header_map) { delete m_header_map; m_header_map = NULL; }
        if (m_body_q) { delete m_body_q; m_body_q = NULL; }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void http_msg::init(void)
{
        m_p_h_list_key.clear();
        m_p_h_list_val.clear();
        m_p_body.clear();
        m_http_major = 0;
        m_http_minor = 0;
        m_complete = false;
        m_supports_keep_alives = false;
        m_cur_buf = NULL;
        m_cur_off = 0;
        m_expect_resp_body_flag = true;
        if (m_header_list)
        {
                for(mutable_arg_list_t::iterator i_q = m_header_list->begin();
                    i_q != m_header_list->end();
                    ++i_q)
                {
                        if (i_q->m_key) { free(i_q->m_key); i_q->m_key = NULL; }
                        if (i_q->m_val) { free(i_q->m_val); i_q->m_val = NULL; }
                }
                if (m_header_list) { delete m_header_list; m_header_list = NULL; }
        }
        if (m_header_map) { delete m_header_map; m_header_map = NULL; }
        if (m_body_q) { delete m_body_q; m_body_q = NULL; }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
http_msg::type_t http_msg::get_type(void) const
{
        return m_type;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
nbq *http_msg::get_q(void) const
{
        return m_q;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
nbq *http_msg::get_body_q(void)
{
        if (m_body_q)
        {
                return m_body_q;
        }
        if (!m_p_body.m_off)
        {
                return NULL;
        }
        int32_t l_s;
        l_s = m_q->split(&m_body_q, m_p_body.m_off);
        if (l_s != NTRNT_STATUS_OK)
        {
                return NULL;
        }
        return m_body_q;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
uint64_t http_msg::get_body_len(void) const
{
        return m_p_body.m_len;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   NA
//! ----------------------------------------------------------------------------
const mutable_arg_list_t& http_msg::get_header_list()
{
        // -------------------------------------------------
        // create header list
        // -------------------------------------------------
        if (!m_header_list)
        {
                m_header_list = new mutable_arg_list_t();
                cr_list_t::const_iterator i_k = m_p_h_list_key.begin();
                cr_list_t::const_iterator i_v = m_p_h_list_val.begin();
                for(;
                    i_k != m_p_h_list_key.end() && i_v != m_p_h_list_val.end();
                    ++i_k, ++i_v)
                {
                        mutable_arg_t l_arg;
                        l_arg.m_key = copy_part(*m_q, i_k->m_off, i_k->m_len);
                        l_arg.m_key_len = i_k->m_len;
                        l_arg.m_val = copy_part(*m_q, i_v->m_off, i_v->m_len);
                        l_arg.m_val_len = i_v->m_len;
                        m_header_list->push_back(l_arg);
                }
        }
        return *m_header_list;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   NA
//! ----------------------------------------------------------------------------
const mutable_data_map_list_t& http_msg::get_header_map()
{
        // -------------------------------------------------
        // create header map
        // -------------------------------------------------
        if (!m_header_map)
        {
                const mutable_arg_list_t &l_list = get_header_list();
                m_header_map = new mutable_data_map_list_t();
                for(mutable_arg_list_t::const_iterator i_q = l_list.begin();
                    i_q != l_list.end();
                    ++i_q)
                {
                        mutable_data_t l_k;
                        l_k.m_data = i_q->m_key;
                        l_k.m_len = i_q->m_key_len;
                        mutable_data_t l_v;
                        l_v.m_data = i_q->m_val;
                        l_v.m_len = i_q->m_val_len;
                        mutable_data_map_list_t::iterator i_obj = m_header_map->find(l_k);
                        if (i_obj != m_header_map->end())
                        {
                                i_obj->second.push_back(l_v);
                        }
                        else
                        {
                                mutable_data_list_t l_list;
                                l_list.push_back(l_v);
                                (*m_header_map)[l_k] = l_list;
                        }
                }
        }
        return *m_header_map;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
uint64_t http_msg::get_idx(void) const
{
        return m_idx;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void http_msg::set_idx(uint64_t a_idx)
{
        m_idx = a_idx;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void http_msg::set_q(nbq *a_q)
{
        m_q = a_q;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void http_msg::reset_body_q(void)
{
       m_body_q = NULL;
       m_p_body.m_len = 0;
       m_p_body.m_off = 0;
}
} //namespace ns_ntrnt {
