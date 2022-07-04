//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
// ---------------------------------------------------------
// external
// ---------------------------------------------------------
#include "ntrnt/def.h"
// ---------------------------------------------------------
// internal
// ---------------------------------------------------------
#include "support/nbq.h"
#include "support/nconn_pool.h"
#include "support/ndebug.h"
#include "support/trace.h"
#include "conn/host_info.h"
#include "conn/nconn.h"
#include "conn/nconn_tls.h"
#include "core/session.h"
#include "dns/nresolver.h"
#include "http/http_resp.h"
#include "bencode/bencode.h"
// ---------------------------------------------------------
// 3rd party
// ---------------------------------------------------------
#include "http_parser/http_parser.h"
// ---------------------------------------------------------
// std
// ---------------------------------------------------------
#include <string.h>

#include "tracker_tcp_rqst.h"
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#define _SET_NCONN_OPT(_conn, _opt, _buf, _len) \
        do { \
                int _status = 0; \
                _status = _conn.set_opt((_opt), (_buf), (_len)); \
                if (_status != nconn::NC_STATUS_OK) { \
                        TRC_ERROR("set_opt %d.  Status: %d.\n", \
                                   _opt, _status); \
                        return NTRNT_STATUS_ERROR;\
                } \
        } while(0)
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t run_state_machine(void *a_data, evr_mode_t a_conn_mode)
{
        NDBG_PRINT("RUN a_conn_mode: %d a_data: %p\n", a_conn_mode, a_data);
        //CHECK_FOR_NULL_ERROR(a_data);
        // TODO -return OK for a_data == NULL
        if (!a_data)
        {
                return NTRNT_STATUS_OK;
        }
        nconn &l_nconn = *(static_cast<nconn*>(a_data));
        if (!l_nconn.get_ctx())
        {
                TRC_ERROR("no t_srvr associated with connection -cleaning up: nconn: label: %s\n",
                          l_nconn.get_label().c_str());
                l_nconn.nc_cleanup();
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // check for cancelled
        // -------------------------------------------------
        if (l_nconn.get_status() == CONN_STATUS_CANCELLED)
        {
                return NTRNT_STATUS_DONE;
        }
        session &l_ses = *(static_cast<session *>(l_nconn.get_ctx()));
        tracker_tcp_rqst *l_rqst = static_cast<tracker_tcp_rqst *>(l_nconn.get_data());
        // -------------------------------------------------
        // mode switch
        // -------------------------------------------------
        switch(a_conn_mode)
        {
        // -------------------------------------------------
        // ERROR
        // -------------------------------------------------
        case EVR_MODE_ERROR:
        {
                TRC_ERROR("connection error: label: %s\n", l_nconn.get_label().c_str());
                int32_t l_s;
                l_s = tracker_tcp_rqst::teardown(l_rqst, l_ses, l_nconn, HTTP_STATUS_BAD_GATEWAY);
                // TODO -check status...
                UNUSED(l_s);
                return NTRNT_STATUS_DONE;
        }
        // -------------------------------------------------
        // TIMEOUT
        // -------------------------------------------------
        case EVR_MODE_TIMEOUT:
        {
                // ignore timeout for free connections
                if (l_nconn.is_free())
                {
                        TRC_ERROR("call back for free connection\n");
                        return NTRNT_STATUS_OK;
                }
                // calc time since last active
                if (!l_rqst)
                {
                        TRC_ERROR("a_conn_mode[%d] session[%p] || t_srvr[%p] == NULL\n",
                                        a_conn_mode,
                                        l_rqst,
                                        &l_ses);
                        return NTRNT_STATUS_ERROR;
                }
                // -----------------------------------------
                // timeout
                // -----------------------------------------
                uint64_t l_ct_ms = get_time_ms();
                if (((uint32_t)(l_ct_ms - l_rqst->m_last_active_ms)) >= l_rqst->m_timeout_ms)
                {
                        //++(l_ses->m_stat.m_upsv_errors);
                        //++(l_ses->m_stat.m_upsv_idle_killed);
                        //TRC_VERBOSE("teardown status: %d\n", HTTP_STATUS_GATEWAY_TIMEOUT);
                        TRC_ERROR("connection error: label: %s\n", l_nconn.get_label().c_str());
                        int32_t l_s;
                        l_s = tracker_tcp_rqst::teardown(l_rqst, l_ses, l_nconn, HTTP_STATUS_BAD_GATEWAY);
                        // TODO -check status...
                        UNUSED(l_s);
                        return NTRNT_STATUS_DONE;
                }
                // TODO check status
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // EVR_MODE_READ
        // -------------------------------------------------
        case EVR_MODE_READ:
        {
                // ignore readable for free connections
                if (l_nconn.is_free())
                {
                        TRC_ERROR("call back for free connection\n");
                        return NTRNT_STATUS_OK;
                }
                // -----------------------------------------
                // skip reads for sessions stuck in again
                // state
                // -----------------------------------------
                if (l_rqst &&
                   l_rqst->m_again)
                {
                        return NTRNT_STATUS_OK;
                }
                break;
        }
        // -------------------------------------------------
        // EVR_MODE_WRITE
        // -------------------------------------------------
        case EVR_MODE_WRITE:
        {
                break;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                TRC_ERROR("unknown a_conn_mode: %d\n", a_conn_mode);
                return NTRNT_STATUS_OK;
        }
        }
        bool l_idle = false;
        // --------------------------------------------------
        // **************************************************
        // state machine
        // **************************************************
        // --------------------------------------------------
        NDBG_PRINT("%sRUN_STATE_MACHINE%s: CONN[%p] STATE[%d] MODE: %d --START\n",
                    ANSI_COLOR_BG_YELLOW, ANSI_COLOR_OFF, &l_nconn, l_nconn.get_state(), a_conn_mode);
state_top:
        NDBG_PRINT("%sRUN_STATE_MACHINE%s: CONN[%p] STATE[%d] MODE: %d\n",
                    ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, &l_nconn, l_nconn.get_state(), a_conn_mode);
        switch(l_nconn.get_state())
        {
        // -------------------------------------------------
        // STATE: FREE
        // -------------------------------------------------
        case nconn::NC_STATE_FREE:
        {
                int32_t l_s;
                l_s = l_nconn.ncsetup();
                if (l_s != nconn::NC_STATUS_OK)
                {
                        TRC_ERROR("performing ncsetup\n");
                        return NTRNT_STATUS_ERROR;
                }
                l_nconn.set_state(nconn::NC_STATE_CONNECTING);
                goto state_top;
        }
        // -------------------------------------------------
        // STATE: CONNECTING
        // -------------------------------------------------
        case nconn::NC_STATE_CONNECTING:
        {
                NDBG_PRINT("%sConnecting%s: host: %s\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, l_nconn.m_label.c_str());
                int32_t l_s;
                l_s = l_nconn.ncconnect();
                if (l_s == nconn::NC_STATUS_ERROR)
                {
                        int32_t l_s;
                        l_s = tracker_tcp_rqst::teardown(l_rqst, l_ses, l_nconn, HTTP_STATUS_BAD_GATEWAY);
                        // TODO -check status...
                        UNUSED(l_s);
                        return NTRNT_STATUS_DONE;
                }
                if (l_nconn.is_connecting())
                {
                        NDBG_PRINT("Still connecting...\n");
                        return NTRNT_STATUS_OK;
                }
                NDBG_PRINT("%sConnected%s: label: %s\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, l_nconn.m_label.c_str());
                TRC_DEBUG("Connected: label: %s\n", l_nconn.m_label.c_str());
                // Returning client fd
                // If OK -change state to connected???
                l_nconn.set_state(nconn::NC_STATE_CONNECTED);
                goto state_top;
        }
        // -------------------------------------------------
        // STATE: DONE
        // -------------------------------------------------
        case nconn::NC_STATE_DONE:
        {
                int32_t l_s;
                l_s = tracker_tcp_rqst::teardown(l_rqst, l_ses, l_nconn, HTTP_STATUS_OK);
                // TODO -check status...
                UNUSED(l_s);
                return NTRNT_STATUS_DONE;
        }
        // -------------------------------------------------
        // STATE: CONNECTED
        // -------------------------------------------------
        case nconn::NC_STATE_CONNECTED:
        {
                switch(a_conn_mode)
                {
                // -----------------------------------------
                // read...
                // -----------------------------------------
                case EVR_MODE_READ:
                {
                        nbq *l_in_q = NULL;
                        if (l_rqst)
                        {
                                l_in_q = l_rqst->m_in_q;
                        }
                        else
                        {
                                // for reading junk disassociated from upstream session
                                l_in_q = l_ses.m_orphan_in_q;
                                l_in_q->reset_write();
                        }
                        if (!l_in_q)
                        {
                                TRC_ERROR("l_in_q == NULL\n");
                                return NTRNT_STATUS_ERROR;
                        }
                        uint32_t l_read = 0;
                        int32_t l_s = nconn::NC_STATUS_OK;
                        char *l_buf = NULL;
                        uint64_t l_off = l_in_q->get_cur_write_offset();
                        l_s = l_nconn.nc_read(l_in_q, &l_buf, l_read);
                        //l_ses.m_stat.m_upsv_bytes_read += l_read;
                        NDBG_PRINT("nc_read: status[%d] l_read[%d]\n", l_s, (int)l_read);
                        // ---------------------------------
                        // handle error
                        // ---------------------------------
                        if (l_s != nconn::NC_STATUS_OK)
                        {
                        switch(l_s)
                        {
                        // ---------------------------------
                        // NC_STATUS_EOF
                        // ---------------------------------
                        case nconn::NC_STATUS_EOF:
                        {
                                if (l_rqst)
                                {
                                        NDBG_PRINT("%sDONE%s\n", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF);
                                        l_rqst->m_resp->show();
                                }
                                // disassociate connection
                                l_nconn.set_data(NULL);
                                int32_t l_s;
                                l_s = tracker_tcp_rqst::teardown(l_rqst, l_ses, l_nconn, HTTP_STATUS_OK);
                                // TODO -check status...
                                UNUSED(l_s);
                                return NTRNT_STATUS_DONE;
                        }
                        // ---------------------------------
                        // NC_STATUS_ERROR
                        // ---------------------------------
                        case nconn::NC_STATUS_ERROR:
                        {
                                int32_t l_s;
                                l_s = tracker_tcp_rqst::teardown(l_rqst, l_ses, l_nconn, HTTP_STATUS_BAD_GATEWAY);
                                // TODO -check status...
                                UNUSED(l_s);
                                return NTRNT_STATUS_DONE;
                        }
                        // ---------------------------------
                        // READ_UNAVAILABLE
                        // ---------------------------------
                        case nconn::NC_STATUS_READ_UNAVAILABLE:
                        {
                                // -------------------------
                                // proxy back pressure
                                // -------------------------
                                if (l_rqst)
                                {
                                        //TRC_DEBUG("set_again(true): l_rqst: %p l_nconn: %p m_subr: %p path: %s\n",
                                        //                l_rqst,
                                        //                l_nconn,
                                        //                l_rqst->m_subr,
                                        //                l_rqst->m_subr->get_path().c_str());
                                        l_rqst->m_again = true;
                                        return NTRNT_STATUS_OK;
                                }
                                // TODO ???
                                break;
                        }
                        // ---------------------------------
                        // NC_STATUS_BREAK
                        // ---------------------------------
                        case nconn::NC_STATUS_BREAK:
                        {
                                return NTRNT_STATUS_OK;
                        }
                        // ---------------------------------
                        // NC_STATUS_AGAIN
                        // ---------------------------------
                        case nconn::NC_STATUS_AGAIN:
                        {
                                if (!l_idle)
                                {
                                        return NTRNT_STATUS_OK;
                                }
                                l_nconn.set_data(NULL);
                                int32_t l_status;
                                l_status = l_ses.get_conn_pool().add_idle(&l_nconn);
                                if (l_status != NTRNT_STATUS_OK)
                                {
                                        TRC_ERROR("performing m_nconn_proxy_pool.add_idle(%p)\n", &l_nconn);
                                        return NTRNT_STATUS_ERROR;
                                }
                                return NTRNT_STATUS_OK;
                        }
                        // ---------------------------------
                        // default...
                        // ---------------------------------
                        default:
                        {
                                TRC_ERROR("unhandled connection state: %d\n", l_s);
                                int32_t l_s;
                                l_s = tracker_tcp_rqst::teardown(l_rqst, l_ses, l_nconn, HTTP_STATUS_BAD_GATEWAY);
                                // TODO -check status...
                                UNUSED(l_s);
                                return NTRNT_STATUS_DONE;
                        }
                        }
                        }
                        // ---------------------------------
                        // parse
                        // ---------------------------------
                        if ((l_read > 0) &&
                           l_rqst &&
                           l_rqst->m_resp &&
                           l_rqst->m_resp->m_http_parser)
                        {
                                http_msg *l_hmsg = static_cast<http_msg *>(l_rqst->m_resp);
                                size_t l_parse_status = 0;
                                //NDBG_PRINT("%sHTTP_PARSER%s: m_read_buf: %p, m_read_buf_idx: %d, l_bytes_read: %d\n",
                                //              ANSI_COLOR_BG_WHITE, ANSI_COLOR_OFF,
                                //              l_buf,
                                //              (int)l_off,
                                //              (int)l_read);
                                l_hmsg->m_cur_buf = l_buf;
                                l_hmsg->m_cur_off = l_off;
                                l_parse_status = http_parser_execute(l_hmsg->m_http_parser,
                                                                     l_hmsg->m_http_parser_settings,
                                                                     reinterpret_cast<const char *>(l_buf),
                                                                     l_read);
                                if (l_parse_status < (size_t)l_read)
                                {
                                        TRC_ERROR("Parse error.  Reason: %s: %s\n",
                                                   http_errno_name((enum http_errno)l_hmsg->m_http_parser->http_errno),
                                                   http_errno_description((enum http_errno)l_hmsg->m_http_parser->http_errno));
                                        //TRC_VERBOSE("teardown status: %d\n", HTTP_STATUS_BAD_GATEWAY);
                                        TRC_ERROR("unhandled connection state: %d\n", l_s);
                                        int32_t l_s;
                                        l_s = tracker_tcp_rqst::teardown(l_rqst, l_ses, l_nconn, HTTP_STATUS_BAD_GATEWAY);
                                        // TODO -check status...
                                        UNUSED(l_s);
                                        return NTRNT_STATUS_DONE;
                                }
                        }
                        // ---------------------------------
                        // handle completion
                        // ---------------------------------
                        if (l_rqst &&
                           l_rqst->m_resp &&
                           l_rqst->m_resp->m_complete)
                        {
                                // -------------------------
                                // Cancel timer
                                // -------------------------
                                l_rqst->cancel_evr_timer();
                                // TODO Check status
                                l_rqst->m_evr_timeout = NULL;
                                // -------------------------
                                // check can reuse
                                // -------------------------
                                bool l_hmsg_keep_alive = false;
                                if (l_rqst->m_resp)
                                {
                                        l_hmsg_keep_alive = l_rqst->m_resp->m_supports_keep_alives;
                                }
                                bool l_nconn_can_reuse = l_nconn.can_reuse();
                                bool l_keepalive = false;
                                // -------------------------
                                // complete request
                                // -------------------------
                                // log status
                                uint16_t l_status = HTTP_STATUS_OK;
                                if (l_rqst->m_resp)
                                {
                                        l_status = l_rqst->m_resp->get_status();
                                }
                                NDBG_PRINT("%sDONE%s\n", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF);
                                l_rqst->m_resp->show();
                                // -------------------------
                                // get body
                                // -------------------------
                                nbq* l_body = l_rqst->m_resp->get_body_q();
                                char* l_body_buf = nullptr;
                                uint64_t l_body_buf_len = l_body->read_avail();
                                l_body_buf = (char *)malloc(sizeof(char)*l_body_buf_len);
                                int64_t l_body_read = 0;
                                l_body_read = l_body->read(l_body_buf, l_body_buf_len);
                                bencode l_be;
                                int32_t l_be_status = NTRNT_STATUS_OK;
                                l_be_status = l_be.init(l_body_buf, l_body_buf_len);
                                l_be.display();
                                if (l_body_buf) { free(l_body_buf); l_body_buf = nullptr; }
                                if (l_body) { delete l_body; l_body = nullptr; }
                                // -------------------------
                                // set state to done
                                // -------------------------
                                l_rqst->m_state = tracker_tcp_rqst::STATE_NONE;
                                if (!l_nconn_can_reuse ||
                                   !l_keepalive ||
                                   !l_hmsg_keep_alive)
                                {
                                        TRC_VERBOSE("marking conn EOF: l_nconn_can_reuse: %d, l_keepalive: %d, l_hmsg_keep_alive: %d\n",
                                                    l_nconn_can_reuse,
                                                    l_keepalive,
                                                    l_hmsg_keep_alive);
                                        l_nconn.set_state_done();
                                        goto state_top;
                                }
                                // Give back rqst + in q
                                if (l_rqst->m_out_q)
                                {
                                        delete l_rqst->m_out_q;
                                        l_rqst->m_out_q = NULL;
                                }
                                if (l_rqst->m_resp)
                                {
                                        delete l_rqst->m_resp;
                                        l_rqst->m_resp = NULL;
                                }
                                delete l_rqst->m_in_q;
                                l_rqst->m_in_q = NULL;
                                // -------------------------
                                // set idle
                                // -------------------------
                                //l_rqst->m_nconn = NULL;
                                l_rqst = NULL;
                                l_idle = true;
                                goto state_top;
                        }
                        goto state_top;
                }
                // -----------------------------------------
                // write...
                // -----------------------------------------
                case EVR_MODE_WRITE:
                {
                        nbq *l_out_q = NULL;
                        if (l_rqst)
                        {
                                l_out_q = l_rqst->m_out_q;
                        }
                        if (!l_out_q ||
                           !l_out_q->read_avail())
                        {
                                return NTRNT_STATUS_OK;
                        }
                        // ---------------------------------
                        // write
                        // ---------------------------------
                        uint32_t l_written = 0;
                        int32_t l_s = nconn::NC_STATUS_OK;
                        l_s = l_nconn.nc_write(l_out_q, l_written);
                        //NDBG_PRINT("nc_write: status[%d] l_written[%d]\n", l_s, (int)l_written);
                        //l_ses.m_stat.m_upsv_bytes_written += l_written;
                        // ---------------------------------
                        // handle error
                        // ---------------------------------
                        if (l_s != nconn::NC_STATUS_OK)
                        {
                        switch(l_s)
                        {
                        // ---------------------------------
                        // NC_STATUS_EOF
                        // ---------------------------------
                        case nconn::NC_STATUS_EOF:
                        {
                                l_nconn.set_state_done();
                                goto state_top;
                        }
                        // ---------------------------------
                        // NC_STATUS_ERROR
                        // ---------------------------------
                        case nconn::NC_STATUS_ERROR:
                        {
                                //++(l_ses.m_stat.m_clnt_errors);
                                l_nconn.set_state_done();
                                goto state_top;
                        }
                        // ---------------------------------
                        // NC_STATUS_BREAK
                        // ---------------------------------
                        case nconn::NC_STATUS_BREAK:
                        {
                                return NTRNT_STATUS_OK;
                        }
                        // ---------------------------------
                        // NC_STATUS_AGAIN
                        // ---------------------------------
                        case nconn::NC_STATUS_AGAIN:
                        {
                                if (!l_idle)
                                {
                                        return NTRNT_STATUS_OK;
                                }
                                l_nconn.set_data(NULL);
                                int32_t l_status;
                                l_status = l_ses.get_conn_pool().add_idle(&l_nconn);
                                if (l_status != NTRNT_STATUS_OK)
                                {
                                        TRC_ERROR("performing m_nconn_proxy_pool.add_idle(%p)\n", &l_nconn);
                                        return NTRNT_STATUS_ERROR;
                                }
                                return NTRNT_STATUS_OK;
                        }
                        // ---------------------------------
                        // default...
                        // ---------------------------------
                        default:
                        {
                                TRC_ERROR("unhandled connection state: %d\n", l_s);
                                return NTRNT_STATUS_ERROR;
                        }
                        }
                        }
                        // stats
                        //l_ses.m_stat.m_upsv_bytes_read += l_read;
                        //l_ses.m_stat.m_upsv_bytes_written += l_written;
                        if (l_out_q->read_avail())
                        {
                                goto state_top;
                        }
                        return NTRNT_STATUS_OK;
                }
                // -----------------------------------------
                // TODO
                // -----------------------------------------
                default:
                {
                        return NTRNT_STATUS_ERROR;
                }
                }
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                //NDBG_PRINT("default\n");
                TRC_ERROR("unexpected conn state %d\n", l_nconn.get_state());
                return NTRNT_STATUS_ERROR;
        }
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
tracker_tcp_rqst::tracker_tcp_rqst(void):
        m_label(),
        m_scheme(SCHEME_NONE),
        m_port(0),
        m_state(STATE_NONE),
        m_host(),
        m_path(),
        m_verb("GET"),
        m_query_list(),
        m_timeout_ms(10000),
        m_last_active_ms(0),
        m_evr_timeout(NULL),
        m_evr_readable(NULL),
        m_evr_writeable(NULL),
        m_again(false),
        m_in_q(NULL),
        m_out_q(NULL),
        m_resp(NULL)
{
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
tracker_tcp_rqst::~tracker_tcp_rqst(void)
{
        if (m_resp)
        {
                delete m_resp;
                m_resp = NULL;
        }
        if (m_in_q)
        {
                delete m_in_q;
                m_in_q = NULL;
        }
        if (m_out_q)
        {
                delete m_out_q;
                m_out_q = NULL;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
const std::string &tracker_tcp_rqst::get_label(void)
{
        if (m_label.empty())
        {
                reset_label();
        }
        return m_label;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void tracker_tcp_rqst::reset_label(void)
{
        switch(m_scheme)
        {
        case SCHEME_NONE:
        {
                m_label += "none://";
                break;
        }
        case SCHEME_TCP:
        {
                m_label += "http://";
                break;
        }
        case SCHEME_TLS:
        {
                m_label += "https://";
                break;
        }
        default:
        {
                m_label += "default://";
                break;
        }
        }
        m_label += m_host;
        char l_port_str[16];
        snprintf(l_port_str, 16, ":%u", m_port);
        m_label += l_port_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
bool tracker_tcp_rqst::get_expect_resp_body_flag(void)
{
        if (m_verb == "HEAD")
        {
                return false;
        }
        else
        {
                return true;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int tracker_tcp_rqst::set_query(const std::string &a_key, const std::string &a_val)
{
        m_query_list.push_back(std::pair<std::string, std::string>(a_key, a_val));
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_tcp_rqst::serialize(nbq &ao_q)
{
        // -------------------------------------------------
        // make path
        // -------------------------------------------------
        std::string l_path;
        l_path = m_path;
        if (l_path.empty())
        {
                l_path = "/";
        }
        // -------------------------------------------------
        // add query string
        // -------------------------------------------------
        if (!(m_query_list.empty()))
        {
                l_path += "?";
        }
        for(auto && i_ql : m_query_list)
        {
                if (i_ql.first.empty() || i_ql.second.empty())
                {
                        continue;
                }
                l_path += i_ql.first.c_str();
                l_path += "=";
                l_path += i_ql.second.c_str();
                l_path += "&";
        }
        if (m_query_list.size())
        {
                l_path.pop_back();
        }
        // -------------------------------------------------
        // generate request string
        // -------------------------------------------------
        //NDBG_PRINT("HOST: %s PATH: %s\n", a_reqlet.m_url.m_host.c_str(), l_path_ref.c_str());
        int32_t l_len = 0;
        char l_buf[2048];
        l_len = snprintf(l_buf, sizeof(l_buf),
                        "%s %s HTTP/1.1",
                        m_verb.c_str(), l_path.c_str());
        NDBG_PRINT("request line: %.*s\n", l_len, l_buf);
        nbq_write_request_line(ao_q, l_buf, l_len);
        // -------------------------------------------------
        // accedpt
        // -------------------------------------------------
        nbq_write_header(ao_q, "Host", m_host.c_str());
        nbq_write_header(ao_q, "User-Agent", "ntrnt/0.0.0");
        nbq_write_header(ao_q, "Accept", "*/*");
        // -------------------------------------------------
        // body
        // -------------------------------------------------
        nbq_write_body(ao_q, NULL, 0);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_tcp_rqst::start(session &a_session)
{
        NDBG_PRINT("start...\n");
        int32_t l_s;
        std::string l_error;
        // -------------------------------------------------
        // set state to none
        // -------------------------------------------------
        m_state = tracker_tcp_rqst::STATE_NONE;
        // -------------------------------------------------
        // try get idle from proxy pool
        // -------------------------------------------------
        nconn_pool& l_conn_pool = a_session.get_conn_pool();
        nresolver& l_resolver = a_session.get_resolver();
        nconn *l_nconn = NULL;
        l_nconn = l_conn_pool.get_idle(get_label());
        if (!l_nconn)
        {
                NDBG_PRINT("l_nconn: %p\n", l_nconn);
                // -----------------------------------------
                // Check for available active connections
                // If we maxed out -try again later...
                // -----------------------------------------
                if (!l_conn_pool.get_active_available())
                {
                        return NTRNT_STATUS_AGAIN;
                }
                // Try fast
                host_info l_host_info;
                NDBG_PRINT("resolve: %s\n", m_host.c_str());
                l_s = l_resolver.lookup_tryfast(m_host,
                                                m_port,
                                                l_host_info);
                NDBG_PRINT("l_resolver: %d\n", l_s);
                if (l_s != NTRNT_STATUS_OK)
                {
                        // sync dns
                        l_s = l_resolver.lookup_sync(m_host, m_port, l_host_info);
                        if (l_s != NTRNT_STATUS_OK)
                        {
                                NDBG_PRINT("Error: performing lookup_sync\n");
                                //++m_stat.m_upsv_errors;
                                return NTRNT_STATUS_ERROR;
                        }
                        else
                        {
                                //++(m_stat.m_dns_resolved);
                        }
                }
                // -----------------------------------------
                // connection setup
                // -----------------------------------------
                l_nconn = l_conn_pool.get_new_active(get_label(), m_scheme);
                if (!l_nconn)
                {
                        //NDBG_PRINT("Returning NULL\n");
                        return NTRNT_STATUS_AGAIN;
                }
                l_nconn->set_ctx(this);
                // TODO make configurable
                l_nconn->set_num_reqs_per_conn(1000);
                //l_nconn->set_collect_stats(l_t_conf.m_collect_stats);
                l_nconn->setup_evr_fd(tracker_tcp_rqst::evr_fd_readable_cb,
                                      tracker_tcp_rqst::evr_fd_writeable_cb,
                                      tracker_tcp_rqst::evr_fd_error_cb);
                if (l_nconn->get_scheme() == SCHEME_TLS)
                {
                        SSL_CTX* l_ctx = a_session.get_client_ssl_ctx();
                        bool l_val = true;
                        _SET_NCONN_OPT((*l_nconn),nconn_tls::OPT_TLS_CTX, l_ctx, sizeof(l_ctx));
                        _SET_NCONN_OPT((*l_nconn), nconn_tls::OPT_TLS_SNI, &(l_val), sizeof(bool));
                        _SET_NCONN_OPT((*l_nconn), nconn_tls::OPT_TLS_HOSTNAME, m_host.c_str(), m_host.length());
                }
                l_nconn->set_host_info(l_host_info);
                //a_subr.m_host_info = l_host_info;
                // -----------------------------------------
                // Reset stats
                // -----------------------------------------
                //l_nconn->reset_stats();
                // stats
                //++m_stat.m_upsv_conn_started;
                //m_stat.m_pool_proxy_conn_active = m_nconn_proxy_pool.get_active_size();
        }
        // -------------------------------------------------
        // If we grabbed an idle connection spoof connect
        // time for stats
        // -------------------------------------------------
        else
        {
                // Reset stats
                //l_nconn->reset_stats();
                //if (l_nconn->get_collect_stats_flag())
                //{
                //        l_nconn->set_connect_start_time_us(get_time_us());
                //}
        }
        // -------------------------------------------------
        // setup
        // -------------------------------------------------
        m_evr_timeout = NULL;
        //m_nconn = l_nconn;
        l_nconn->set_data(this);
        l_nconn->set_evr_loop(a_session.get_evr_loop());
        // -------------------------------------------------
        // resp
        // -------------------------------------------------
        m_resp = new http_resp();
        m_resp->init();
        m_resp->m_http_parser->data = m_resp;
        m_resp->m_expect_resp_body_flag = get_expect_resp_body_flag();
        // -------------------------------------------------
        // in q
        // -------------------------------------------------
        m_in_q = a_session.get_nbq(NULL);
        m_resp->set_q(m_in_q);
        // -------------------------------------------------
        // out q
        // -------------------------------------------------
        if (!m_out_q)
        {
                m_out_q = a_session.get_nbq(NULL);
        }
        else
        {
                m_out_q->reset_read();
        }
        // -------------------------------------------------
        // create request
        // -------------------------------------------------
        l_s = serialize(*(m_out_q));
        if (l_s != NTRNT_STATUS_OK)
        {
                return tracker_tcp_rqst::evr_fd_error_cb(l_nconn);
        }
        // -------------------------------------------------
        // start writing request
        // -------------------------------------------------
        return tracker_tcp_rqst::evr_fd_writeable_cb(l_nconn);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_tcp_rqst::teardown(tracker_tcp_rqst *a_subr,
                            session &a_session,
                            nconn &a_nconn,
                            http_status_t a_status)
{
        NDBG_PRINT("%sTEARDOWN%s: a_nconn: %p a_status: %8d a_ups: %p\n",
                   ANSI_COLOR_FG_RED, ANSI_COLOR_OFF,
                   &a_nconn, a_status, a_subr);
        if (!a_subr)
        {
                if (a_session.get_conn_pool().release(&a_nconn) != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing m_nconn_proxy_pool.release: a_nconn: %p\n", &a_nconn);
                }
                return NTRNT_STATUS_OK;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_tcp_rqst::cancel_evr_timer(void)
{
        if (!m_evr_timeout)
        {
                return NTRNT_STATUS_OK;
        }
        m_evr_timeout = NULL;
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_tcp_rqst::evr_fd_readable_cb(void *a_data)
{
        return run_state_machine(a_data, EVR_MODE_READ);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_tcp_rqst::evr_fd_writeable_cb(void *a_data)
{
        return run_state_machine(a_data, EVR_MODE_WRITE);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_tcp_rqst::evr_fd_error_cb(void *a_data)
{
        return run_state_machine(a_data, EVR_MODE_ERROR);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_tcp_rqst::evr_event_timeout_cb(void *a_data)
{
        if (!a_data)
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // clear event
        // -------------------------------------------------
        nconn* l_nconn = static_cast<nconn*>(a_data);
        tracker_tcp_rqst *l_rqst = static_cast<tracker_tcp_rqst *>(l_nconn->get_data());
        if (l_rqst &&
            l_rqst->m_evr_timeout)
        {
                l_rqst->m_evr_timeout = NULL;
        }
        return run_state_machine(a_data, EVR_MODE_TIMEOUT);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_tcp_rqst::evr_event_readable_cb(void *a_data)
{
        if (!a_data)
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // clear event
        // -------------------------------------------------
        nconn* l_nconn = static_cast<nconn*>(a_data);
        tracker_tcp_rqst *l_rqst = static_cast<tracker_tcp_rqst *>(l_nconn->get_data());
        if (l_rqst &&
            l_rqst->m_evr_readable)
        {
                l_rqst->m_evr_readable = NULL;
        }
        NDBG_PRINT("readable\n");
        return run_state_machine(a_data, EVR_MODE_READ);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_tcp_rqst::evr_event_writeable_cb(void *a_data)
{
        if (!a_data)
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // clear event
        // -------------------------------------------------
        nconn* l_nconn = static_cast<nconn*>(a_data);
        tracker_tcp_rqst *l_rqst = static_cast<tracker_tcp_rqst *>(l_nconn->get_data());
        if (l_rqst &&
            l_rqst->m_evr_writeable)
        {
                l_rqst->m_evr_writeable = NULL;
        }
        return run_state_machine(a_data, EVR_MODE_WRITE);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
#if 0
void tracker_tcp_rqst::show(bool a_color)
{
        std::string l_host_color = "";
        std::string l_query_color = "";
        std::string l_header_color = "";
        std::string l_body_color = "";
        std::string l_off_color = "";
        if (a_color)
        {
                l_host_color = ANSI_COLOR_FG_BLUE;
                l_query_color = ANSI_COLOR_FG_MAGENTA;
                l_header_color = ANSI_COLOR_FG_GREEN;
                l_body_color = ANSI_COLOR_FG_YELLOW;
                l_off_color = ANSI_COLOR_OFF;
        }
        // Host
        NDBG_OUTPUT("%sUri%s:  %s\n", l_host_color.c_str(), l_off_color.c_str(), m_uri.c_str());
        NDBG_OUTPUT("%sPath%s: %s\n", l_host_color.c_str(), l_off_color.c_str(), m_path.c_str());
        // Query
        for(kv_list_map_t::iterator i_key = m_query.begin();
                        i_key != m_query.end();
            ++i_key)
        {
                NDBG_OUTPUT("%s%s%s: %s\n",
                                l_query_color.c_str(), i_key->first.c_str(), l_off_color.c_str(),
                                i_key->second.begin()->c_str());
        }

        // Headers
        for(kv_list_map_t::iterator i_key = m_headers.begin();
            i_key != m_headers.end();
            ++i_key)
        {
                NDBG_OUTPUT("%s%s%s: %s\n",
                                l_header_color.c_str(), i_key->first.c_str(), l_off_color.c_str(),
                                i_key->second.begin()->c_str());
        }
        // Body
        NDBG_OUTPUT("%sBody%s: %s\n", l_body_color.c_str(), l_off_color.c_str(), m_body.c_str());
}
#endif
} //namespace ns_ntrnt {
