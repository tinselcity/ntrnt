//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
// ---------------------------------------------------------
// external includes
// ---------------------------------------------------------
#include "ntrnt/def.h"
// ---------------------------------------------------------
// internal includes
// ---------------------------------------------------------
#include "support/trace.h"
#include "support/ndebug.h"
#include "support/data.h"
#include "support/util.h"
#include "support/net_util.h"
#include "support/nbq.h"
#include "support/sha1.h"
#include "conn/nconn.h"
#include "conn/nconn_tls.h"
#include "bencode/bencode.h"
#include "dns/nresolver.h"
#include "http/http_resp.h"
#include "http/http_resp_strs.h"
#include "core/session.h"
#include "core/tracker_tcp.h"
// ---------------------------------------------------------
// ext
// ---------------------------------------------------------
#include "http_parser/http_parser.h"
// ---------------------------------------------------------
// std
// ---------------------------------------------------------
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
// ---------------------------------------------------------
// stl
// ---------------------------------------------------------
#include <map>
#include <sstream>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _REQUEST_SIZE 16384
#define _DEFAULT_NBQ_BLOCK_SIZE (4*1024)
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! writing utilities
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nbq_write_request_line(nbq &ao_q, const char *a_buf, uint32_t a_len)
{
        ao_q.write(a_buf, a_len);
        ao_q.write("\r\n", strlen("\r\n"));
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nbq_write_status(nbq &ao_q, http_status_t a_status)
{
        http_resp_strs::code_resp_map_t::const_iterator i_r = http_resp_strs::S_CODE_RESP_MAP.find(a_status);
        if (i_r != http_resp_strs::S_CODE_RESP_MAP.end())
        {
                ao_q.write("HTTP/1.1 ", strlen("HTTP/1.1 "));
                char l_status_code_str[10];
                sprintf(l_status_code_str, "%u ", a_status);
                ao_q.write(l_status_code_str, strnlen(l_status_code_str, 10));
                ao_q.write(i_r->second.c_str(), i_r->second.length());
                ao_q.write("\r\n", strlen("\r\n"));
        }
        else
        {
                ao_q.write("HTTP/1.1 900 Missing\r\n", strlen("HTTP/1.1 900 Missing"));
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nbq_write_header(nbq &ao_q,
                         const char *a_key_buf, uint32_t a_key_len,
                         const char *a_val_buf, uint32_t a_val_len)
{
        ao_q.write(a_key_buf, a_key_len);
        ao_q.write(": ", 2);
        ao_q.write(a_val_buf, a_val_len);
        ao_q.write("\r\n", 2);
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nbq_write_header(nbq &ao_q,
                         const char *a_key_buf,
                         const char *a_val_buf)
{
        nbq_write_header(ao_q, a_key_buf, strlen(a_key_buf), a_val_buf, strlen(a_val_buf));
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nbq_write_body(nbq &ao_q, const char *a_buf, uint32_t a_len)
{
        ao_q.write("\r\n", strlen("\r\n"));
        ao_q.write(a_buf, a_len);
        return 0;
}
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                               R E Q U E S T
//! ****************************************************************************
//! ----------------------------------------------------------------------------
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
//! ----------------------------------------------------------------------------
//! tracker_tcp_rqst
//! ----------------------------------------------------------------------------
class tracker_tcp_rqst
{
public:
        // -------------------------------------------------
        // public types
        // -------------------------------------------------
        // state
        typedef enum {
                STATE_NONE = 0,
                STATE_QUEUED,
                STATE_DNS_LOOKUP,
                STATE_ACTIVE
        } state_t;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        tracker_tcp_rqst(tracker_tcp& a_tracker);
        ~tracker_tcp_rqst();
        int set_query(const std::string &a_key, const std::string &a_val);
        int32_t serialize(nbq &ao_q);
        const std::string &get_label(void);
        void reset_label(void);
        int32_t start(session &a_session);
        tracker_tcp& get_tracker(void) { return m_tracker; }
        // -------------------------------------------------
        // Public Static (class) methods
        // -------------------------------------------------
        static int32_t evr_fd_readable_cb(void *a_data);
        static int32_t evr_fd_writeable_cb(void *a_data);
        static int32_t evr_fd_error_cb(void *a_data);
        static int32_t evr_event_timeout_cb(void *a_data);
        static int32_t evr_event_readable_cb(void *a_data);
        static int32_t evr_event_writeable_cb(void *a_data);
        int32_t cancel_evr_timer(void);
        static int32_t teardown(tracker_tcp_rqst *a_rqst,
                                nconn &a_nconn,
                                http_status_t a_status);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        tracker_tcp& m_tracker;
        bool m_scrape;
        state_t m_state;
        // -------------------------------------------------
        // properties
        // -------------------------------------------------
        std::string m_label;
        scheme_t m_scheme;
        uint16_t m_port;
        std::string m_host;
        std::string m_path;
        std::string m_verb;
        kv_list_t m_query_list;
        // -------------------------------------------------
        // event properties
        // -------------------------------------------------
        uint32_t m_timeout_ms;
        uint64_t m_last_active_ms;
        evr_event_t *m_evr_timeout;
        evr_event_t *m_evr_readable;
        evr_event_t *m_evr_writeable;
        nconn* m_nconn;
        // -------------------------------------------------
        // buffer queues
        // -------------------------------------------------
        nbq *m_in_q;
        nbq *m_out_q;
        // -------------------------------------------------
        // resp
        // -------------------------------------------------
        http_resp *m_resp;
private:
        // -------------------------------------------------
        // private  methods
        // -------------------------------------------------
        // Disallow copy/assign
        tracker_tcp_rqst& operator=(const tracker_tcp_rqst &);
        tracker_tcp_rqst(const tracker_tcp_rqst &);
};
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t run_state_machine(void *a_data, evr_mode_t a_conn_mode)
{
        //NDBG_PRINT("RUN a_conn_mode: %d a_data: %p\n", a_conn_mode, a_data);
        //CHECK_FOR_NULL_ERROR(a_data);
        // TODO -return OK for a_data == nullptr
        if (!a_data)
        {
                return NTRNT_STATUS_OK;
        }
        nconn &l_nconn = *(static_cast<nconn*>(a_data));
        // -------------------------------------------------
        // check for cancelled
        // -------------------------------------------------
        if (l_nconn.get_status() == CONN_STATUS_CANCELLED)
        {
                return NTRNT_STATUS_DONE;
        }
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
                l_s = tracker_tcp_rqst::teardown(l_rqst, l_nconn, HTTP_STATUS_BAD_GATEWAY);
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
                        TRC_ERROR("a_conn_mode[%d]\n", a_conn_mode);
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
                        l_s = tracker_tcp_rqst::teardown(l_rqst, l_nconn, HTTP_STATUS_BAD_GATEWAY);
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
        // --------------------------------------------------
        // **************************************************
        // state machine
        // **************************************************
        // --------------------------------------------------
        //NDBG_PRINT("%sRUN_STATE_MACHINE%s: CONN[%p] STATE[%d] MODE: %d --START\n",
        //            ANSI_COLOR_BG_YELLOW, ANSI_COLOR_OFF, &l_nconn, l_nconn.get_state(), a_conn_mode);
state_top:
        //NDBG_PRINT("%sRUN_STATE_MACHINE%s: CONN[%p] STATE[%d] MODE: %d\n",
        //           ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, &l_nconn, l_nconn.get_state(), a_conn_mode);
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
                //NDBG_PRINT("%sConnecting%s: host: %s\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, l_nconn.m_label.c_str());
                int32_t l_s;
                l_s = l_nconn.ncconnect();
                //NDBG_PRINT("%sConnecting%s: ncconnect: %d\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, l_s);
                if (l_s == nconn::NC_STATUS_ERROR)
                {
                        int32_t l_s;
                        l_s = tracker_tcp_rqst::teardown(l_rqst, l_nconn, HTTP_STATUS_BAD_GATEWAY);
                        // TODO -check status...
                        UNUSED(l_s);
                        return NTRNT_STATUS_DONE;
                }
                if (l_nconn.is_connecting())
                {
                        //NDBG_PRINT("Still connecting...\n");
                        return NTRNT_STATUS_OK;
                }
                //NDBG_PRINT("%sConnected%s: label: %s\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, l_nconn.m_label.c_str());
                //TRC_DEBUG("Connected: label: %s\n", l_nconn.m_label.c_str());
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
                l_s = tracker_tcp_rqst::teardown(l_rqst, l_nconn, HTTP_STATUS_OK);
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
                        nbq *l_in_q = nullptr;
                        if (l_rqst)
                        {
                                l_in_q = l_rqst->m_in_q;
                        }
                        else
                        {
                                // for reading junk disassociated from upstream session
                                l_in_q = l_rqst->m_tracker.m_orphan_in_q;
                                l_in_q->reset_write();
                        }
                        if (!l_in_q)
                        {
                                TRC_ERROR("l_in_q == nullptr\n");
                                return NTRNT_STATUS_ERROR;
                        }
                        uint32_t l_read = 0;
                        int32_t l_s = nconn::NC_STATUS_OK;
                        char *l_buf = nullptr;
                        uint64_t l_off = l_in_q->get_cur_write_offset();
                        l_s = l_nconn.nc_read(l_in_q, &l_buf, l_read);
                        //l_ses.m_stat.m_upsv_bytes_read += l_read;
                        //NDBG_PRINT("nc_read: status[%d] l_read[%d]\n", l_s, (int)l_read);
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
                                // disassociate connection
                                l_nconn.set_data(nullptr);
                                int32_t l_s;
                                l_s = tracker_tcp_rqst::teardown(l_rqst, l_nconn, HTTP_STATUS_OK);
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
                                l_s = tracker_tcp_rqst::teardown(l_rqst, l_nconn, HTTP_STATUS_BAD_GATEWAY);
                                // TODO -check status...
                                UNUSED(l_s);
                                return NTRNT_STATUS_DONE;
                        }
                        // ---------------------------------
                        // READ_UNAVAILABLE
                        // ---------------------------------
                        case nconn::NC_STATUS_READ_UNAVAILABLE:
                        {
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
                                return NTRNT_STATUS_OK;
                        }
                        // ---------------------------------
                        // default...
                        // ---------------------------------
                        default:
                        {
                                TRC_ERROR("unhandled connection state: %d\n", l_s);
                                int32_t l_s;
                                l_s = tracker_tcp_rqst::teardown(l_rqst, l_nconn, HTTP_STATUS_BAD_GATEWAY);
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
                                        l_s = tracker_tcp_rqst::teardown(l_rqst, l_nconn, HTTP_STATUS_BAD_GATEWAY);
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
                                l_rqst->m_evr_timeout = nullptr;
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
                                if (l_rqst->m_resp)
                                {
                                        if (l_rqst->m_scrape)
                                        {
                                                int32_t l_hs;
                                                l_hs = l_rqst->m_tracker.handle_scrape_response(*(l_rqst->m_resp));
                                                UNUSED(l_hs);
                                                // TODO check resp
                                        }
                                        else
                                        {
                                                int32_t l_hs;
                                                l_hs = l_rqst->m_tracker.handle_announce_response(*(l_rqst->m_resp));
                                                UNUSED(l_hs);
                                                // TODO check resp
                                        }
                                }
                                // log status
                                uint16_t l_status = HTTP_STATUS_OK;
                                if (l_rqst->m_resp)
                                {
                                        l_status = l_rqst->m_resp->get_status();
                                }
                                UNUSED(l_status);
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
                                        l_rqst->m_out_q = nullptr;
                                }
                                if (l_rqst->m_resp)
                                {
                                        delete l_rqst->m_resp;
                                        l_rqst->m_resp = nullptr;
                                }
                                if (l_rqst->m_in_q)
                                {
                                        delete l_rqst->m_in_q;
                                        l_rqst->m_in_q = nullptr;
                                }
                                // -------------------------
                                // set idle
                                // -------------------------
                                //l_rqst->m_nconn = nullptr;
                                l_rqst = nullptr;
                                goto state_top;
                        }
                        goto state_top;
                }
                // -----------------------------------------
                // write...
                // -----------------------------------------
                case EVR_MODE_WRITE:
                {
                        nbq *l_out_q = nullptr;
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
tracker_tcp_rqst::tracker_tcp_rqst(tracker_tcp& a_tracker):
        m_tracker(a_tracker),
        m_scrape(false),
        m_state(STATE_NONE),
        m_label(),
        m_scheme(SCHEME_NONE),
        m_port(0),
        m_host(),
        m_path(),
        m_verb("GET"),
        m_query_list(),
        m_timeout_ms(10000),
        m_last_active_ms(0),
        m_evr_timeout(nullptr),
        m_evr_readable(nullptr),
        m_evr_writeable(nullptr),
        m_nconn(nullptr),
        m_in_q(nullptr),
        m_out_q(nullptr),
        m_resp(nullptr)
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
                m_resp = nullptr;
        }
        if (m_in_q)
        {
                delete m_in_q;
                m_in_q = nullptr;
        }
        if (m_out_q)
        {
                delete m_out_q;
                m_out_q = nullptr;
        }
        if (m_nconn)
        {
                delete m_nconn;
                m_nconn = nullptr;
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
        //NDBG_PRINT("request line: %.*s\n", l_len, l_buf);
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
        nbq_write_body(ao_q, nullptr, 0);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_tcp_rqst::start(session &a_session)
{
        int32_t l_s;
        std::string l_error;
        // -------------------------------------------------
        // set state to none
        // -------------------------------------------------
        m_state = tracker_tcp_rqst::STATE_NONE;
        // -------------------------------------------------
        // try get idle from proxy pool
        // -------------------------------------------------
        nresolver& l_resolver = a_session.get_resolver();
        //NDBG_PRINT("l_nconn: %p\n", l_nconn);
        // Try fast
        host_info l_host_info;
        //NDBG_PRINT("resolve: %s\n", m_host.c_str());
        l_s = l_resolver.lookup_tryfast(m_host,
                                        m_port,
                                        l_host_info);
        //NDBG_PRINT("l_resolver: %d\n", l_s);
        if (l_s != NTRNT_STATUS_OK)
        {
                // sync dns
                l_s = l_resolver.lookup_sync(m_host, m_port, l_host_info);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("Error: performing lookup_sync\n");
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
        if (m_nconn) { delete m_nconn; m_nconn = nullptr; }
        if (m_scheme == SCHEME_TCP) { m_nconn = new nconn_tcp(); }
        else if (m_scheme == SCHEME_TLS) { m_nconn = new nconn_tls(); }
        if (!m_nconn)
        {
                //NDBG_PRINT("Returning nullptr\n");
                return NTRNT_STATUS_AGAIN;
        }
        m_nconn->set_label(m_label);
        // TODO make configurable
        m_nconn->set_num_reqs_per_conn(1000);
        //l_nconn->set_collect_stats(l_t_conf.m_collect_stats);
        m_nconn->setup_evr_fd(tracker_tcp_rqst::evr_fd_readable_cb,
                              tracker_tcp_rqst::evr_fd_writeable_cb,
                              tracker_tcp_rqst::evr_fd_error_cb);
        if (m_nconn->get_scheme() == SCHEME_TLS)
        {
                SSL_CTX* l_ctx = a_session.get_client_ssl_ctx();
                bool l_val = true;
                _SET_NCONN_OPT((*m_nconn),nconn_tls::OPT_TLS_CTX, l_ctx, sizeof(l_ctx));
                _SET_NCONN_OPT((*m_nconn), nconn_tls::OPT_TLS_SNI, &(l_val), sizeof(bool));
                _SET_NCONN_OPT((*m_nconn), nconn_tls::OPT_TLS_HOSTNAME, m_host.c_str(), m_host.length());
        }
        m_nconn->set_host_info(l_host_info);
        //a_rqst.m_host_info = l_host_info;
        // -----------------------------------------
        // Reset stats
        // -----------------------------------------
        //l_nconn->reset_stats();
        // stats
        //++m_stat.m_upsv_conn_started;
        //m_stat.m_pool_proxy_conn_active = m_nconn_proxy_pool.get_active_size();
        // -------------------------------------------------
        // setup
        // -------------------------------------------------
        m_evr_timeout = nullptr;
        //m_nconn = l_nconn;
        m_nconn->set_data(this);
        m_nconn->set_evr_loop(a_session.get_evr_loop());
        // -------------------------------------------------
        // resp
        // -------------------------------------------------
        m_resp = new http_resp();
        m_resp->init();
        m_resp->m_http_parser->data = m_resp;
        // -------------------------------------------------
        // in q
        // -------------------------------------------------
        m_in_q = m_tracker.get_nbq(nullptr);
        m_resp->set_q(m_in_q);
        // -------------------------------------------------
        // out q
        // -------------------------------------------------
        if (!m_out_q)
        {
                m_out_q = m_tracker.get_nbq(nullptr);
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
                return tracker_tcp_rqst::evr_fd_error_cb(m_nconn);
        }
        // -------------------------------------------------
        // start writing request
        // -------------------------------------------------
        return tracker_tcp_rqst::evr_fd_writeable_cb(m_nconn);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_tcp_rqst::teardown(tracker_tcp_rqst *a_rqst,
                                   nconn &a_nconn,
                                   http_status_t a_status)
{
        //NDBG_PRINT("%sTEARDOWN%s: a_nconn[%s]: %p session: %p a_status: %8d a_rqst: %p\n",
        //           ANSI_COLOR_FG_RED,
        //           ANSI_COLOR_OFF,
        //           a_nconn.get_label().c_str(),
        //           &a_nconn,
        //           &a_session,
        //           a_status,
        //           a_rqst);
        if (a_rqst &&
            a_rqst->m_nconn)
        {
                int32_t l_s;
                l_s = a_rqst->m_nconn->nc_cleanup();
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing conn cleanup");
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
int32_t tracker_tcp_rqst::cancel_evr_timer(void)
{
        if (!m_evr_timeout)
        {
                return NTRNT_STATUS_OK;
        }
        m_evr_timeout = nullptr;
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
                l_rqst->m_evr_timeout = nullptr;
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
                l_rqst->m_evr_readable = nullptr;
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
                l_rqst->m_evr_writeable = nullptr;
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
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                             T R A C K E R
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
tracker_tcp::tracker_tcp(session& a_session):
        tracker(a_session),
        m_orphan_in_q(nullptr),
        m_orphan_out_q(nullptr),
        m_rqst_list(),
        m_gc_tcp_rqst_list()
{
        m_orphan_in_q = get_nbq(nullptr);
        m_orphan_out_q = get_nbq(nullptr);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
tracker_tcp::~tracker_tcp(void)
{
        for(auto && i_r : m_gc_tcp_rqst_list)
        {
                if (i_r) { delete i_r; i_r = nullptr;}
        }
        // -------------------------------------------------
        // orphan q
        // -------------------------------------------------
        if (m_orphan_in_q)
        {
                delete m_orphan_in_q;
                m_orphan_in_q = nullptr;
        }
        if (m_orphan_out_q)
        {
                delete m_orphan_out_q;
                m_orphan_out_q = nullptr;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_tcp::announce(void)
{
        const std::string& l_ext_ip = m_session.get_ext_ip();
        std::string l_ipv4_enc;
        std::string l_ipv6_enc;
        // -------------------------------------------------
        // ipv4
        // -------------------------------------------------
        if (l_ext_ip.find(':') == std::string::npos)
        {
                http_escape(l_ipv4_enc, l_ext_ip, true);
        }
        // -------------------------------------------------
        // ipv6
        // -------------------------------------------------
        else
        {
                http_escape(l_ipv6_enc, l_ext_ip, true);
        }
        // -------------------------------------------------
        // create info hash
        // -------------------------------------------------
        char l_info_hash_encoded[64];
        encode_digest(l_info_hash_encoded, m_session.get_info_hash(), NTRNT_SHA1_SIZE);
        // -------------------------------------------------
        // port str
        // -------------------------------------------------
        char l_port_str[16];
        snprintf(l_port_str, 16, "%u", m_session.get_ext_port());
        // -------------------------------------------------
        // numwant str
        // -------------------------------------------------
        char l_numwant_str[16];
        snprintf(l_numwant_str, 16, "%u", NTRNT_SESSION_NUMWANT);
        // -------------------------------------------------
        // create request
        // -------------------------------------------------
        tracker_tcp_rqst *l_rqst = new tracker_tcp_rqst(*this);
        l_rqst->m_scheme = m_scheme;
        l_rqst->m_port = m_port;
        l_rqst->m_host = m_host;
        l_rqst->m_path = m_root;
        l_rqst->m_verb = "GET";
        // -------------------------------------------------
        // TODO -used for gc -fix!!!
        // -------------------------------------------------
        m_gc_tcp_rqst_list.push_back(l_rqst);
        // -------------------------------------------------
        // set query string
        // -------------------------------------------------
        // TODO -fix fields
        l_rqst->set_query("info_hash", l_info_hash_encoded);
        l_rqst->set_query("peer_id", m_session.get_peer_id().c_str());
        l_rqst->set_query("port", l_port_str);
        l_rqst->set_query("uploaded", "0");
        l_rqst->set_query("downloaded", "0");
        l_rqst->set_query("left", "1130114013");
        l_rqst->set_query("numwant", l_numwant_str);
        l_rqst->set_query("key", "8535250");
        l_rqst->set_query("compact", "1");
        l_rqst->set_query("supportcrypto", "1");
        l_rqst->set_query("event", "started");
        if (!l_ipv4_enc.empty())
        {
        l_rqst->set_query("ip", l_ipv4_enc);
        }
        else
        {
        l_rqst->set_query("ipv6", l_ipv6_enc);
        }
        // -------------------------------------------------
        // enqueue
        // -------------------------------------------------
        l_rqst->m_state = tracker_tcp_rqst::STATE_QUEUED;
        m_rqst_list.push_back(l_rqst);
        // -------------------------------------------------
        // queue event
        // TODO -make 0 a define like EVR_EVENT_QUEUE_NOW
        // -------------------------------------------------
        int32_t l_s;
        evr_event *l_event = nullptr;
        l_s = m_session.get_evr_loop()->add_event(0, rqst_dequeue, this, &l_event);
        UNUSED(l_s);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_tcp::scrape(void)
{
        // -------------------------------------------------
        // create info hash
        // -------------------------------------------------
        char l_info_hash_encoded[64];
        encode_digest(l_info_hash_encoded, m_session.get_info_hash(), NTRNT_SHA1_SIZE);
        // -------------------------------------------------
        // create request
        // -------------------------------------------------
        tracker_tcp_rqst *l_rqst = new tracker_tcp_rqst(*this);
        l_rqst->m_scrape = true;
        l_rqst->m_scheme = m_scheme;
        l_rqst->m_port = m_port;
        l_rqst->m_host = m_host;
        l_rqst->m_path = "/scrape";
        l_rqst->m_verb = "GET";
        // -------------------------------------------------
        // TODO -used for gc -fix!!!
        // -------------------------------------------------
        m_gc_tcp_rqst_list.push_back(l_rqst);
        // -------------------------------------------------
        // set query string
        // -------------------------------------------------
        // TODO -fix fields
        l_rqst->set_query("info_hash", l_info_hash_encoded);
        // -------------------------------------------------
        // enqueue
        // -------------------------------------------------
        l_rqst->m_state = tracker_tcp_rqst::STATE_QUEUED;
        m_rqst_list.push_back(l_rqst);
        // -------------------------------------------------
        // queue event
        // TODO -make 0 a define like EVR_EVENT_QUEUE_NOW
        // -------------------------------------------------
        int32_t l_s;
        evr_event *l_event = nullptr;
        l_s = m_session.get_evr_loop()->add_event(0, rqst_dequeue, this, &l_event);
        UNUSED(l_s);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_tcp::rqst_dequeue(void *a_data)
{
        // TODO FIX!!!
        if (!a_data)
        {
                // TODO -log error???
                return NTRNT_STATUS_ERROR;
        }
        tracker_tcp &l_tracker = *(static_cast <tracker_tcp *>(a_data));
        session &l_session = l_tracker.m_session;
        //NDBG_PRINT("%sSTART%s\n", ANSI_COLOR_BG_GREEN, ANSI_COLOR_OFF);
        //NDBG_PRINT("l_session.m_tcp_rqst_list.size(): %d\n", (int)l_session.m_tcp_rqst_list.size());
        // -------------------------------------------------
        // dequeue until stopped or empty
        // -------------------------------------------------
        tcp_rqst_list_t& l_list = l_tracker.m_rqst_list;
        while(l_list.size() &&
              !l_session.get_stopped())
        {
                // -----------------------------------------
                // dequeue
                // -----------------------------------------
                if (!l_list.front())
                {
                        l_list.pop_front();
                        continue;
                }
                // -----------------------------------------
                // get front
                // -----------------------------------------
                //NDBG_PRINT("%sSTART%s\n", ANSI_COLOR_BG_GREEN, ANSI_COLOR_OFF);
                tracker_tcp_rqst &l_rqst = *(l_list.front());
                l_list.pop_front();
                // -----------------------------------------
                // start
                // -----------------------------------------
                int32_t l_s = NTRNT_STATUS_OK;
                l_s = l_rqst.start(l_session);
                if (l_s == NTRNT_STATUS_AGAIN)
                {
                        // break since ran out of available connections
                        l_list.push_back(&l_rqst);
                        break;
                }
                else if (l_s != NTRNT_STATUS_OK)
                {
                        // TODO -log error???
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
nbq *tracker_tcp::get_nbq(nbq *a_nbq)
{
        // TODO make configurable
        uint32_t l_b_size = _DEFAULT_NBQ_BLOCK_SIZE;
        UNUSED(a_nbq);
        nbq *l_nbq = nullptr;
        l_nbq = new nbq(l_b_size);
        return l_nbq;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_tcp::handle_announce_response(http_resp& a_resp)
{
        uint64_t l_now_s = get_time_s();
        m_stat_last_announce_time_s = l_now_s;
        m_next_announce_s = l_now_s + NTRNT_SESSION_TRACKER_ANNOUNCE_S;
        ++m_stat_announce_num;
        //NDBG_PRINT("%sDONE%s\n", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF);
        //a_resp.show();
        // -------------------------------------------------
        // get body
        // -------------------------------------------------
        nbq* l_body = a_resp.get_body_q();
        // -------------------------------------------------
        // read body into flat buffer
        // -------------------------------------------------
        char* l_buf = nullptr;
        uint64_t l_buf_len = l_body->read_avail();
        l_buf = (char *)malloc(sizeof(char)*l_buf_len);
        int64_t l_body_read = l_body->read(l_buf, l_buf_len);
        UNUSED(l_body_read);
        // -------------------------------------------------
        // parse resp
        // -------------------------------------------------
        bdecode l_be;
        int32_t l_be_status = NTRNT_STATUS_OK;
        l_be_status = l_be.init(l_buf, l_buf_len);
        if (l_be_status != NTRNT_STATUS_OK)
        {
                TRC_ERROR("[HOST: %s] performing bdecode init w/", m_host.c_str());
                TRC_ALL(l_buf, l_buf_len);
                if (l_buf) { free(l_buf); l_buf = nullptr; }
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get peers in resp
        // -------------------------------------------------
        for(auto && i_m : l_be.m_dict)
        {
                const be_obj_t& i_obj = i_m.second;
                // -----------------------------------------
                // peers is "compact"
                // ref: https://wiki.theory.org/BitTorrentSpecification
                // (binary model) Instead of using dict,
                // peers value is string consisting of:
                // - multiples of 6 bytes
                //   - first 4 bytes are IP address
                //   - last 2 bytes are port number.
                // All in network (big endian) notation.
                // -----------------------------------------
                if ((i_m.first == "peers") &&
                    (i_obj.m_type == BE_OBJ_STRING))
                {
                        //NDBG_PRINT("[HOST: %s] peers: raw: %lu -- ipv4: %lu\n", m_host.c_str(), i_obj.m_len, i_obj.m_len/6);
                        for (size_t i_p = 0; i_p < i_obj.m_len/6; ++i_p)
                        {
                                off_t l_off = i_p*6;
                                uint8_t* l_buf = (uint8_t*)i_obj.m_ptr + l_off;
                                int32_t l_s;
                                l_s = m_session.add_peer_raw(AF_INET, l_buf, 6, NTRNT_PEER_FROM_TRACKER);
                                UNUSED(l_s);
                        }
                }
                else if ((i_m.first == "peers6") &&
                         (i_obj.m_type == BE_OBJ_STRING))
                {
                        //NDBG_PRINT("[HOST: %s] peers6: raw: %lu -- ipv6: %lu\n", m_host.c_str(), i_obj.m_len, i_obj.m_len/18);
                        for (size_t i_p = 0; i_p < i_obj.m_len/18; ++i_p)
                        {
                                off_t l_off = i_p*18;
                                uint8_t* l_buf = (uint8_t*)i_obj.m_ptr + l_off;
                                int32_t l_s;
                                l_s = m_session.add_peer_raw(AF_INET6, l_buf, 18, NTRNT_PEER_FROM_TRACKER);
                                UNUSED(l_s);
                        }
                }
        }
        // -------------------------------------------------
        // successfully got resp -set next announce
        // -------------------------------------------------
        m_next_announce_s = get_time_s() + NTRNT_SESSION_TRACKER_ANNOUNCE_S;
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if (l_buf) { free(l_buf); l_buf = nullptr; }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_tcp::handle_scrape_response(http_resp& a_resp)
{
        m_stat_last_scrape_time_s = get_time_s();
        ++m_stat_scrape_num;
        //NDBG_PRINT("%sDONE%s\n", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF);
        // -------------------------------------------------
        // get body
        // -------------------------------------------------
        nbq* l_body = a_resp.get_body_q();
        // -------------------------------------------------
        // read body into flat buffer
        // -------------------------------------------------
        char* l_buf = nullptr;
        uint64_t l_buf_len = l_body->read_avail();
        l_buf = (char *)malloc(sizeof(char)*l_buf_len);
        int64_t l_body_read = l_body->read(l_buf, l_buf_len);
        UNUSED(l_body_read);
        // -------------------------------------------------
        // parse resp
        // -------------------------------------------------
        bdecode l_be;
        int32_t l_be_status = NTRNT_STATUS_OK;
        l_be_status = l_be.init(l_buf, l_buf_len);
        if (l_be_status != NTRNT_STATUS_OK)
        {
                TRC_ERROR("[HOST: %s] performing bdecode init w/", m_host.c_str());
                TRC_ALL(l_buf, l_buf_len);
                if (l_buf) { free(l_buf); l_buf = nullptr; }
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get values in resp
        // -------------------------------------------------
        for(auto && i_m : l_be.m_dict)
        {
                const be_obj_t& i_obj = i_m.second;
                // -----------------------------------------
                // peers is "compact"
                // ref: https://wiki.theory.org/BitTorrentSpecification
                // (binary model) Instead of using dict,
                // peers value is string consisting of:
                // - multiples of 6 bytes
                //   - first 4 bytes are IP address
                //   - last 2 bytes are port number.
                // All in network (big endian) notation.
                // -----------------------------------------
                if ((i_m.first == "files") &&
                    (i_obj.m_type == BE_OBJ_DICT))
                {
                        const be_dict_t& l_files_dict = *((const be_dict_t*)i_obj.m_obj);
                        for(auto && i_f : l_files_dict)
                        {
                                const be_obj_t& ii_obj = i_f.second;
                                if (ii_obj.m_type != BE_OBJ_DICT)
                                {
                                        continue;
                                }
                                const be_dict_t& l_keys_dict = *((const be_dict_t*)ii_obj.m_obj);
                                for(auto && ii_f : l_keys_dict)
                                {
                                        const be_obj_t& iii_obj = ii_f.second;
                                        if (0) {}
                                        // -----------------
                                        // complete
                                        // -----------------
                                        else if(ii_f.first == "complete")
                                        {
                                                if (iii_obj.m_type != BE_OBJ_INT)
                                                {
                                                        continue;
                                                }
                                                const be_int_t& l_len = *((const be_int_t*)iii_obj.m_obj);
                                                m_stat_last_scrape_num_complete = (size_t)l_len;
                                        }
                                        // -----------------
                                        // complete
                                        // -----------------
                                        else if(ii_f.first == "downloaded")
                                        {
                                                if (iii_obj.m_type != BE_OBJ_INT)
                                                {
                                                        continue;
                                                }
                                                const be_int_t& l_len = *((const be_int_t*)iii_obj.m_obj);
                                                m_stat_last_scrape_num_downloaded = (size_t)l_len;
                                        }
                                        // -----------------
                                        // complete
                                        // -----------------
                                        else if(ii_f.first == "incomplete")
                                        {
                                                if (iii_obj.m_type != BE_OBJ_INT)
                                                {
                                                        continue;
                                                }
                                                const be_int_t& l_len = *((const be_int_t*)iii_obj.m_obj);
                                                m_stat_last_scrape_num_incomplete = (size_t)l_len;
                                        }
                                }
                        }
                }
        }
        // -------------------------------------------------
        // successfully got resp -set next announce
        // -------------------------------------------------
        m_next_announce_s = get_time_s() + NTRNT_SESSION_TRACKER_ANNOUNCE_S;
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if (l_buf) { free(l_buf); l_buf = nullptr; }
        return NTRNT_STATUS_OK;
}
}
