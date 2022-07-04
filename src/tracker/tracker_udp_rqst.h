#ifndef _TRACKER_UDP_RQST_H
#define _TRACKER_UDP_RQST_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#if 0
// ---------------------------------------------------------
// internal
// ---------------------------------------------------------
#include "http/http_status.h"
#include "conn/scheme.h"
#include "support/data.h"
// ---------------------------------------------------------
// stl
// ---------------------------------------------------------
#include <string>
#include <list>
#endif
namespace ns_ntrnt {
#if 0
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class nbq;
class session;
class http_resp;
//! ----------------------------------------------------------------------------
//! tracker_udp_rqst
//! ----------------------------------------------------------------------------
class tracker_udp_rqst
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
        tracker_udp_rqst(void);
        ~tracker_udp_rqst();
        int set_query(const std::string &a_key, const std::string &a_val);
        int32_t serialize(nbq &ao_q);
        const std::string &get_label(void);
        void reset_label(void);
        int32_t start(session &a_session);
        bool get_expect_resp_body_flag(void);
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
        static int32_t teardown(tracker_udp_rqst *a_subr,
                                session &a_session,
                                nconn &a_nconn,
                                http_status_t a_status);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
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
        bool m_again;
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
        tracker_udp_rqst& operator=(const tracker_udp_rqst &);
        tracker_udp_rqst(const tracker_udp_rqst &);
};
#endif
} //namespace ns_ntrnt {
#endif
