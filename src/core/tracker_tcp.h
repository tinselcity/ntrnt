#ifndef _NTRNT_TRACKER_TCP_H
#define _NTRNT_TRACKER_TCP_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include <string>
#include "ntrnt/types.h"
#include "core/tracker.h"
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class http_resp;
class tracker_tcp_rqst;
class session;
class nbq;
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::list<tracker_tcp_rqst*> tracker_tcp_rqst_list_t;
//! ----------------------------------------------------------------------------
//! \class: tracker_tcp
//! ----------------------------------------------------------------------------
class tracker_tcp: public tracker {
public:
        // -------------------------------------------------
        // public types
        // -------------------------------------------------
        typedef std::list <tracker_tcp_rqst *> tcp_rqst_list_t;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        tracker_tcp(session& a_session);
        ~tracker_tcp(void);
        int32_t init(const char* a_str, size_t a_str_len);
        nbq *get_nbq(nbq *a_nbq);
        virtual int32_t announce(void);
        virtual int32_t scrape(void);
        int32_t handle_announce_response(http_resp& a_resp);
        int32_t handle_scrape_response(http_resp& a_resp);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        nbq *m_orphan_in_q;
        nbq *m_orphan_out_q;
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // disallow copy/assign
        tracker_tcp(const tracker_tcp&);
        tracker_tcp& operator=(const tracker_tcp&);
        // -------------------------------------------------
        // private static
        // -------------------------------------------------
        static int32_t rqst_dequeue(void *a_data);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        tcp_rqst_list_t m_rqst_list;
        tracker_tcp_rqst_list_t m_gc_tcp_rqst_list;
};
}
#endif
