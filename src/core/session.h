#ifndef _SESSION_H
#define _SESSION_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "ntrnt/types.h"
#include "evr/evr.h"
#include "support/nconn_pool.h"
#include <stdint.h>
#include <signal.h>
#include <string>
//! ----------------------------------------------------------------------------
//! ext fwd decl's
//! ----------------------------------------------------------------------------
typedef struct ssl_ctx_st SSL_CTX;
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class nbq;
class torrent;
class tracker;
class tracker_http_rqst;
class nresolver;
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::list<tracker*> tracker_list_t;
//! ----------------------------------------------------------------------------
//! \class: session
//! ----------------------------------------------------------------------------
class session {
public:
        // -------------------------------------------------
        // public types
        // -------------------------------------------------
        typedef std::list <tracker_http_rqst *> http_subr_list_t;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        session(const std::string& a_peer_id,
                torrent& a_torrent);
        ~session(void);
        int32_t init(void);
        int32_t run(void);
        void signal(void);
        void stop(void);
        int32_t enqueue(tracker_http_rqst& a_subr);
        void display(void);
        bool is_running(void) { return !m_stopped; }
        bool get_stopped(void) { return (bool)m_stopped; }
        nconn_pool& get_conn_pool(void) { return m_conn_pool; }
        nresolver& get_resolver(void) { return *m_nresolver; }
        SSL_CTX* get_client_ssl_ctx(void) { return m_client_ssl_ctx; }
        evr_loop *get_evr_loop(void) { return m_evr_loop; }
        nbq *get_nbq(nbq *a_nbq);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        http_subr_list_t m_http_subr_list;
        nbq *m_orphan_in_q;
        nbq *m_orphan_out_q;
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // disallow copy/assign
        session(const session&);
        session& operator=(const session&);
        int32_t subr_start(tracker_http_rqst &a_subr);
        // -------------------------------------------------
        // private static
        // -------------------------------------------------
        static int32_t http_subr_dequeue(void *a_data);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_is_initd;
        sig_atomic_t m_stopped;
        std::string m_peer_id;
        torrent& m_torrent;
        tracker_list_t m_tracker_list;
        nconn_pool m_conn_pool;
        nresolver *m_nresolver;
        SSL_CTX *m_client_ssl_ctx;
        // -------------------------------------------------
        //
        // -------------------------------------------------
        evr_loop_type_t m_evr_loop_type;
        evr_loop *m_evr_loop;
};
}
#endif
