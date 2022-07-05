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
#include "support/ndebug.h"
#include "support/trace.h"
#include "support/util.h"
#include "support/nbq.h"
#include "support/tls_util.h"
#include "core/torrent.h"
#include "core/session.h"
#include "conn/nconn.h"
#include "conn/nconn_tls.h"
#include "dns/nresolver.h"
#include "tracker/tracker.h"
#include "tracker/tracker_tcp_rqst.h"
#include "tracker/tracker_udp_rqst.h"
// ---------------------------------------------------------
// openssl includes
// ---------------------------------------------------------
#include <openssl/ssl.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _DEFAULT_NBQ_BLOCK_SIZE (4*1024)
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
session::session(const std::string& a_peer_id,
                 torrent& a_torrent):
        m_tcp_rqst_list(),
        m_orphan_in_q(NULL),
        m_orphan_out_q(NULL),
        m_is_initd(false),
        m_stopped(true),
        m_peer_id(a_peer_id),
        m_torrent(a_torrent),
        m_tracker_list(),
        // TODO make configurable ???
        m_conn_pool(1024 ,4096),
        m_nresolver(NULL),
        m_client_ssl_ctx(NULL),
        m_evr_loop_type(EVR_LOOP_EPOLL),
        m_evr_loop(NULL)
{
        m_orphan_in_q = get_nbq(NULL);
        m_orphan_out_q = get_nbq(NULL);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
session::~session(void)
{
        // -------------------------------------------------
        // tracker list
        // -------------------------------------------------
        for(auto && i_t : m_tracker_list)
        {
                if (i_t) { delete i_t; i_t = nullptr;}
        }
        // -------------------------------------------------
        // resolver
        // -------------------------------------------------
        if (m_nresolver)
        {
                delete m_nresolver;
                m_nresolver = NULL;
        }
        // -------------------------------------------------
        // evr loop
        // -------------------------------------------------
        if (m_evr_loop)
        {
                delete m_evr_loop;
                m_evr_loop = NULL;
        }
        // -------------------------------------------------
        // orphan q
        // -------------------------------------------------
        if (m_orphan_in_q)
        {
                delete m_orphan_in_q;
                m_orphan_in_q = NULL;
        }
        if (m_orphan_out_q)
        {
                delete m_orphan_out_q;
                m_orphan_out_q = NULL;
        }
        // -------------------------------------------------
        // tls cleanup
        // -------------------------------------------------
        if (m_client_ssl_ctx)
        {
                SSL_CTX_free(m_client_ssl_ctx);
                m_client_ssl_ctx = NULL;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::init(void)
{
        if (m_is_initd)
        {
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // SSL init...
        // -------------------------------------------------
        tls_init();
        std::string l_unused;
        // -------------------------------------------------
        // ssl client setup
        // -------------------------------------------------
        m_client_ssl_ctx = tls_init_ctx(
                l_unused,   // ctx cipher list str
                0,          // ctx options
                l_unused,   // ctx ca file
                l_unused,   // ctx ca path
                false,      // is server?
                l_unused,   // tls key
                l_unused,   // tls crt
                true);      // force h1 -for now
        if (!m_client_ssl_ctx)
        {
                TRC_ERROR("Error: performing ssl_init(client)\n");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // init resolver with cache
        // TODO make configurable
        // -------------------------------------------------
        m_nresolver = new nresolver();
        int32_t l_s;
        std::string l_ai_cache_file = NRESOLVER_DEFAULT_AI_CACHE_FILE;
        l_s = m_nresolver->init(true, l_ai_cache_file);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("Error performing resolver init with ai_cache: %s\n",
                                l_ai_cache_file.c_str());
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // setup evr loop
        // TODO Need to make epoll vector resizeable...
        // -------------------------------------------------
        m_evr_loop = new evr_loop(m_evr_loop_type, 512);
        if (!m_evr_loop)
        {
                TRC_ERROR("m_evr_loop == NULL\n");
                return NTRNT_STATUS_ERROR;
        }
        m_is_initd = true;
        return NTRNT_STATUS_OK;
}

//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::run(void)
{
        // -------------------------------------------------
        // init if not
        // -------------------------------------------------
        if (!m_is_initd)
        {
                int32_t l_s;
                l_s = init();
                if (l_s != NTRNT_STATUS_OK)
                {
                        return NTRNT_STATUS_ERROR;
                }
        }
        NDBG_PRINT(": run...\n");
        // -------------------------------------------------
        // init trackers
        // -------------------------------------------------
        for(auto && i_a : m_torrent.get_accounce_list())
        {
                int32_t l_s;
                const std::string& l_a = i_a;
                tracker* l_t;
                l_s = init_tracker_w_url(&l_t, l_a.c_str(), l_a.length());
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_WARN("error initializing tracker with announce: %s", l_a.c_str());
                        if (l_t) { delete l_t; l_t = nullptr; }
                        continue;
                }
                m_tracker_list.push_back(l_t);
        }
        // -------------------------------------------------
        // send announce
        // -------------------------------------------------
        for(auto && i_t : m_tracker_list)
        {
                int32_t l_s;
                NDBG_PRINT(": announce: %s\n", i_t->str().c_str());
                l_s = i_t->announce(*this, m_torrent);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_WARN("performing send announce for: %s", i_t->str().c_str());
                        continue;
                }
        }
        // -------------------------------------------------
        // run
        // -------------------------------------------------
#if 0
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        int32_t l_s;
        l_s = init();
        if (l_s != STATUS_OK)
        {
                TRC_ERROR("Error performing init.\n");
                return NULL;
        }
        m_stopped = false;
        // -------------------------------------------------
        // start stats
        // -------------------------------------------------
        m_stat.clear();
        if (m_t_conf->m_stat_update_ms)
        {
                // Add timers...
                void *l_timer = NULL;
                add_timer(m_t_conf->m_stat_update_ms,
                          s_stat_update,
                          this,
                          &l_timer);
        }
#endif
        // -------------------------------------------------
        // run
        // -------------------------------------------------
        m_stopped = false;
        while(!m_stopped)
        {
                // -----------------------------------------
                // run event loop
                // -----------------------------------------
                int32_t l_s;
                NDBG_PRINT("run\n");
                //++m_stat.m_total_run;
                l_s = m_evr_loop->run();
                if (l_s != NTRNT_STATUS_OK)
                {
                        // TODO log error
                }
                // -----------------------------------------
                // reap inactive conns
                // TODO -do less frequently???
                // -----------------------------------------
                m_conn_pool.reap();
        }
        NDBG_PRINT("stopped\n");
        m_stopped = true;
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void session::signal(void)
{
        int32_t l_status;
        l_status = m_evr_loop->signal();
        if (l_status != NTRNT_STATUS_OK)
        {
                // TODO ???
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void session::stop(void)
{
        m_stopped = true;
        signal();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::enqueue(tracker_tcp_rqst& a_rqst)
{
        // -------------------------------------------------
        // enqueue
        // -------------------------------------------------
        a_rqst.m_state = tracker_tcp_rqst::STATE_QUEUED;
        m_tcp_rqst_list.push_back(&a_rqst);
        // -------------------------------------------------
        // queue event
        // TODO -make 0 a define like EVR_EVENT_QUEUE_NOW
        // -------------------------------------------------
        int32_t l_s;
        evr_event *l_event = nullptr;
        l_s = m_evr_loop->add_event(0, tcp_rqst_dequeue, this, &l_event);
        // TODO CHECK STATUS!!!
        (void)l_s;
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::enqueue(tracker_udp_rqst& a_rqst)
{
        // -------------------------------------------------
        // enqueue
        // -------------------------------------------------
        a_rqst.m_state = tracker_udp_rqst::STATE_QUEUED;
        m_udp_rqst_list.push_back(&a_rqst);
        // -------------------------------------------------
        // queue event
        // TODO -make 0 a define like EVR_EVENT_QUEUE_NOW
        // -------------------------------------------------
        int32_t l_s;
        evr_event *l_event = nullptr;
        l_s = m_evr_loop->add_event(0, udp_rqst_dequeue, this, &l_event);
        // TODO CHECK STATUS!!!
        (void)l_s;
        return NTRNT_STATUS_OK;
}

//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
nbq *session::get_nbq(nbq *a_nbq)
{
        // TODO make configurable
        uint32_t l_b_size = _DEFAULT_NBQ_BLOCK_SIZE;
        UNUSED(a_nbq);
        nbq *l_nbq = NULL;
        l_nbq = new nbq(l_b_size);
        return l_nbq;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void session::display(void)
{
        NDBG_OUTPUT("+-----------------------------------------------------------\n");
        NDBG_OUTPUT("|                    S E S S I O N \n");
        NDBG_OUTPUT("+-----------------------------------------------------------\n");
        NDBG_OUTPUT("| trackers: \n");
        for(auto && i_m : m_tracker_list)
        {
        NDBG_OUTPUT("|                %s\n", i_m->str().c_str());
        }
        NDBG_OUTPUT("+-----------------------------------------------------------\n");
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::tcp_rqst_dequeue(void *a_data)
{
        // TODO FIX!!!
        if (!a_data)
        {
                // TODO -log error???
                return NTRNT_STATUS_ERROR;
        }
        session &l_session = *(static_cast <session *>(a_data));
        NDBG_PRINT("%sSTART%s\n", ANSI_COLOR_BG_GREEN, ANSI_COLOR_OFF);
        NDBG_PRINT("l_session.m_tcp_rqst_list.size(): %d\n", (int)l_session.m_tcp_rqst_list.size());
        // -------------------------------------------------
        // dequeue until stopped or empty
        // -------------------------------------------------
        while(l_session.m_tcp_rqst_list.size() &&
              !l_session.get_stopped())
        {
                // -----------------------------------------
                // dequeue
                // -----------------------------------------
                if (!l_session.m_tcp_rqst_list.front())
                {
                        l_session.m_tcp_rqst_list.pop_front();
                        continue;
                }
                // -----------------------------------------
                // get front
                // -----------------------------------------
                NDBG_PRINT("%sSTART%s\n", ANSI_COLOR_BG_GREEN, ANSI_COLOR_OFF);
                tracker_tcp_rqst &l_rqst = *(l_session.m_tcp_rqst_list.front());
                l_session.m_tcp_rqst_list.pop_front();
                // -----------------------------------------
                // start
                // -----------------------------------------
                int32_t l_s = NTRNT_STATUS_OK;
                l_s = l_rqst.start(l_session);
                if (l_s == NTRNT_STATUS_AGAIN)
                {
                        // break since ran out of available connections
                        l_session.enqueue(l_rqst);
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
int32_t session::udp_rqst_dequeue(void *a_data)
{
        // TODO FIX!!!
        if (!a_data)
        {
                // TODO -log error???
                return NTRNT_STATUS_ERROR;
        }
        session &l_session = *(static_cast <session *>(a_data));
        NDBG_PRINT("%sSTART%s\n", ANSI_COLOR_BG_GREEN, ANSI_COLOR_OFF);
        NDBG_PRINT("l_session.m_udp_rqst_list.size(): %d\n", (int)l_session.m_udp_rqst_list.size());
        // -------------------------------------------------
        // dequeue until stopped or empty
        // -------------------------------------------------
        while(l_session.m_udp_rqst_list.size() &&
              !l_session.get_stopped())
        {
                // -----------------------------------------
                // dequeue
                // -----------------------------------------
                if (!l_session.m_udp_rqst_list.front())
                {
                        l_session.m_udp_rqst_list.pop_front();
                        continue;
                }
                // -----------------------------------------
                // get front
                // -----------------------------------------
                NDBG_PRINT("%sSTART%s\n", ANSI_COLOR_BG_GREEN, ANSI_COLOR_OFF);
                tracker_udp_rqst &l_rqst = *(l_session.m_udp_rqst_list.front());
                l_session.m_udp_rqst_list.pop_front();
                // -----------------------------------------
                // start
                // -----------------------------------------
                int32_t l_s = NTRNT_STATUS_OK;
                l_s = l_rqst.start(l_session);
                if (l_s == NTRNT_STATUS_AGAIN)
                {
                        // break since ran out of available connections
                        l_session.enqueue(l_rqst);
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
}
