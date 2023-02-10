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
#include "core/session.h"
#include "core/peer.h"
#include "core/peer_mgr.h"
#include "core/pickr.h"
#include "support/btfield.h"
#include "support/net_util.h"
#include "support/ndebug.h"
#include "support/trace.h"
#include "support/geoip2_mmdb.h"
// ---------------------------------------------------------
// utp
// ---------------------------------------------------------
#include "libutp/utp.h"
// ---------------------------------------------------------
// std c++
// ---------------------------------------------------------
#include <unordered_map>
#include <vector>
#include <algorithm>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                        U T P   C A L L B A C K S
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static uint64 _pm_utp_log(utp_callback_arguments* a_args)
{
        // -------------------------------------------------
        // get peer manager
        // -------------------------------------------------
        peer_mgr* l_pm = static_cast<peer_mgr*>(utp_context_get_userdata(a_args->context));
        if (!l_pm)
        {
                TRC_ERROR("peer_mgr == null");
                return 0;
        }
        // TODO unused if trace not enabled???
        // TODO cap length with a_args->len
        NDBG_OUTPUT("[UTP_LOG] %s\n", a_args->buf);
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static uint64 _pm_utp_on_accept(utp_callback_arguments* a_args)
{
        // -------------------------------------------------
        // get peer manager
        // -------------------------------------------------
        peer_mgr* l_pm = static_cast<peer_mgr*>(utp_context_get_userdata(a_args->context));
        if (!l_pm)
        {
                TRC_ERROR("peer_mgr == null");
                return 0;
        }
        // -------------------------------------------------
        // accept
        // -------------------------------------------------
        int32_t l_s;
        l_s = l_pm->pm_utp_on_accept(a_args->socket);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing pm_utp_on_accept");
                return 0;
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static uint64 _pm_utp_on_sendto(utp_callback_arguments* a_args)
{
        // -------------------------------------------------
        // get peer manager
        // -------------------------------------------------
        peer_mgr* l_pm = static_cast<peer_mgr*>(utp_context_get_userdata(a_args->context));
        if (!l_pm)
        {
                TRC_ERROR("peer_mgr == null");
                return 0;
        }
        // -------------------------------------------------
        // sendto
        // -------------------------------------------------
        int32_t l_s;
        l_s = l_pm->pm_utp_sendto(a_args->buf, a_args->len, a_args->address, a_args->address_len);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing pm_utp_sendto");
                return 0;
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static uint64 _pm_utp_on_read(utp_callback_arguments* a_args)
{
        // -------------------------------------------------
        // get peer
        // -------------------------------------------------
        peer* l_peer = nullptr;
        if (!a_args->socket)
        {
                return 0;
        }
        l_peer = static_cast<peer*>(utp_get_userdata(a_args->socket));
        if (!l_peer)
        {
                return 0;
        }
        // -------------------------------------------------
        // on read
        // -------------------------------------------------
        l_peer->pr_utp_on_read(a_args->buf, a_args->len);
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static uint64 _pm_utp_get_read_buffer_size(utp_callback_arguments* a_args)
{
        // -------------------------------------------------
        // get peer
        // -------------------------------------------------
        peer* l_peer = nullptr;
        if (!a_args->socket)
        {
                return 0;
        }
        l_peer = static_cast<peer*>(utp_get_userdata(a_args->socket));
        if (!l_peer)
        {
                return 0;
        }
        // -------------------------------------------------
        // return sizeof in buffer
        // -------------------------------------------------
        return l_peer->pr_utp_get_read_buffer_size();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static uint64 _pm_utp_on_error(utp_callback_arguments* a_args)
{
        // -------------------------------------------------
        // get peer
        // -------------------------------------------------
        peer* l_peer = nullptr;
        if (!a_args->socket)
        {
                return 0;
        }
        l_peer = static_cast<peer*>(utp_get_userdata(a_args->socket));
        if (!l_peer)
        {
                return 0;
        }
        // -------------------------------------------------
        // on error
        // -------------------------------------------------
        l_peer->pr_utp_on_error(a_args->error_code);
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static uint64 _pm_utp_on_overhead_statistics(utp_callback_arguments* a_args)
{
        // -------------------------------------------------
        // get peer
        // -------------------------------------------------
        peer* l_peer = nullptr;
        if (!a_args->socket)
        {
                return 0;
        }
        l_peer = static_cast<peer*>(utp_get_userdata(a_args->socket));
        if (!l_peer)
        {
                return 0;
        }
        // -------------------------------------------------
        // on overhead stats
        // -------------------------------------------------
        l_peer->pr_utp_on_overhead_statistics(a_args->send, a_args->len);
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static uint64 _pm_utp_on_state_change(utp_callback_arguments* a_args)
{
        // -------------------------------------------------
        // get peer
        // -------------------------------------------------
        peer* l_peer = nullptr;
        if (!a_args->socket)
        {
                return 0;
        }
        l_peer = static_cast<peer*>(utp_get_userdata(a_args->socket));
        if (!l_peer)
        {
                return 0;
        }
        // -------------------------------------------------
        // on state change
        // -------------------------------------------------
        l_peer->pr_utp_on_state_change(a_args->state);
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t _pm_utp_check_timeouts(void *a_data)
{
        if(!a_data)
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // perform utp maintenance
        // -------------------------------------------------
        peer_mgr* l_pm = static_cast<peer_mgr*>(a_data);
        int32_t l_s;
        l_s = l_pm->pm_utp_check_timeouts();
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing check_utp_timeouts");
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
peer_mgr::peer_mgr(session& a_session):
        m_is_initd(false),
        m_session(a_session),
        m_mutex(),
        m_utp_ctx(nullptr),
        m_peer_vec(),
        m_peer_vec_v4(),
        m_peer_vec_v6(),
        m_peer_map(),
        m_peer_connected_vec(),
        m_peer_active_vec_v4(),
        m_peer_active_vec_v6(),
        m_cfg_max_conn(20),
        m_no_accept(false),
        m_peer_vec_idx(0),
        m_ctx_peer_map()
{
        pthread_mutex_init(&m_mutex, NULL);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
peer_mgr::~peer_mgr(void)
{
        // -------------------------------------------------
        // utp ctx
        // -------------------------------------------------
        if (m_utp_ctx)
        {
                utp_destroy(m_utp_ctx);
                m_utp_ctx = nullptr;
        }
        // -------------------------------------------------
        // peer_map
        // -------------------------------------------------
        for(auto && i_p : m_peer_vec)
        {
                peer* l_p = i_p;
                if (l_p) { delete l_p; l_p = nullptr;}
        }
        pthread_mutex_destroy(&m_mutex);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer_mgr::init(void)
{
        if (m_is_initd)
        {
                return NTRNT_STATUS_OK;
        }
        m_is_initd = true;
        // -------------------------------------------------
        // utp initialization
        // -------------------------------------------------
        // always version 2 ???
        m_utp_ctx = utp_init(2);
        if (!m_utp_ctx)
        {
                TRC_ERROR("performing utp_init");
                return NTRNT_STATUS_ERROR;
        }
        void* l_ptr = nullptr;
        l_ptr = utp_context_set_userdata(m_utp_ctx, this);
        UNUSED(l_ptr);
        // set callbacks
        utp_set_callback(m_utp_ctx, UTP_ON_ACCEPT, _pm_utp_on_accept);
        utp_set_callback(m_utp_ctx, UTP_SENDTO, _pm_utp_on_sendto);
        utp_set_callback(m_utp_ctx, UTP_ON_READ, _pm_utp_on_read);
        utp_set_callback(m_utp_ctx, UTP_GET_READ_BUFFER_SIZE, _pm_utp_get_read_buffer_size);
        utp_set_callback(m_utp_ctx, UTP_ON_ERROR, _pm_utp_on_error);
        utp_set_callback(m_utp_ctx, UTP_ON_OVERHEAD_STATISTICS, _pm_utp_on_overhead_statistics);
        utp_set_callback(m_utp_ctx, UTP_ON_STATE_CHANGE, _pm_utp_on_state_change);
        // tracing
//#ifdef UTP_DEBUG_LOGGING
#if 0
        utp_set_callback(m_utp_ctx, UTP_LOG, &_pm_utp_log);
        utp_context_set_option(m_utp_ctx, UTP_LOG_NORMAL, 1);
        utp_context_set_option(m_utp_ctx, UTP_LOG_MTU, 1);
        utp_context_set_option(m_utp_ctx, UTP_LOG_DEBUG, 1);
#else
        UNUSED(_pm_utp_log);
#endif
        // set recv buffer size?
        int32_t l_s;
        l_s = utp_context_set_option(m_utp_ctx, UTP_RCVBUF, NTRNT_SESSION_UTP_RECV_BUF_SIZE);
        if (l_s != 0)
        {
                TRC_ERROR("performing utp_context_set_option");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // *************************************************
        //           T I M E R (S)   K I C K O F F
        // *************************************************
        // -------------------------------------------------
        void *l_timer = NULL;
        l_s = m_session.add_timer((uint32_t)(NTRNT_SESSION_T_CHECK_TIMEOUTS_MS),
                                  _pm_utp_check_timeouts,
                                  (void *)this,
                                  &l_timer);
        UNUSED(l_s);
        UNUSED(l_timer);
        // -------------------------------------------------
        // done
        // -------------------------------------------------
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void peer_mgr::display(void)
{
        uint32_t l_states[16]  = { 0 };
        uint32_t l_choked = 0;
        for (auto && i_p : m_peer_map)
        {
                if (!i_p.second) { continue; }
                peer& l_p = *(i_p.second);
                ++l_states[l_p.get_state()];
                if (l_p.get_btp_am_interested() &&
                    l_p.get_btp_peer_choking())
                {
                        ++l_choked;
                }
        }
        NDBG_OUTPUT("PEERS");
        for (uint16_t i_s = 0; i_s <= peer::STATE_CONNECTED; ++i_s)
        {
#define _ELIF_STATE(_s) \
        else if (i_s == peer::STATE_##_s) { \
                NDBG_OUTPUT(" [%s]: %u", #_s, l_states[i_s]); \
        }
                if (0) {}
                _ELIF_STATE(NONE)
                _ELIF_STATE(UTP_CONNECTING)
                _ELIF_STATE(PHE_SETUP)
                _ELIF_STATE(PHE_CONNECTING)
                _ELIF_STATE(HANDSHAKING)
                _ELIF_STATE(CONNECTED)
        }
        NDBG_OUTPUT(" [ACTIVE]: %lu", m_peer_connected_vec.size());
        NDBG_OUTPUT(" [CHOKED]: %u\n", l_choked);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void peer_mgr::display_peers(void)
{
        NDBG_OUTPUT("peers: \n");
        for (auto && i_p : m_peer_map)
        {
                if (!i_p.second) { continue; }
                NDBG_PRINT("HOST: %s STATE: %d FROM: %d\n",
                           i_p.second->get_host().c_str(),
                           i_p.second->get_state(),
                           i_p.second->get_from());
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer_mgr::connect_peers(void)
{
        // -------------------------------------------------
        // check peer state
        // -------------------------------------------------
#if 0
        uint64_t l_now_s = get_time_s();
        for (auto && i_p : m_peer_connected_vec)
        {
                if (!i_p) { continue; }
                peer& l_p = *i_p;
                // -----------------------------------------
                // check for too many expired
                // -----------------------------------------
                uint64_t l_exp = l_p.get_stat_expired_br();
                if (l_exp > (uint64_t)l_p.get_ltep_reqq())
                {
                        TRC_WARN("[HOST: %s] [CLIENT: %s] [PEER: %s] seems down -removing from swarm [expired count: %u]",
                                 l_p.m_host.c_str(),
                                 l_p.m_btp_peer_str.c_str(),
                                 l_p.m_ltep_peer_id.c_str(),
                                 (unsigned int)l_exp);
                        l_p.shutdown(peer::ERROR_EXPIRED_BR);
                        continue;
                }
                // -----------------------------------------
                // check for idle
                // -----------------------------------------
                if (l_now_s > (l_p.m_stat_last_recvd_time_s + NTRNT_SESSION_PEER_MAX_IDLE_S))
                {
                        TRC_WARN("[HOST: %s] [CLIENT: %s] [PEER: %s] seems down -removing from swarm [last msg recvd: %u s ago]",
                                 l_p.m_host.c_str(),
                                 l_p.m_btp_peer_str.c_str(),
                                 l_p.m_ltep_peer_id.c_str(),
                                 (unsigned int)(l_now_s - l_p.m_stat_last_recvd_time_s));
                        l_p.shutdown(peer::ERROR_IDLE_TIMEOUT);
                        continue;
                }
        }
#endif
        // -------------------------------------------------
        // update swarm
        // -------------------------------------------------
        m_peer_connected_vec.clear();
        m_peer_active_vec_v4.clear();
        m_peer_active_vec_v6.clear();
        uint32_t l_states[16]  = { 0 };
        size_t l_inflight = 0;
        size_t l_active = 0;
        pthread_mutex_lock(&m_mutex);
        for (auto && i_p : m_peer_vec)
        {
                if (!i_p) { continue; }
                peer& l_p = *i_p;
                peer::state_t l_ps = l_p.get_state();
                // -----------------------------------------
                // stats
                // -----------------------------------------
                ++l_states[l_ps];
                l_p.m_stat_bytes_recv_per_s = (uint64_t)((double)(l_p.m_stat_bytes_recv - l_p.m_stat_bytes_recv_last) * (1000.0 / (double)(NTRNT_SESSION_T_CONNECT_PEERS_MS)));
                l_p.m_stat_bytes_recv_last = l_p.m_stat_bytes_recv;
                l_p.m_stat_bytes_sent_per_s = (uint64_t)((double)(l_p.m_stat_bytes_sent - l_p.m_stat_bytes_sent_last) * (1000.0 / (double)(NTRNT_SESSION_T_CONNECT_PEERS_MS)));
                l_p.m_stat_bytes_sent_last = l_p.m_stat_bytes_sent;
                // -----------------------------------------
                // update swarm
                // -----------------------------------------
                if (l_ps != peer::STATE_NONE)
                {
                        ++l_active;
                        const sockaddr_storage& l_sas = l_p.get_sas();
                        if (l_sas.ss_family == AF_INET)
                        {
                                m_peer_active_vec_v4.push_back(i_p);
                        }
                        else if(l_sas.ss_family == AF_INET6)
                        {
                                m_peer_active_vec_v6.push_back(i_p);
                        }
                        if (l_ps == peer::STATE_CONNECTED)
                        {
                                m_peer_connected_vec.push_back(i_p);
                        }
                        else
                        {
                                ++l_inflight;
                        }
                }
        }
        pthread_mutex_unlock(&m_mutex);
        // -------------------------------------------------
        // check num connected
        // -------------------------------------------------
        UNUSED(l_inflight);
        uint32_t l_st_connected = 0;
        l_st_connected += l_states[peer::STATE_CONNECTED];
        if (l_st_connected >= m_cfg_max_conn)
        {
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        // try connect to up to N peers per period from
        // list of potential peers
        // -------------------------------------------------
        if (l_active >= m_cfg_max_conn)
        {
                return NTRNT_STATUS_OK;
        }
        size_t l_num = m_cfg_max_conn - l_active;
        typedef std::vector <peer*> _peer_vector_t;
        _peer_vector_t l_pv;
        pthread_mutex_lock(&m_mutex);
        for (size_t i_pc = 0;
             (i_pc < m_peer_vec.size()) &&
             (l_pv.size() <= l_num);
             ++i_pc)
        {
                peer* i_p = m_peer_vec[m_peer_vec_idx];
                if (!i_p) { continue; }
                // -----------------------------------------
                // increment next idx
                // -----------------------------------------
                ++m_peer_vec_idx;
                if (m_peer_vec_idx >= m_peer_vec.size())
                {
                        m_peer_vec_idx = 0;
                }
                // -----------------------------------------
                // check for self
                // -----------------------------------------
                const std::string& l_host = i_p->get_host();
                if ((l_host == m_session.get_ext_address_v4()) ||
                    (l_host == m_session.get_ext_address_v6()))
                {
                        continue;
                }
                // -----------------------------------------
                // if state none add to candidate
                // -----------------------------------------
                peer::state_t l_st = i_p->get_state();
                if (l_st == peer::STATE_NONE)
                {
                        l_pv.push_back(i_p);
                }
        }
        pthread_mutex_unlock(&m_mutex);
        // -------------------------------------------------
        // start connections
        // -------------------------------------------------
        for (auto && i_p : l_pv)
        {
                if (!i_p) { continue; }
                // -----------------------------------------
                // push into active
                // -----------------------------------------
                const sockaddr_storage& l_sas = i_p->get_sas();
                if (l_sas.ss_family == AF_INET)
                {
                        m_peer_active_vec_v4.push_back(i_p);
                }
                else if(l_sas.ss_family == AF_INET6)
                {
                        m_peer_active_vec_v6.push_back(i_p);
                }
                // -----------------------------------------
                // connect
                // -----------------------------------------
                TRC_DEBUG("[HOST %s] CONNECT", i_p->get_host().c_str());
                int32_t l_s;
                l_s = i_p->connect();
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing peer connect");
                        i_p->shutdown(peer::ERROR_CONNECT);
                }
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer_mgr::set_geoip(peer& a_peer, const sockaddr_storage& a_sas)
{
        geoip2_mmdb* l_geoip2_mmdb = m_session.get_geoip2_mmdb();
        if (!l_geoip2_mmdb)
        {
                return NTRNT_STATUS_OK;
        }
        const char* l_cn = nullptr;
        uint32_t l_cn_len = 0;
        const char* l_city = nullptr;
        uint32_t l_city_len = 0;
        double l_lat = 0.0;
        double l_lon = 0.0;
        int32_t l_s;
        std::string l_ip_str = sas_to_ip_str(a_sas);
        l_s = l_geoip2_mmdb->get_geoip_data(&l_cn,
                                            l_cn_len,
                                            &l_city,
                                            l_city_len,
                                            l_lat,
                                            l_lon,
                                            l_ip_str.c_str(),
                                            l_ip_str.length());
        // set if success -soft fail...
        if (l_s == NTRNT_STATUS_OK)
        {
                if (l_cn && l_cn_len)
                {
                        a_peer.m_geoip2_country.assign(l_cn, l_cn_len);
                }
                if (l_city && l_city_len)
                {
                        a_peer.m_geoip2_city.assign(l_city, l_city_len);
                }
                a_peer.m_geoip2_lat = l_lat;
                a_peer.m_geoip2_lon = l_lon;
        }
        else
        {
                //TRC_ERROR("performing lookup for ip: %s", l_ip_str.c_str());
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer_mgr::validate_address(const sockaddr_storage& a_sas)
{
        uint16_t l_port = 0;
        // -------------------------------------------------
        // check blocklists
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        // ipv4
        // -------------------------------------------------
        if (a_sas.ss_family == AF_INET)
        {
                struct sockaddr_in* l_sin = (struct sockaddr_in*) &(a_sas);
                // -----------------------------------------
                // extract port
                // -----------------------------------------
                l_port = ntohs(l_sin->sin_port);
                // -----------------------------------------
                // check for martian
                // -----------------------------------------
#if 0
                const uint8_t* l_addr = (uint8_t*)(&(l_sin->sin_addr));
                if ((l_addr[0] == 0) ||
                    (l_addr[0] == 127) ||
                    ((l_addr[0] & 0xE0) == 0xE0))
                {
                        TRC_ERROR("address[%s] appears to be local", sas_to_str(a_sas).c_str());
                        return NTRNT_STATUS_ERROR;
                }
#endif
        }
        // -------------------------------------------------
        // ipv6
        // -------------------------------------------------
        else if(a_sas.ss_family == AF_INET6)
        {
                struct sockaddr_in6* l_sin6 = (struct sockaddr_in6*) &(a_sas);
                // -----------------------------------------
                // extract port
                // -----------------------------------------
                l_port = ntohs(l_sin6->sin6_port);
                // -----------------------------------------
                // check for v6 is linklocal
                // -----------------------------------------
                if (IN6_IS_ADDR_LINKLOCAL(&(l_sin6->sin6_addr)))
                {
                        TRC_ERROR("address[%s] ipv6 is linklocal", sas_to_str(a_sas).c_str());
                        return NTRNT_STATUS_ERROR;
                }
                // -----------------------------------------
                // check for v4 mapped ipv6
                // -----------------------------------------
                if (IN6_IS_ADDR_V4MAPPED(&(l_sin6->sin6_addr)))
                {
                        TRC_ERROR("address[%s] ipv6 is v4 mapped", sas_to_str(a_sas).c_str());
                        return NTRNT_STATUS_ERROR;
                }
                // -----------------------------------------
                // check for martian
                // -----------------------------------------
                static const uint16_t s_zeros[16] = {
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                };
                const uint8_t* l_addr = (uint8_t*)(&(l_sin6->sin6_addr));
                if ((l_addr[0] == 0xFF) ||
                    ((memcmp(l_addr, s_zeros, 15) == 0) &&
                     ((l_addr[15] == 0x00) ||
                      (l_addr[15] == 0x01))))
              {
                        TRC_ERROR("address[%s] ipv6 is default or unspecified", sas_to_str(a_sas).c_str());
                        return NTRNT_STATUS_ERROR;
              }
        }
        else
        {
                TRC_ERROR("address[%s] unrecognized address family: %d", sas_to_str(a_sas).c_str(), a_sas.ss_family);
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // check for zero port
        // -------------------------------------------------
        if (l_port == 0)
        {
                TRC_ERROR("address[%s] bad address port is zero", sas_to_str(a_sas).c_str());
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // check for self
        // -------------------------------------------------
        const std::string* l_self = nullptr;
        if (a_sas.ss_family == AF_INET)
        {
                l_self = &(m_session.get_ext_address_v4());
        }
        else if (a_sas.ss_family == AF_INET6)
        {
                l_self = &(m_session.get_ext_address_v6());
        }
        if (l_self &&
            !l_self->empty())
        {
                const std::string& l_addr = sas_to_str(a_sas);
                if (*l_self == l_addr)
                {
                        TRC_WARN("dropping peer appears to be self: %s", l_addr.c_str());
                        return NTRNT_STATUS_OK;
                }
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer_mgr::add_peer(const sockaddr_storage& a_sas,
                           peer_from_t a_from)
{
        int32_t l_s;
        // -------------------------------------------------
        // validate address
        // -------------------------------------------------
        // disable to allow for localhost testing
        l_s = validate_address(a_sas);
        if (l_s != NTRNT_STATUS_OK)
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // find
        // -------------------------------------------------
        if (peer_exists(a_sas))
        {
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // make new
        // -------------------------------------------------
        peer* l_peer = new peer(a_from, m_session, *this, a_sas);
        // -------------------------------------------------
        // geoip
        // -------------------------------------------------
        l_s = set_geoip(*l_peer, a_sas);
        UNUSED(l_s);
        // -------------------------------------------------
        // add to map
        // -------------------------------------------------
        add_peer(l_peer);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer_mgr::pm_utp_on_accept(utp_socket* a_utp_conn)

{
        int32_t l_s;
        // -------------------------------------------------
        // skip accept if not handling
        // -------------------------------------------------
        if (m_no_accept)
        {
                utp_close(a_utp_conn);
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // block if at max
        // -------------------------------------------------
        if (m_peer_connected_vec.size() >= m_cfg_max_conn)
        {
                utp_close(a_utp_conn);
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // get peer
        // -------------------------------------------------
        struct sockaddr_storage l_sas;
        struct sockaddr* l_sa = (struct sockaddr*)(&l_sas);
        socklen_t l_sa_len = sizeof(l_sas);
        l_s = utp_getpeername(a_utp_conn, l_sa, &l_sa_len);
        if (l_s != 0)
        {
                TRC_ERROR("performing utp_getpeername");
                utp_close(a_utp_conn);
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get by family
        // -------------------------------------------------
        struct sockaddr_storage l_psas;
        if (l_sa->sa_family == AF_INET)
        {
                l_psas.ss_family = AF_INET;
                memcpy(&l_psas, (const void*)(l_sa), sizeof(struct sockaddr_in));
        }
        else if (l_sa->sa_family == AF_INET6)
        {
                l_psas.ss_family = AF_INET6;
                memcpy(&l_psas, (const void*)(l_sa), sizeof(struct sockaddr_in6));
        }
        else
        {
                TRC_ERROR("unrecognized address family: %u len: %u",
                          l_sa->sa_family, l_sa_len);
                utp_close(a_utp_conn);
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate address
        // -------------------------------------------------
        // disable to allow for localhost testing
        l_s = validate_address(l_psas);
        if (l_s != NTRNT_STATUS_OK)
        {
                utp_close(a_utp_conn);
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // find
        // -------------------------------------------------
        if (peer_exists(l_psas))
        {
                utp_close(a_utp_conn);
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // make new
        // -------------------------------------------------
        peer* l_peer = new peer(NTRNT_PEER_FROM_INBOUND, m_session, *this, l_psas);
        l_s = l_peer->accept_utp(a_utp_conn);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing accept_utp");
                utp_set_userdata(a_utp_conn, nullptr);
                if (l_peer) { delete l_peer; l_peer = nullptr; }
                utp_close(a_utp_conn);
                return NTRNT_STATUS_OK;
        }
        l_peer->set_state(peer::STATE_PHE_SETUP);
        // -------------------------------------------------
        // geoip
        // -------------------------------------------------
        l_s = set_geoip(*l_peer, l_psas);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing set_geoip");
        }
        // -------------------------------------------------
        // add to map
        // -------------------------------------------------
        add_peer(l_peer);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer_mgr::pm_utp_sendto(const uint8_t* a_buf,
                                size_t a_len,
                                const struct sockaddr* a_sa,
                                socklen_t a_socklen)
{
        int l_fd = -1;
        if(a_sa->sa_family == AF_INET)
        {
                l_fd = m_session.get_udp_fd();
        }
        else if(a_sa->sa_family == AF_INET6)
        {
                l_fd = m_session.get_udp6_fd();
        }
        else
        {
                TRC_ERROR("unknown family: %d", a_sa->sa_family);
                return NTRNT_STATUS_ERROR;
        }
        int l_s;
        errno = 0;
        //NDBG_PRINT("[SENDTO] [LEN: %lu]\n", a_len);
        //NDBG_PRINT("SENDTO [LEN: %lu]\n", a_len);
        l_s = sendto(l_fd, a_buf, a_len, 0, a_sa, a_socklen);
        if (l_s < 0)
        {
                // -----------------------------------------
                // EAGAIN
                // -----------------------------------------
                if (errno == EAGAIN)
                {
                        NDBG_PRINT("%sEAGAIN%s\n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF);
                        return NTRNT_STATUS_AGAIN;
                }
                TRC_ERROR("error performing sendto. Reason: %s", strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
bool peer_mgr::peer_exists(const sockaddr_storage& a_sas)
{
        pthread_mutex_lock(&m_mutex);
        auto i_p = m_peer_map.find(a_sas);
        if (i_p != m_peer_map.end())
        {
                pthread_mutex_unlock(&m_mutex);
                return true;
        }
        pthread_mutex_unlock(&m_mutex);
        return false;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void peer_mgr::add_peer(peer* a_peer)
{
        //NDBG_PRINT("[HOST: %s] [FROM: %d]\n", a_peer->m_host.c_str(), a_peer->m_from);
        const sockaddr_storage& a_sas = a_peer->get_sas();
        pthread_mutex_lock(&m_mutex);
        m_peer_vec.push_back(a_peer);
        if (a_sas.ss_family == AF_INET)
        {
                m_peer_vec_v4.push_back(a_peer);
        }
        else if(a_sas.ss_family == AF_INET6)
        {
                m_peer_vec_v6.push_back(a_peer);
        }
        m_peer_map[a_sas] = a_peer;
        pthread_mutex_unlock(&m_mutex);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer_mgr::dequeue_out(void)
{
        int32_t l_s;
        l_s = dequeue_out_v4();
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing dequeue_out(v4)");
                return NTRNT_STATUS_ERROR;
        }
        l_s = dequeue_out_v6();
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing dequeue_out(v6)");
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer_mgr::dequeue_out_v4(void)
{
        // -------------------------------------------------
        // foreach peer
        // -------------------------------------------------
        for (auto && i_p : m_peer_active_vec_v4)
        {
                if (!i_p) { continue; }
                peer& l_p = *i_p;
                // -----------------------------------------
                // check state
                // -----------------------------------------
                if (l_p.get_state() == peer::STATE_NONE)
                {
                        continue;
                }
                // -----------------------------------------
                // get utp conn
                // -could be null due to shutdown
                // -----------------------------------------
                utp_socket* l_utp_conn = l_p.get_utp_conn();
                if (!l_utp_conn)
                {
                        TRC_ERROR("[PEER: %s] [STATE: %d] utp_conn == null", l_p.get_host().c_str(), l_p.get_state());
                        return NTRNT_STATUS_OK;
                }
                // -----------------------------------------
                // write until EAGAIN
                // -----------------------------------------
                nbq& l_q = l_p.get_out_q();
                while (l_q.read_avail())
                {
                        ssize_t l_s;
                        int32_t l_try_read = l_q.b_read_avail();
                        l_s = utp_write(l_utp_conn, l_q.b_read_ptr(), l_try_read);
                        //NDBG_PRINT("[%sutp_write%s: %ld / %d] [errno[%d] %s]\n",
                        //           ANSI_COLOR_FG_CYAN, ANSI_COLOR_OFF,
                        //           l_s, l_try_read,
                        //           errno, strerror(errno));
                        // ---------------------------------
                        // socket no longer writable
                        // ---------------------------------
                        if (l_s == 0)
                        {
                                //NDBG_PRINT("NO LONGER WRITEABLE\n");
                                break;
                        }
                        // ---------------------------------
                        // shrink q  by read
                        // ---------------------------------
                        else if (l_s > 0)
                        {
                                l_p.m_stat_bytes_sent += l_s;
                                l_q.b_read_incr(l_s);
                                l_q.shrink();
                        }
                }
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer_mgr::dequeue_out_v6(void)
{
        // -------------------------------------------------
        // foreach peer
        // -------------------------------------------------
        for (auto && i_p : m_peer_active_vec_v6)
        {
                if (!i_p) { continue; }
                peer& l_p = *i_p;
                // -----------------------------------------
                // check state
                // -----------------------------------------
                if (l_p.get_state() == peer::STATE_NONE)
                {
                        continue;
                }
                // -----------------------------------------
                // get utp conn
                // -could be null due to shutdown
                // -----------------------------------------
                utp_socket* l_utp_conn = l_p.get_utp_conn();
                if (!l_utp_conn)
                {
                        TRC_ERROR("[PEER: %s] [STATE: %d] utp_conn == null", l_p.get_host().c_str(), l_p.get_state());
                        return NTRNT_STATUS_OK;
                }
                // -----------------------------------------
                // write until eagain
                // -----------------------------------------
                nbq& l_q = l_p.get_out_q();
                while (l_q.read_avail())
                {
                        ssize_t l_s;
                        int32_t l_try_read = l_q.b_read_avail();
                        l_s = utp_write(l_utp_conn, l_q.b_read_ptr(), l_try_read);
                        //NDBG_PRINT("[%sutp_write%s: %ld / %d] [errno[%d] %s]\n",
                        //           ANSI_COLOR_FG_CYAN, ANSI_COLOR_OFF,
                        //           l_s, l_try_read,
                        //           errno, strerror(errno));
                        // ---------------------------------
                        // socket no longer writable
                        // ---------------------------------
                        if (l_s == 0)
                        {
                                break;
                        }
                        // ---------------------------------
                        // shrink q  by read
                        // ---------------------------------
                        else if (l_s > 0)
                        {
                                l_p.m_stat_bytes_sent += l_s;
                                l_q.b_read_incr(l_s);
                                l_q.shrink();
                        }
                }
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer_mgr::pm_utp_check_timeouts(void)
{
        // -------------------------------------------------
        // utp_check_timeouts
        // -------------------------------------------------
        //NDBG_PRINT("utp_check_timeouts\n");
        utp_check_timeouts(m_utp_ctx);
        // -------------------------------------------------
        // issue deferred acks
        // -------------------------------------------------
        //NDBG_PRINT("utp_issue_deferred_acks\n");
        utp_issue_deferred_acks(m_utp_ctx);
        // -------------------------------------------------
        // fire again
        // -------------------------------------------------
        int32_t l_s;
        void *l_timer = NULL;
        l_s = m_session.add_timer((uint32_t)(NTRNT_SESSION_T_CHECK_TIMEOUTS_MS),
                                  _pm_utp_check_timeouts,
                                  (void *)this,
                                  &l_timer);
        UNUSED(l_s);
        // TODO Check status...
        return NTRNT_STATUS_OK;
}
}
