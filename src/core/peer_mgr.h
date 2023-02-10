#ifndef _NTRNT_PEER_MGR_H
#define _NTRNT_PEER_MGR_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "ntrnt/ntrnt.h"
#include "farmhash.h"
#include "core/peer.h"
#include <arpa/inet.h>
#include <unordered_map>
#include <set>
#include <deque>
//! ----------------------------------------------------------------------------
//! ext fwd decl's
//! ----------------------------------------------------------------------------
typedef struct UTPSocket utp_socket;
typedef struct struct_utp_context utp_context;
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class session;
class nbq;
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
// ---------------------------------------------------------
// sockaddr_storage hash
// ---------------------------------------------------------
typedef struct _sas_hash
{
        inline std::size_t operator()(const sockaddr_storage& a_key) const
        {
                return util::Hash64((const char*)(&a_key), sizeof(a_key));
        }
} sas_hash_t;
// ---------------------------------------------------------
// sockaddr_storage '=='
// ---------------------------------------------------------
typedef struct _sas_comp
{
        inline bool operator()(const sockaddr_storage& lhs, const sockaddr_storage& rhs) const
        {
                return (memcmp(&lhs, &rhs, sizeof(lhs)) == 0);
        }
} sas_comp_t;
typedef std::unordered_map<sockaddr_storage, peer*, sas_hash_t, sas_comp_t> peer_map_t;
typedef std::vector<peer*> peer_vec_t;
typedef std::unordered_map<void*, peer*> ctx_peer_map_t;
//! ----------------------------------------------------------------------------
//! \class: tracker
//! ----------------------------------------------------------------------------
class peer_mgr {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        peer_mgr(session& a_session);
        ~peer_mgr(void);
        int32_t init(void);
        void display(void);
        void display_peers(void);
        // -------------------------------------------------
        // operations
        // -------------------------------------------------
        int32_t connect_peers(void);
        int32_t add_peer(const sockaddr_storage& a_sas, peer_from_t a_from);
        int32_t dequeue_out(void);
        int32_t dequeue_out_v4(void);
        int32_t dequeue_out_v6(void);
        // -------------------------------------------------
        // set
        // -------------------------------------------------
        void set_cfg_max_conn(size_t a_num) { m_cfg_max_conn = a_num; }
        void set_no_accept(bool a_flag) { m_no_accept = a_flag; }
        // -------------------------------------------------
        // get
        // -------------------------------------------------
        peer_vec_t& get_peer_connected_vec(void) { return m_peer_connected_vec; }
        bool get_no_accept(void) {return m_no_accept; }
        utp_context* get_utp_ctx(void) { return m_utp_ctx; }
        // -------------------------------------------------
        // utp
        // -------------------------------------------------
        int32_t pm_utp_check_timeouts(void);
        int32_t pm_utp_on_accept(utp_socket* a_utp_conn);
        int32_t pm_utp_sendto(const uint8_t* a_buf,
                              size_t a_len,
                              const struct sockaddr* a_sa,
                              socklen_t a_socklen);
        // -------------------------------------------------
        // apis
        // -------------------------------------------------
        int32_t get_peers_api(std::string& ao_body);
        int32_t get_peers_str(std::string& ao_body);
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // -------------------------------------------------
        // disallow copy/assign
        // -------------------------------------------------
        peer_mgr(const peer_mgr&);
        peer_mgr& operator=(const peer_mgr&);
        int32_t set_geoip(peer& a_peer, const sockaddr_storage& a_sas);
        bool peer_exists(const sockaddr_storage& a_sas);
        void add_peer(peer* a_peer);
        int32_t validate_address(const sockaddr_storage& a_sas);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_is_initd;
        session& m_session;
        pthread_mutex_t m_mutex;
        utp_context* m_utp_ctx;
        peer_vec_t m_peer_vec;
        peer_vec_t m_peer_vec_v4;
        peer_vec_t m_peer_vec_v6;
        peer_map_t m_peer_map;
        peer_vec_t m_peer_connected_vec;
        peer_vec_t m_peer_active_vec_v4;
        peer_vec_t m_peer_active_vec_v6;
        // -------------------------------------------------
        // settings
        // -------------------------------------------------
        size_t m_cfg_max_conn;
        bool m_no_accept;
        size_t m_peer_vec_idx;
        // -------------------------------------------------
        // debugging
        // -------------------------------------------------
        ctx_peer_map_t m_ctx_peer_map;
        friend peer;
};
//! ----------------------------------------------------------------------------
//! prototypes
//! ----------------------------------------------------------------------------
}
#endif
