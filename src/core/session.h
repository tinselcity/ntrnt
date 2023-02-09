#ifndef _NTRNT_SESSION_H
#define _NTRNT_SESSION_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "ntrnt/types.h"
#include "evr/evr.h"
#include "core/peer_mgr.h"
#include "core/info_pickr.h"
#include "core/pickr.h"
#include <stdint.h>
#include <signal.h>
#include <arpa/inet.h>
#include <string>
#include <unordered_map>
//! ----------------------------------------------------------------------------
//! ext fwd decl's
//! ----------------------------------------------------------------------------
typedef struct ssl_ctx_st SSL_CTX;
typedef struct struct_utp_context utp_context;
typedef struct UTPSocket utp_socket;
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class tracker;
class tracker_udp_rqst;
class nresolver;
class dht_mgr;
class geoip2_mmdb;
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::list<tracker*> tracker_list_t;
typedef std::unordered_map<uint32_t, tracker_udp_rqst*> tid_tracker_udp_map_t;
//! ----------------------------------------------------------------------------
//! \class: session
//! ----------------------------------------------------------------------------
class session {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        session(void);
        ~session(void);
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        int32_t init_w_metainfo(const std::string& a_path);
        int32_t init_w_magnet(const std::string& a_url);
        int32_t init_w_hash(const std::string& a_hash);
        // -------------------------------------------------
        // running
        // -------------------------------------------------
        int32_t run(void);
        void signal(void);
        void stop(void);
        void display(void);
        void display_info(void);
        bool is_running(void) { return !m_stopped; }
        void set_stopped(bool a_flag) { m_stopped = a_flag; }
        // -------------------------------------------------
        // add peers
        // -------------------------------------------------
        int32_t add_peer(struct sockaddr_storage& a_sas, peer_from_t a_from);
        int32_t add_peer_raw(int a_family, const uint8_t* a_buf, size_t a_len, peer_from_t a_from);
        // -------------------------------------------------
        // udp helpers
        // -------------------------------------------------
        int32_t udp_mux(struct sockaddr_storage& a_ss,
                        socklen_t& a_ss_len,
                        uint8_t* a_msg,
                        uint32_t a_msg_len);
        // -------------------------------------------------
        // timer helper
        // -------------------------------------------------
        int32_t add_timer(uint32_t a_time_ms,
                          evr_event_cb_t a_cb,
                          void *a_data,
                          void **ao_event);
        int32_t cancel_timer(void* a_timer);
        // -------------------------------------------------
        // get
        // -------------------------------------------------
        bool get_stopped(void) { return (bool)m_stopped; }
        nresolver& get_resolver(void) { return *m_nresolver; }
        SSL_CTX* get_client_ssl_ctx(void) { return m_client_ssl_ctx; }
        evr_loop *get_evr_loop(void) { return m_evr_loop; }
        std::string& get_ext_ip(void) { return m_ext_ip; }
        uint16_t get_ext_port(void) { return m_ext_port; }
        int get_udp_fd(void) { return m_udp_fd; }
        int get_udp6_fd(void) { return m_udp6_fd; }
        utp_context* get_utp_ctx(void) { return m_utp_ctx; }
        peer_mgr& get_peer_mgr(void) { return m_peer_mgr; }
        pickr& get_pickr(void) { return m_pickr; }
        info_pickr& get_info_pickr(void) { return m_info_pickr; }
        geoip2_mmdb* get_geoip2_mmdb(void) { return m_geoip2_mmdb; }
        const uint8_t* get_info_hash(void) const { return m_info_hash.m_data; }
        const std::string& get_info_hash_str(void) const { return m_info_hash_str; }
        uint32_t get_info_num_pieces(void) { return (uint32_t)m_info_pickr.get_info_pieces_size(); }
        const std::string& get_peer_id(void) { return m_peer_id; }
        const std::string& get_ext_address_v4(void) { return m_ext_address_v4; }
        const std::string& get_ext_address_v6(void) { return m_ext_address_v6; }
        // -------------------------------------------------
        // set
        // -------------------------------------------------
        void set_dht(bool a_flag) { m_dht_enable = a_flag; }
        void set_trackers(bool a_flag) { m_trackers_enable = a_flag; }
        void set_ext_ip(const char* a_addr) { m_ext_ip = a_addr; }
        void set_ext_port(uint16_t a_port) { m_ext_port = a_port; }
        void set_peer(const std::string& a_str) { m_peer = a_str; }
        void set_ext_address_v4(const std::string& a_str) { m_ext_address_v4 = a_str; }
        void set_ext_address_v6(const std::string& a_str) { m_ext_address_v6 = a_str; }
        // -------------------------------------------------
        // geoip2 support
        // -------------------------------------------------
        int32_t set_geoip_db(const std::string& a_db);
        // -------------------------------------------------
        // timers
        // -------------------------------------------------
        int32_t t_trackers(void);
        int32_t t_request_blocks(void);
        int32_t t_connect_peers(void);
        int32_t t_check_timeouts(void);
        // -------------------------------------------------
        // apis
        // -------------------------------------------------
        int32_t api_get_info(std::string& ao_body);
        int32_t api_get_trackers(std::string& ao_body);
        int32_t api_get_peers(std::string& ao_body);
        // -------------------------------------------------
        // Public Static (class) methods
        // -------------------------------------------------
        // udp
        static int32_t udp_fd_readable_cb(void *a_data);
        static int32_t udp_fd_writeable_cb(void *a_data);
        static int32_t udp_fd_error_cb(void *a_data);
        // udp6
        static int32_t udp6_fd_readable_cb(void *a_data);
        static int32_t udp6_fd_writeable_cb(void *a_data);
        static int32_t udp6_fd_error_cb(void *a_data);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        tid_tracker_udp_map_t m_tid_tracker_udp_map;
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // disallow copy/assign
        session(const session&);
        session& operator=(const session&);
        int32_t init(void);
        int32_t setup_udp(void);
        int32_t setup_udp6(void);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_is_initd;
        // -------------------------------------------------
        // session properties
        // -------------------------------------------------
        id_t m_info_hash;
        std::string m_info_hash_str;
        std::string m_announce;
        str_list_t m_announce_list;
        int64_t m_creation_date;
        std::string m_created_by;
        std::string m_encoding;
        std::string m_comment;
        // -------------------------------------------------
        // state
        // -------------------------------------------------
        sig_atomic_t m_stopped;
        bool m_trackers_enable;
        std::string m_peer_id;
        std::string m_ext_ip;
        uint16_t m_ext_port;
        std::string m_ext_address_v4;
        std::string m_ext_address_v6;
        std::string m_peer;
        tracker_list_t m_tracker_list;
        nresolver *m_nresolver;
        SSL_CTX *m_client_ssl_ctx;
        // -------------------------------------------------
        // reactor
        // -------------------------------------------------
        evr_loop_type_t m_evr_loop_type;
        evr_loop *m_evr_loop;
        // -------------------------------------------------
        // udp evr fd
        // -------------------------------------------------
        evr_fd_t m_evr_udp_fd;
        evr_fd_t m_evr_udp6_fd;
        // -------------------------------------------------
        // sockets
        // -------------------------------------------------
        int m_udp_fd;
        int m_udp6_fd;
        // -------------------------------------------------
        // dht
        // -------------------------------------------------
        bool m_dht_enable;
        dht_mgr* m_dht_mgr;
        // -------------------------------------------------
        // utp
        // -------------------------------------------------
        utp_context* m_utp_ctx;
        // -------------------------------------------------
        // peer mgr
        // -------------------------------------------------
        peer_mgr m_peer_mgr;
        // -------------------------------------------------
        // pickr
        // -------------------------------------------------
        info_pickr m_info_pickr;
        pickr m_pickr;
        // -------------------------------------------------
        // geoip2 support
        // -------------------------------------------------
        geoip2_mmdb *m_geoip2_mmdb;
        std::string m_geoip2_db;
};
}
#endif
