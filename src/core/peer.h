#ifndef _NTRNT_PEER_H
#define _NTRNT_PEER_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "ntrnt/ntrnt.h"
#include "support/nbq.h"
#include "support/btfield.h"
#include <arpa/inet.h>
#include <string.h>
#include <string>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define NTRNT_PEER_CONNECT_TIMEOUT 5000
//#define NTRNT_PEER_IDLE_TIMEOUT 5000
#define NTRNT_PEER_HANDSHAKE_SIZE 68
#define NTRNT_PEER_LTEP_HANDSHAKE_SIZE 512
//! ----------------------------------------------------------------------------
//! ext fwd decl's
//! ----------------------------------------------------------------------------
typedef struct UTPSocket utp_socket;
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class session;
class peer_mgr;
class pickr;
class phe;
//! ----------------------------------------------------------------------------
//! globals
//! ----------------------------------------------------------------------------
// ---------------------------------------------------------
// "<0x19>BitTorrent protocol"
// ---------------------------------------------------------
const uint8_t g_btp_str[20] = {
        0x13, 0x42, 0x69, 0x74,
        0x54, 0x6f, 0x72, 0x72,
        0x65, 0x6e, 0x74, 0x20,
        0x70, 0x72, 0x6f, 0x74,
        0x6f, 0x63, 0x6f, 0x6c
};
//! ----------------------------------------------------------------------------
//! \class: tracker
//! ----------------------------------------------------------------------------
class peer {
public:
        // ---------------------------------------------------------
        // handshake flags
        // ---------------------------------------------------------
        typedef enum {
                _BT_RSVD_BITS_LTEP = 43,
                _BT_RSVD_BITS_FEXT = 61,
                _BT_RSVD_BITS_DHT  = 63,
        } _bt_rsvd_bits_t;
        // -------------------------------------------------
        // types
        // -------------------------------------------------
        typedef enum _error {
                ERROR_NONE,
                ERROR_TIMEOUT,
                ERROR_EOF,
                ERROR_EXPIRED_BR,
                ERROR_IDLE_TIMEOUT,
                ERROR_CONNECT,
                ERROR_UTP_EOF,
                ERROR_UTP_CB_DONE,
                ERROR_UTP_CB_ERROR,
                ERROR_UTP_ON_ERROR,
                ERROR_HANDSHAKE_SELF,
        } error_t;
        typedef enum _state {
                STATE_NONE,
                STATE_UTP_CONNECTING,
                STATE_PHE_SETUP,
                STATE_PHE_CONNECTING,
                STATE_HANDSHAKING,
                STATE_CONNECTED
        } state_t;
        // -------------------------------------------------
        // BitTorrent Protocol Command ID's
        // -------------------------------------------------
        typedef enum {
                BTP_CMD_CHOKE = 0,
                BTP_CMD_UNCHOKE = 1,
                BTP_CMD_INTERESTED = 2,
                BTP_CMD_NOT_INTERESTED = 3,
                BTP_CMD_HAVE = 4,
                BTP_CMD_BITFIELD = 5,
                BTP_CMD_REQUEST = 6,
                BTP_CMD_PIECE = 7,
                BTP_CMD_CANCEL = 8,
                BTP_CMD_PORT = 9,
                BTP_CMD_FEXT_SUGGEST = 13,
                BTP_CMD_FEXT_HAVE_ALL = 14,
                BTP_CMD_FEXT_HAVE_NONE = 15,
                BTP_CMD_FEXT_REJECT = 16,
                BTP_CMD_FEXT_ALLOWED_FAST = 17,
                BTP_CMD_LTEP = 20
        } btp_cmd_t;
        // -------------------------------------------------
        // LTEP Protocol Command ID's
        // ref:
        //   MetaData
        //     https://www.bittorrent.org/beps/bep_0009.html
        //   Peer Exchange
        //     https://www.bittorrent.org/beps/bep_0011.html
        //   LTEP
        //     https://www.bittorrent.org/beps/bep_0010.html
        // -------------------------------------------------
        typedef enum {
                LTEP_CMD_HANDSHAKE = 0,
                LTEP_CMD_PEX = 1,
                LTEP_CMD_METADATA = 3
        } ltep_cmd_t;
        // -------------------------------------------------
        // LTEP PEX Peer Flags
        // https://www.bittorrent.org/beps/bep_0011.html
        // bit  | when set
        // -----+---------------------------------------------
        // 0x01 | prefers encryption, as indicated by e field in extension handshake
        // 0x02 | seed/upload_only
        // 0x04 | supports uTP
        // 0x08 | peer indicated ut_holepunch support in extension handshake
        // 0x10 | outgoing connection, peer is reachable
        // -------------------------------------------------
        typedef enum {
                LTEP_PEER_FLAG_PREFERS_ENCRYPTION   = 1 << 0,
                LTEP_PEER_FLAG_SEED                 = 1 << 1,
                LTEP_PEER_FLAG_SUPPORTS_UTP         = 1 << 2,
                LTEP_PEER_FLAG_SUPPORTS_HOLEPUNCH   = 1 << 3,
                LTEP_PEER_FLAG_OUTGOING_CONNECTION  = 1 << 4
        } ltep_peer_flag_t;
        // -------------------------------------------------
        // LTEP Metadata request type
        // ref:
        // https://www.bittorrent.org/beps/bep_0009.html
        // id | msg types:
        // ---+---------------------------------------------
        //  0 | request
        //  1 | data
        //  2 | reject
        // -------------------------------------------------
        typedef enum {
                LTEP_METADATA_CMD_RQST = 0,
                LTEP_METADATA_CMD_DATA = 1,
                LTEP_METADATA_CMD_REJECT = 2
        } ltep_metadata_msg_t;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        peer(peer_from_t a_from,
             session& a_session,
             peer_mgr& a_peer_mgr,
             const sockaddr_storage& a_sas);
        ~peer(void);
        void reset(void);
        int32_t connect(void);
        int32_t accept_utp(void *a_ctx);
        uint64_t utp_cb(utp_socket* a_utp_conn,
                        int a_type,
                        int a_state,
                        const uint8_t* a_buf,
                        size_t a_len);
        void shutdown(error_t a_reason);
        // -------------------------------------------------
        // get/set
        // -------------------------------------------------
        void set_state(state_t a_state) { m_state = a_state; }
        const sockaddr_storage& get_sas(void) const { return m_sas; }
        state_t get_state(void) { return m_state; }
        std::string& get_host(void) { return m_host; }
        peer_from_t get_from(void) { return m_from; }
        peer_mgr& get_peer_mgr(void) { return m_peer_mgr; }
        utp_socket* get_utp_conn(void) { return m_utp_conn; }
        phe* get_phe(void) { return m_phe; }
        bool get_btp_peer_choking(void) { return m_btp_peer_choking; }
        bool get_btp_am_interested(void) { return m_btp_am_interested; }
        btfield& get_btp_pieces_have(void) { return m_btp_pieces_have; }
        const std::string get_btp_peer_str(void) { return m_btp_peer_str; }
        session& get_session(void) { return m_session; }
        error_t get_error(void) { return m_error; }
        int64_t get_ltep_reqq(void) { return m_ltep_reqq; }
        int64_t get_ltep_metadata_size(void) { return m_ltep_metadata_size; }
        bool get_ltep_msg_support_ut_metadata(void) { return m_ltep_msg_support_ut_metadata; }
        nbq& get_out_q(void) { return m_out_q; }
        // -------------------------------------------------
        // operators
        // -------------------------------------------------
        bool operator==(const peer& a_that) const
        {
                return (memcmp(&m_sas, &(a_that.get_sas()), sizeof(sockaddr_storage)) == 0);
        }
        // -------------------------------------------------
        // bittorrent protocol
        // -------------------------------------------------
        int32_t btp_send_keepalive(void);
        int32_t btp_send_request(uint32_t a_idx, uint32_t a_off, uint32_t a_len);
        int32_t btp_send_cancel(uint32_t a_idx, uint32_t a_off, uint32_t a_len);
        int32_t btp_send_have(uint32_t a_idx);
        // -------------------------------------------------
        // ltep protocol
        // -------------------------------------------------
        int32_t ltep_send_metadata_request(uint32_t a_idx);
        // -------------------------------------------------
        // stats
        // -------------------------------------------------
        void stat_add_br_expired(uint32_t a_val) { m_stat_expired_br += a_val; }
        void stat_add_bytes_sent(uint32_t a_val) { m_stat_bytes_sent += a_val; }
        void stat_add_bytes_recv(uint32_t a_val) { m_stat_bytes_recv += a_val; }
        uint64_t get_stat_expired_br(void) { return m_stat_expired_br; }
        uint64_t get_stat_bytes_sent(void) { return m_stat_bytes_sent; }
        uint64_t get_stat_bytes_recv(void) { return m_stat_bytes_recv; }
        // -------------------------------------------------
        // geoip
        // -------------------------------------------------
        const std::string& get_geoip2_country(void) { return m_geoip2_country; }
        const std::string& get_geoip2_city(void) { return m_geoip2_city; }
        double get_geoip2_lat(void) { return m_geoip2_lat; }
        double get_geoip2_lon(void) { return m_geoip2_lon; }
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // -------------------------------------------------
        // disallow copy/assign
        // -------------------------------------------------
        peer(const peer&);
        peer& operator=(const peer&);
        int32_t add_timer(uint32_t a_ms);
        int32_t cancel_timer(void);
        int32_t utp_read(const uint8_t* a_buf, size_t a_len);
        // -------------------------------------------------
        // handle btp protocol
        // -------------------------------------------------
        void btp_create_handshake(void);
        int32_t btp_parse_handshake_ia(const uint8_t* a_buf, size_t a_len);
        int32_t btp_parse_handshake(void);
        int32_t btp_send_choke(void);
        int32_t btp_send_unchoke(void);
        int32_t btp_send_interested(void);
        int32_t btp_send_not_interested(void);
        int32_t btp_send_bitfield(void);
        int32_t btp_send_piece(uint32_t a_idx, uint32_t a_off, uint32_t a_len);
        int32_t btp_read_until(void);
        int32_t btp_read_cmd(void);
        int32_t btp_recv_have(void);
        int32_t btp_recv_bitfield(void);
        int32_t btp_recv_piece(void);
        int32_t btp_recv_request(void);
        int32_t btp_recv_cancel(void);
        int32_t btp_recv_port(void);
        // -------------------------------------------------
        // ltep protocol
        // -------------------------------------------------
        void ltep_create_handshake(void);
        int32_t ltep_read_cmd(void);
        int32_t ltep_send_handshake(void);
        int32_t ltep_send_pex(void);
        int32_t ltep_send_metadata(uint32_t a_idx);
        int32_t ltep_send_metadata_reject(uint32_t a_idx);
        int32_t ltep_recv_handshake(size_t a_len);
        int32_t ltep_recv_pex(size_t a_len);
        int32_t ltep_recv_metadata(size_t a_len);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        peer_from_t m_from;
        session& m_session;
        peer_mgr& m_peer_mgr;
        state_t m_state;
        error_t m_error;
        size_t m_num_block_rqst_inflight;
        sockaddr_storage m_sas;
        std::string m_host;
        nbq m_in_q;
        nbq m_out_q;
        void* m_timer;
        utp_socket* m_utp_conn;
        phe* m_phe;
        uint8_t m_handshake[NTRNT_PEER_HANDSHAKE_SIZE];
        // -------------------------------------------------
        // client state
        // -------------------------------------------------
        bool m_btp_ltep;
        bool m_btp_fext;
        bool m_btp_dht;
        id_t m_btp_info_hash;
        peer_id_t m_btp_peer_id;
        std::string m_btp_peer_str;
        btfield m_btp_pieces_have;
        bool m_btp_am_choking;
        bool m_btp_am_interested;
        bool m_btp_peer_choking;
        bool m_btp_peer_interested;
        // -------------------------------------------------
        // current cmd
        // -------------------------------------------------
        bool m_btp_cmd_flag;
        uint32_t m_btp_cmd_len;
        uint8_t m_btp_cmd;
        // -------------------------------------------------
        // ltep settings
        // -------------------------------------------------
        uint8_t* m_ltep_handshake;
        size_t m_ltep_handshake_len;
        bool m_ltep_encryption;
        int64_t m_ltep_metadata_size;
        int64_t m_ltep_reqq;
        bool m_ltep_upload_only;
        std::string m_ltep_peer_id;
        int64_t m_ltep_complete_ago;
        int64_t m_ltep_peer_port;
        bool m_ltep_msg_support_ut_metadata;
        bool m_ltep_msg_support_ut_pex;
        bool m_ltep_msg_support_ut_holepunch;
        int64_t m_ltep_ut_metadata_id;
        int64_t m_ltep_ut_pex_id;
        int64_t m_ltep_ut_holepunch_id;
        // -------------------------------------------------
        // stats
        // -------------------------------------------------
        size_t m_stat_expired_br;
        size_t m_stat_bytes_sent;
        size_t m_stat_bytes_sent_last;
        size_t m_stat_bytes_sent_per_s;
        size_t m_stat_bytes_recv;
        size_t m_stat_bytes_recv_last;
        size_t m_stat_bytes_recv_per_s;
        size_t m_stat_last_recvd_time_s;
        // -------------------------------------------------
        // geoip
        // -------------------------------------------------
        std::string m_geoip2_country;
        std::string m_geoip2_city;
        double m_geoip2_lat;
        double m_geoip2_lon;
        // -------------------------------------------------
        // sharing private fields with peer mgr
        // -------------------------------------------------
        friend peer_mgr;
        friend pickr;
};
}
#endif
