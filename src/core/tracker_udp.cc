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
#include "conn/nconn.h"
#include "conn/nconn_tls.h"
#include "bencode/bencode.h"
#include "dns/nresolver.h"
#include "http/http_resp.h"
#include "core/session.h"
#include "core/tracker_udp.h"
// ---------------------------------------------------------
// ext
// ---------------------------------------------------------
#include "http_parser/http_parser.h"
// ---------------------------------------------------------
// openssl
// ---------------------------------------------------------
#include <openssl/rand.h>
// ---------------------------------------------------------
// std
// ---------------------------------------------------------
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
// ---------------------------------------------------------
// stl
// ---------------------------------------------------------
#include <map>
#include <sstream>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _PROTOCOL_ID 0x41727101980
#define _REQUEST_SIZE 16384
#define _ACTION_CONNECT  0
#define _ACTION_ANNOUNCE 1
#define _ACTION_SCRAPE   2
//! ----------------------------------------------------------------------------
//! Macros
//! ----------------------------------------------------------------------------
// Set socket option macro...
#define SET_SOCK_OPT(_sock_fd, _sock_opt_level, _sock_opt_name, _sock_opt_val) \
        do { \
                int _l__sock_opt_val = _sock_opt_val; \
                int _l_status = 0; \
                errno = 0; \
                _l_status = ::setsockopt(_sock_fd, \
                                _sock_opt_level, \
                                _sock_opt_name, \
                                &_l__sock_opt_val, \
                                sizeof(_l__sock_opt_val)); \
                if (_l_status == -1) { \
                        TRC_ERROR("Failed to set sock_opt: %s.  Reason: %s.", #_sock_opt_name, strerror(errno)); \
                        return NTRNT_STATUS_ERROR;\
                } \
        } while(0)
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                               R E Q U E S T
//! ****************************************************************************
//! ----------------------------------------------------------------------------
// ---------------------------------------------------------------------
// Connect:
// ---------------------------------------------------------------------
// Offset |Size           |Name           |Value         |Notes
// -------+---------------+---------------+--------------+--------------
// 0       64-bit integer  protocol_id     0x41727101980  magic constant
// 8       32-bit integer  action          0              connect
// 12      32-bit integer  transaction_id
// 16
// ---------------------------------------------------------------------
// ---------------------------------------------------------------------
// Connect Response:
// ---------------------------------------------------------------------
// Offset |Size           |Name           |Value         |Notes
// -------+---------------+---------------+--------------+--------------
// 0       32-bit integer  action          0              connect
// 4       32-bit integer  transaction_id
// 8       64-bit integer  connection_id
// 16
// ---------------------------------------------------------------------
// ---------------------------------------------------------------------
// Announce:
// ---------------------------------------------------------------------
// Offset |Size           |Name           |Value         |Notes
// -------+---------------+---------------+--------------+--------------
// 0       64-bit integer  connection_id
// 8       32-bit integer  action          1              announce
// 12      32-bit integer  transaction_id
// 16      20-byte string  info_hash
// 36      20-byte string  peer_id
// 56      64-bit integer  downloaded
// 64      64-bit integer  left
// 72      64-bit integer  uploaded
// 80      32-bit integer  event           0              0: none; 1: completed; 2: started; 3: stopped
// 84      32-bit integer  IP address      0              default
// 88      32-bit integer  key
// 92      32-bit integer  num_want        -1             default
// 96      16-bit integer  port
// 98
// ---------------------------------------------------------------------
// ---------------------------------------------------------------------
// Announce Response:
// ---------------------------------------------------------------------
// Offset     |Size           |Name           |Value         |Notes
// -----------+---------------+---------------+--------------+----------
// 0           32-bit integer  action          1              announce
// 4           32-bit integer  transaction_id
// 8           32-bit integer  interval
// 12          32-bit integer  leechers
// 16          32-bit integer  seeders
// 20 + 6 * n  32-bit integer  IP address
// 24 + 6 * n  16-bit integer  TCP port
// 20 + 6 * N
// ---------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! tracker_udp_rqst
//! ----------------------------------------------------------------------------
class tracker_udp_rqst
{
public:
        // -------------------------------------------------
        // public types
        // -------------------------------------------------
        // type
        typedef enum {
                TYPE_NONE = 0,
                TYPE_ANNOUNCE,
                TYPE_SCRAPE
        } type_t;
        // state
        typedef enum {
                STATE_NONE = 0,
                STATE_QUEUED,
                STATE_FREE,
                STATE_CONNECTING,
                STATE_CONNECTED,
                STATE_DONE,
        } state_t;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        tracker_udp_rqst(tracker_udp& a_tracker);
        ~tracker_udp_rqst();
        int32_t setup(void);
        int32_t handle_resp(uint8_t* a_msg, uint32_t a_msg_len);
        int32_t send_connect(void);
        int32_t recv_connect(uint8_t* a_msg, uint32_t a_msg_len);
        int32_t send_announce(void);
        int32_t recv_announce(uint8_t* a_msg, uint32_t a_msg_len);
        int32_t send_scrape(void);
        int32_t recv_scrape(uint8_t* a_msg, uint32_t a_msg_len);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        tracker_udp& m_tracker;
        type_t m_type;
        state_t m_state;
        // -------------------------------------------------
        // properties
        // -------------------------------------------------
        host_info m_host_info;
        int m_fd;
        // transaction id
        uint32_t m_tid;
        // connection id
        uint64_t m_cid;
private:
        // -------------------------------------------------
        // private  methods
        // -------------------------------------------------
        // Disallow copy/assign
        tracker_udp_rqst& operator=(const tracker_udp_rqst &);
        tracker_udp_rqst(const tracker_udp_rqst &);
};
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
tracker_udp_rqst::tracker_udp_rqst(tracker_udp& a_tracker):
        m_tracker(a_tracker),
        m_type(TYPE_NONE),
        m_state(STATE_NONE),
        m_host_info(),
        m_fd(-1),
        m_tid(0),
        m_cid(0)
{
        // create transaction id
        RAND_bytes((unsigned char*)(&m_tid), sizeof(m_tid));
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
tracker_udp_rqst::~tracker_udp_rqst(void)
{
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_udp_rqst::setup(void)
{
        // -------------------------------------------------
        // resolve
        // -------------------------------------------------
        int32_t l_s;
        nresolver& l_resolver = m_tracker.m_session.get_resolver();
        // sync dns
        l_s = l_resolver.lookup_sync(m_tracker.m_host, m_tracker.m_port, m_host_info);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("error: performing lookup_sync\n");
                //++m_stat.m_upsv_errors;
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get fd
        // -------------------------------------------------
        if (m_host_info.m_sock_family == AF_INET)
        {
                m_fd = m_tracker.m_session.get_udp_fd();
        }
        else if (m_host_info.m_sock_family == AF_INET6)
        {
                m_fd = m_tracker.m_session.get_udp6_fd();
        }
        else
        {
                TRC_ERROR("error: unrecognized family type: %d\n", m_host_info.m_sock_family);
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_udp_rqst::handle_resp(uint8_t* a_msg, uint32_t a_msg_len)
{
        int32_t l_s;
        switch(m_state)
        {
        // -------------------------------------------------
        // STATE_FREE
        // -------------------------------------------------
        case tracker_udp_rqst::STATE_FREE:
        {
                break;
        }
        // -------------------------------------------------
        // STATE_CONNECTING
        // -------------------------------------------------
        case tracker_udp_rqst::STATE_CONNECTING:
        {
                // ---------------------------------
                // recv connect message
                // ---------------------------------
                l_s = recv_connect(a_msg, a_msg_len);
                if (l_s != NTRNT_STATUS_OK)
                {
                        return NTRNT_STATUS_ERROR;
                }
                m_state = tracker_udp_rqst::STATE_CONNECTED;
                // ---------------------------------
                // send announce
                // ---------------------------------
                l_s = send_announce();
                if (l_s != NTRNT_STATUS_OK)
                {
                        return NTRNT_STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // STATE_CONNECTED
        // -------------------------------------------------
        case tracker_udp_rqst::STATE_CONNECTED:
        {
                // -----------------------------------------
                // read announce resp
                // -----------------------------------------
                if (m_type == tracker_udp_rqst::TYPE_ANNOUNCE)
                {
                        l_s = recv_announce(a_msg, a_msg_len);
                        if (l_s != NTRNT_STATUS_OK)
                        {
                                return NTRNT_STATUS_ERROR;
                        }
                        m_tracker.m_next_announce_s = get_time_s() + NTRNT_SESSION_TRACKER_ANNOUNCE_S;
                }
                else if (m_type == tracker_udp_rqst::TYPE_SCRAPE)
                {
                        l_s = recv_scrape(a_msg, a_msg_len);
                        if (l_s != NTRNT_STATUS_OK)
                        {
                                return NTRNT_STATUS_ERROR;
                        }
                        m_tracker.m_next_scrape_s = get_time_s() + NTRNT_SESSION_TRACKER_ANNOUNCE_S;
                }
                m_state = tracker_udp_rqst::STATE_DONE;
                break;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                break;
        }
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_udp_rqst::send_connect(void)
{
        int32_t l_s;
        // -------------------------------------------------
        // make connect
        // -------------------------------------------------
        uint8_t l_msg[16];
        // -------------------------------------------------
        // 64 protocol_id    0x41727101980
        // 32 action                     0 (connect)
        // 32 transaction_id          <ID>
        // -------------------------------------------------
        uint64_t l_pid = bswap_64(_PROTOCOL_ID);
        off_t l_off = 0;
        memcpy((void*)(l_msg+l_off), &l_pid, sizeof(l_pid));
        l_off += sizeof(l_pid);
        uint32_t l_aid = bswap_32(_ACTION_CONNECT);
        memcpy((void*)(l_msg+l_off), &l_aid, sizeof(l_aid));
        l_off += sizeof(l_aid);
        uint32_t l_tid_swp = bswap_32(m_tid);
        memcpy((void*)(l_msg+l_off), &l_tid_swp, sizeof(l_tid_swp));
        l_off += sizeof(l_tid_swp);
        // -------------------------------------------------
        // sendto
        // -------------------------------------------------
        errno = 0;
        l_s = sendto(m_fd,
                     l_msg,
                     sizeof(l_msg),
                     0,
                     (struct sockaddr*)(&m_host_info.m_sa),
                     m_host_info.m_sa_len);
        if (l_s < 0)
        {
                // -----------------------------------------
                // EAGAIN
                // -----------------------------------------
                if (errno == EAGAIN)
                {
                        TRC_ERROR("unexpected EAGAIN from sendto\n");
                        return NTRNT_STATUS_AGAIN;
                }
                TRC_ERROR("error performing sendto. Reason: %s\n", strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_udp_rqst::recv_connect(uint8_t* a_msg, uint32_t a_msg_len)
{
        m_state = STATE_CONNECTED;
        // -------------------------------------------------
        // 32 action                       0 (connect)
        // 32 transaction_id            <ID>
        // 64 connection_id    0x41727101980
        // -------------------------------------------------
        off_t l_off = 0;
        uint32_t l_aid = bswap_32((*((uint32_t*)(a_msg+l_off))));
        l_off+= sizeof(l_aid);
        uint32_t l_tid = bswap_32((*((uint32_t*)(a_msg+l_off))));
        l_off+= sizeof(l_tid);
        m_cid = bswap_64((*((uint64_t*)(a_msg+l_off))));
        l_off+= sizeof(m_cid);
        // -------------------------------------------------
        // check transaction id
        // -------------------------------------------------
        if (m_tid != l_tid)
        {
                TRC_ERROR("Error transaction id's don't match (%08x != %08x)\n", m_tid, l_tid);
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_udp_rqst::send_announce(void)
{
        int32_t l_s;
        // ---------------------------------------------------------------------
        // Announce:
        // ---------------------------------------------------------------------
        // Offset |Size           |Name           |Value         |Notes
        // -------+---------------+---------------+--------------+--------------
        // 0       64-bit integer  connection_id
        // 8       32-bit integer  action          1              announce
        // 12      32-bit integer  transaction_id
        // 16      20-byte string  info_hash
        // 36      20-byte string  peer_id
        // 56      64-bit integer  downloaded
        // 64      64-bit integer  left
        // 72      64-bit integer  uploaded
        // 80      32-bit integer  event           0              0: none; 1: completed; 2: started; 3: stopped
        // 84      32-bit integer  IP address      0              default
        // 88      32-bit integer  key
        // 92      32-bit integer  num_want        -1             default
        // 96      16-bit integer  port
        // 98
        // ---------------------------------------------------------------------
        uint8_t l_ann[98];
        uint64_t l_tmp64;
        uint32_t l_tmp32;
        uint16_t l_tmp16;
        off_t l_off = 0;
        // -------------------------------------------------
        // connection id
        // -------------------------------------------------
        l_tmp64 = bswap_64(m_cid);
        memcpy((void*)(l_ann+l_off), &l_tmp64, sizeof(l_tmp64));
        l_off += sizeof(l_tmp64);
        // -------------------------------------------------
        // action (announce)
        // -------------------------------------------------
        l_tmp32 = bswap_32(_ACTION_ANNOUNCE);
        memcpy((void*)(l_ann+l_off), &l_tmp32, sizeof(l_tmp32));
        l_off += sizeof(l_tmp32);
        // -------------------------------------------------
        // transaction_id
        // -------------------------------------------------
        l_tmp32 = bswap_32(m_tid);
        memcpy((void*)(l_ann+l_off), &l_tmp32, sizeof(l_tmp32));
        l_off += sizeof(l_tmp32);
        // -------------------------------------------------
        // info_hash
        // -------------------------------------------------
        memcpy((void*)(l_ann+l_off), m_tracker.m_session.get_info_hash(), 20);
        l_off += 20;
        // -------------------------------------------------
        // peer_id
        // -------------------------------------------------
        memcpy((void*)(l_ann+l_off), m_tracker.m_session.get_peer_id().c_str(), 20);
        l_off += 20;
        // -------------------------------------------------
        // downloaded
        // -------------------------------------------------
        uint64_t l_tmp64_val = 0;
        l_tmp64_val = 0;
        l_tmp64 = bswap_64(l_tmp64_val);
        memcpy((void*)(l_ann+l_off), &l_tmp64, sizeof(l_tmp64));
        l_off += sizeof(l_tmp64);
        // -------------------------------------------------
        // left
        // -------------------------------------------------
        l_tmp64 = bswap_64(l_tmp64_val);
        memcpy((void*)(l_ann+l_off), &l_tmp64, sizeof(l_tmp64));
        l_off += sizeof(l_tmp64);
        // -------------------------------------------------
        // uploaded
        // -------------------------------------------------
        l_tmp64 = bswap_64(l_tmp64_val);
        memcpy((void*)(l_ann+l_off), &l_tmp64, sizeof(l_tmp64));
        l_off += sizeof(l_tmp64);
        // -------------------------------------------------
        // event default(0)
        // 0: none; 1: completed; 2: started; 3: stopped
        // -------------------------------------------------
        uint64_t l_tmp32_val;
        l_tmp32_val = 0;
        l_tmp32 = bswap_32(l_tmp32_val);
        memcpy((void*)(l_ann+l_off), &l_tmp32, sizeof(l_tmp32));
        l_off += sizeof(l_tmp32);
        // -------------------------------------------------
        // ip default(0)
        // -------------------------------------------------
        l_tmp32 = bswap_32(l_tmp32_val);
        memcpy((void*)(l_ann+l_off), &l_tmp32, sizeof(l_tmp32));
        l_off += sizeof(l_tmp32);
        // -------------------------------------------------
        // key
        // -------------------------------------------------
        uint32_t l_key;
        RAND_bytes((unsigned char*)(&l_key), sizeof(l_key));
        l_tmp32 = bswap_32(l_key);
        memcpy((void*)(l_ann+l_off), &l_tmp32, sizeof(l_tmp32));
        l_off += sizeof(l_tmp32);
        // -------------------------------------------------
        // numwant
        // -------------------------------------------------
        uint32_t l_numwant = NTRNT_SESSION_NUMWANT;
        l_tmp32 = bswap_32(l_numwant);
        memcpy((void*)(l_ann+l_off), &l_tmp32, sizeof(l_tmp32));
        l_off += sizeof(l_tmp32);
        // -------------------------------------------------
        // port
        // -------------------------------------------------
        uint16_t l_port = m_tracker.m_session.get_ext_port();
        l_tmp16 = bswap_16(l_port);
        memcpy((void*)(l_ann+l_off), &l_tmp16, sizeof(l_tmp16));
        l_off += sizeof(l_tmp16);
        // -------------------------------------------------
        // sendto
        // -------------------------------------------------
        errno = 0;
        l_s = sendto(m_fd,
                     l_ann,
                     sizeof(l_ann),
                     0,
                     (struct sockaddr*)(&m_host_info.m_sa),
                     m_host_info.m_sa_len);
        if (l_s < 0)
        {
                // -----------------------------------------
                // EAGAIN
                // -----------------------------------------
                if (errno == EAGAIN)
                {
                        TRC_ERROR("unexpected EAGAIN from sendto\n");
                        return NTRNT_STATUS_AGAIN;
                }
                TRC_ERROR("error performing sendto. Reason: %s\n", strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_udp_rqst::recv_announce(uint8_t* a_msg, uint32_t a_msg_len)
{
        uint64_t l_now_s = get_time_s();
        m_tracker.m_stat_last_announce_time_s = l_now_s;
        m_tracker.m_next_announce_s = l_now_s + NTRNT_SESSION_TRACKER_ANNOUNCE_S;
        ++m_tracker.m_stat_announce_num;
        // -------------------------------------------------
        // 0           32-bit integer  action          1              announce
        // 4           32-bit integer  transaction_id
        // 8           32-bit integer  interval
        // 12          32-bit integer  leechers
        // 16          32-bit integer  seeders
        // 20 + 6 * n  32-bit integer  IP address
        // 24 + 6 * n  16-bit integer  TCP port
        // 20 + 6 * N
        // -------------------------------------------------
        uint32_t l_int = 0;
        uint32_t l_lcr = 0;
        uint32_t l_sdr = 0;
        off_t l_off = 0;
        uint32_t l_aid = bswap_32((*((uint32_t*)(a_msg+l_off))));
        l_off+= sizeof(l_aid);
        uint32_t l_tid = bswap_32((*((uint32_t*)(a_msg+l_off))));
        l_off+= sizeof(l_tid);
        l_int = bswap_32((*((uint64_t*)(a_msg+l_off))));
        l_off+= sizeof(l_int);
        l_lcr = bswap_32((*((uint64_t*)(a_msg+l_off))));
        l_off+= sizeof(l_int);
        l_sdr = bswap_32((*((uint64_t*)(a_msg+l_off))));
        l_off+= sizeof(l_int);
        UNUSED(l_lcr);
        UNUSED(l_sdr);
        // -------------------------------------------------
        // get peer addresses (ipv4)
        // -------------------------------------------------
        uint32_t l_p_size = a_msg_len-l_off;
        if (m_host_info.m_sock_family == AF_INET)
        {
                int32_t l_s;
                l_s = m_tracker.m_session.add_peer_raw(AF_INET,
                                                       a_msg + l_off,
                                                       l_p_size,
                                                       nullptr,
                                                       0,
                                                       NTRNT_PEER_FROM_TRACKER);
                UNUSED(l_s);
        }
        // -------------------------------------------------
        // get peer addresses (ipv6)
        // -------------------------------------------------
        else if (m_host_info.m_sock_family == AF_INET6)
        {
                int32_t l_s;
                l_s = m_tracker.m_session.add_peer_raw(AF_INET6,
                                                       a_msg + l_off,
                                                       l_p_size,
                                                       nullptr,
                                                       0,
                                                       NTRNT_PEER_FROM_TRACKER);
                UNUSED(l_s);
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_udp_rqst::send_scrape(void)
{
        int32_t l_s;
        // ---------------------------------------------------------------------
        // Announce:
        // ---------------------------------------------------------------------
        // Offset |Size           |Name           |Value         |Notes
        // -------+---------------+---------------+--------------+--------------
        // 0       64-bit integer  connection_id
        // 8       32-bit integer  action          2              scrape
        // 12      32-bit integer  transaction_id
        // 16      20-byte string  info_hash
        // ---------------------------------------------------------------------
        uint8_t l_ann[98];
        uint64_t l_tmp64;
        uint32_t l_tmp32;
        off_t l_off = 0;
        // -------------------------------------------------
        // connection id
        // -------------------------------------------------
        l_tmp64 = bswap_64(m_cid);
        memcpy((void*)(l_ann+l_off), &l_tmp64, sizeof(l_tmp64));
        l_off += sizeof(l_tmp64);
        // -------------------------------------------------
        // action (announce)
        // -------------------------------------------------
        l_tmp32 = bswap_32(_ACTION_SCRAPE);
        memcpy((void*)(l_ann+l_off), &l_tmp32, sizeof(l_tmp32));
        l_off += sizeof(l_tmp32);
        // -------------------------------------------------
        // transaction_id
        // -------------------------------------------------
        l_tmp32 = bswap_32(m_tid);
        memcpy((void*)(l_ann+l_off), &l_tmp32, sizeof(l_tmp32));
        l_off += sizeof(l_tmp32);
        // -------------------------------------------------
        // info_hash
        // -------------------------------------------------
        memcpy((void*)(l_ann+l_off), m_tracker.m_session.get_info_hash(), 20);
        l_off += 20;
        // -------------------------------------------------
        // sendto
        // -------------------------------------------------
        errno = 0;
        l_s = sendto(m_fd,
                     l_ann,
                     sizeof(l_ann),
                     0,
                     (struct sockaddr*)(&m_host_info.m_sa),
                     m_host_info.m_sa_len);
        if (l_s < 0)
        {
                // -----------------------------------------
                // EAGAIN
                // -----------------------------------------
                if (errno == EAGAIN)
                {
                        TRC_ERROR("unexpected EAGAIN from sendto\n");
                        return NTRNT_STATUS_AGAIN;
                }
                TRC_ERROR("error performing sendto. Reason: %s\n", strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_udp_rqst::recv_scrape(uint8_t* a_msg, uint32_t a_msg_len)
{
        m_tracker.m_stat_last_scrape_time_s = get_time_s();
        ++m_tracker.m_stat_scrape_num;
        // -------------------------------------------------
        // 0           32-bit integer  action          2 (scrape)
        // 4           32-bit integer  transaction_id
        // 8  + 12 * n 32-bit integer  seeders
        // 12 + 12 * n 32-bit integer  completed
        // 16 + 12 * n 32-bit integer  leechers
        // -------------------------------------------------
        off_t l_off = 0;
        uint32_t l_tmp32;
        uint32_t l_aid = bswap_32((*((uint32_t*)(a_msg+l_off))));
        l_off+= sizeof(l_aid);
        uint32_t l_tid = bswap_32((*((uint32_t*)(a_msg+l_off))));
        l_off+= sizeof(l_tid);
        // -------------------------------------------------
        // get fields
        // -------------------------------------------------
        // -------------------------------------------------
        // complete
        // -------------------------------------------------
        l_tmp32 = bswap_32((*((uint32_t*)(a_msg+l_off))));
        m_tracker.m_stat_last_scrape_num_complete = l_tmp32;
        l_off+= sizeof(l_tmp32);
        // -------------------------------------------------
        // downloaded
        // -------------------------------------------------
        l_tmp32 = bswap_32((*((uint32_t*)(a_msg+l_off))));
        m_tracker.m_stat_last_scrape_num_downloaded = l_tmp32;
        l_off+= sizeof(l_tmp32);
        // -------------------------------------------------
        // incomplete
        // -------------------------------------------------
        l_tmp32 = bswap_32((*((uint32_t*)(a_msg+l_off))));
        m_tracker.m_stat_last_scrape_num_incomplete = l_tmp32;
        l_off+= sizeof(l_tmp32);
        return NTRNT_STATUS_OK;
}
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
tracker_udp::tracker_udp(session& a_session):
        tracker(a_session),
        m_gc_udp_rqst_list()
{
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
tracker_udp::~tracker_udp(void)
{
        for(auto && i_r : m_gc_udp_rqst_list)
        {
                if (i_r) { delete i_r; i_r = nullptr; }
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! \notes:   ref: https://www.bittorrent.org/beps/bep_0015.html
//! ----------------------------------------------------------------------------
int32_t tracker_udp::announce(void)
{
        int32_t l_s;
        // -------------------------------------------------
        // create announce
        // -------------------------------------------------
        tracker_udp_rqst* l_rqst = new tracker_udp_rqst(*this);
        l_rqst->m_type = tracker_udp_rqst::TYPE_ANNOUNCE;
        l_rqst->m_state = tracker_udp_rqst::STATE_FREE;
        // -------------------------------------------------
        // add transaction id to session
        // -------------------------------------------------
        m_session.m_tid_tracker_udp_map[l_rqst->m_tid] = l_rqst;
        // TODO -used for gc -fix!!!
        m_gc_udp_rqst_list.push_back(l_rqst);
        // -------------------------------------------------
        // run dns resolution inline for now
        // -------------------------------------------------
        l_s = l_rqst->setup();
        if (l_s != NTRNT_STATUS_OK)
        {
                return NTRNT_STATUS_ERROR;
        }
        l_rqst->m_state = tracker_udp_rqst::STATE_CONNECTING;
        // -------------------------------------------------
        // send connect
        // -------------------------------------------------
        l_s = l_rqst->send_connect();
        if (l_s != NTRNT_STATUS_OK)
        {
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_udp::scrape(void)
{
        int32_t l_s;
        // -------------------------------------------------
        // create announce
        // -------------------------------------------------
        tracker_udp_rqst* l_rqst = new tracker_udp_rqst(*this);
        l_rqst->m_type = tracker_udp_rqst::TYPE_SCRAPE;
        l_rqst->m_state = tracker_udp_rqst::STATE_FREE;
        // -------------------------------------------------
        // add transaction id to session
        // -------------------------------------------------
        m_session.m_tid_tracker_udp_map[l_rqst->m_tid] = l_rqst;
        // TODO -used for gc -fix!!!
        m_gc_udp_rqst_list.push_back(l_rqst);
        // -------------------------------------------------
        // run dns resolution inline for now
        // -------------------------------------------------
        l_s = l_rqst->setup();
        if (l_s != NTRNT_STATUS_OK)
        {
                return NTRNT_STATUS_ERROR;
        }
        l_rqst->m_state = tracker_udp_rqst::STATE_CONNECTING;
        // -------------------------------------------------
        // send connect
        // -------------------------------------------------
        l_s = l_rqst->send_connect();
        if (l_s != NTRNT_STATUS_OK)
        {
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_udp::handle_resp(tid_tracker_udp_map_t& a_map,
                                 uint8_t* a_msg,
                                 uint32_t a_msg_len)
{
        off_t l_off = 0;
        // -------------------------------------------------
        // read action/tx id
        // common across udp tracker resp messages
        // -------------------------------------------------
        // -------------------------------------------------
        // 32 action                       0 (connect) 1 (announce)
        // 32 transaction_id            <ID>
        // -------------------------------------------------
        uint32_t l_aid = bswap_32((*((uint32_t*)(a_msg+l_off))));
        l_off+= sizeof(l_aid);
        uint32_t l_tid = bswap_32((*((uint32_t*)(a_msg+l_off))));
        l_off+= sizeof(l_tid);
        // -------------------------------------------------
        // look up rqst based on tid
        // -------------------------------------------------
        tracker_udp_rqst* l_rqst = nullptr;
        auto i_rqst = a_map.find(l_tid);
        if (i_rqst == a_map.end())
        {
                TRC_ERROR("receieved udp tracker message w/o associated tid for request\n");
                return NTRNT_STATUS_ERROR;
        }
        l_rqst = i_rqst->second;
        // -------------------------------------------------
        // handle resp
        // -------------------------------------------------
        int32_t l_s;
        l_s = l_rqst->handle_resp(a_msg, a_msg_len);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing handle_resp");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // cleanup if done
        // -------------------------------------------------
        if (l_rqst->m_state == tracker_udp_rqst::STATE_DONE)
        {
                a_map.erase(i_rqst);
                // TODO -handled by gc elswhere
                // delete l_rqst;
                // l_rqst = nullptr;
        }
        return NTRNT_STATUS_OK;
}
}
