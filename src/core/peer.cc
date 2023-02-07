//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
// ---------------------------------------------------------
// libutp includes
// ---------------------------------------------------------
#include "libutp/utp.h"
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
#include "support/net_util.h"
#include "support/btfield.h"
#include "support/nbq.h"
#include "support/peer_id.h"
#include "bencode/bencode.h"
#include "core/session.h"
#include "core/pickr.h"
#include "core/peer_mgr.h"
#include "core/peer.h"
#include "core/phe.h"
//! ----------------------------------------------------------------------------
//! bittorrent protocol
//! ----------------------------------------------------------------------------
#define _PEER_INQ_BSIZE (8*1024)
#define _PEER_OUTQ_BSIZE (32*1024)
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::vector<uint8_t> uint8_vec_t;
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                       T I M E R   C A L L B A C K S
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t _timeout(void *a_data)
{
        //NDBG_PRINT("[%sTIMEOUT!!!%s]: ...\n", ANSI_COLOR_BG_MAGENTA, ANSI_COLOR_OFF);
        if(!a_data)
        {
                return NTRNT_STATUS_ERROR;
        }
        peer* l_peer = static_cast<peer*>(a_data);
        l_peer->shutdown(peer::ERROR_TIMEOUT);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                    S T A T I C   F U N C T I O N S
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t _decrypt_filter_cb(void* a_ctx, char* a_buf, size_t a_len)
{
        if (!a_ctx)
        {
                TRC_ERROR("a_ctx == null");
                return NTRNT_STATUS_ERROR;
        }
        peer* l_peer = (peer*)a_ctx;
        phe* l_phe = (phe*)(l_peer->get_phe());
        if (!l_phe)
        {
                TRC_ERROR("phe == null");
                return NTRNT_STATUS_ERROR;
        }
        int32_t l_s;
        l_s = l_phe->decrypt((uint8_t*)a_buf, a_len);
        if (l_s < 0)
        {
                TRC_ERROR("performing phe read\n");
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t _encrypt_filter_cb(void* a_ctx, char* a_buf, size_t a_len)
{
        if (!a_ctx)
        {
                TRC_ERROR("a_ctx == null");
                return NTRNT_STATUS_ERROR;
        }
        peer* l_peer = (peer*)a_ctx;
        phe* l_phe = (phe*)(l_peer->get_phe());
        if (!l_phe)
        {
                TRC_ERROR("phe == null");
                return NTRNT_STATUS_ERROR;
        }
        int32_t l_s;
        l_s = l_phe->encrypt((uint8_t*)a_buf, a_len);
        if (l_s < 0)
        {
                TRC_ERROR("performing phe read\n");
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static bool _is_handshake(const uint8_t*a_buf, size_t a_len)
{
        if (memcmp(a_buf, g_btp_str, sizeof(g_btp_str)) == 0)
        {
                return true;
        }
        return false;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int peer_phe_select_skey_cb(void* a_ctx, void* a_cb_ctx, void* a_buf, size_t a_len)
{
        if (!a_ctx ||
            !a_cb_ctx)
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get peer
        // -------------------------------------------------
        phe* l_phe = (phe*)a_ctx;
        peer* l_peer = (peer*)a_cb_ctx;
        const uint8_t* l_info_hash = l_peer->get_session().get_info_hash();
        l_phe->set_skey(l_info_hash, sizeof(id_t));
        return NTRNT_STATUS_OK;
}
}
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
peer::peer(peer_from_t a_from,
           session& a_session,
           peer_mgr& a_peer_mgr,
           const sockaddr_storage& a_sas):
        m_from(a_from),
        m_session(a_session),
        m_peer_mgr(a_peer_mgr),
        m_state(STATE_NONE),
        m_error(ERROR_NONE),
        m_num_block_rqst_inflight(0),
        m_sas(a_sas),
        m_host("__na__"),
        m_in_q(_PEER_INQ_BSIZE),
        m_out_q(_PEER_OUTQ_BSIZE),
        m_timer(nullptr),
        m_utp_conn(nullptr),
        m_phe(nullptr),
        m_handshake(),
        m_btp_ltep(false),
        m_btp_fext(false),
        m_btp_dht(false),
        m_btp_info_hash(),
        m_btp_peer_id(),
        m_btp_peer_str("__na__"),
        m_btp_pieces_have(),
        m_btp_am_choking(true),
        m_btp_am_interested(false),
        m_btp_peer_choking(true),
        m_btp_peer_interested(false),
        m_btp_cmd_flag(false),
        m_btp_cmd_len(),
        m_btp_cmd(),
        m_ltep_handshake(nullptr),
        m_ltep_handshake_len(0),
        m_ltep_encryption(false),
        m_ltep_metadata_size(0),
        m_ltep_reqq(NTRNT_SESSION_PEER_MAX_INFLIGHT),
        m_ltep_upload_only(false),
        m_ltep_peer_id(),
        m_ltep_complete_ago(0),
        m_ltep_peer_port(0),
        m_ltep_msg_support_ut_metadata(false),
        m_ltep_msg_support_ut_pex(false),
        m_ltep_msg_support_ut_holepunch(false),
        m_ltep_ut_metadata_id(LTEP_CMD_METADATA),
        m_ltep_ut_pex_id(LTEP_CMD_PEX),
        m_ltep_ut_holepunch_id(0),
        m_stat_expired_br(0),
        m_stat_bytes_sent(0),
        m_stat_bytes_sent_last(0),
        m_stat_bytes_sent_per_s(0),
        m_stat_bytes_recv(0),
        m_stat_bytes_recv_last(0),
        m_stat_bytes_recv_per_s(0),
        m_stat_last_recvd_time_s(0),
        m_geoip2_country("__na__"),
        m_geoip2_city("__na__"),
        m_geoip2_lat(0.0),
        m_geoip2_lon(0.0)
{
        m_host = sas_to_str(a_sas);
        btp_create_handshake();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
peer::~peer(void)
{
        int32_t l_s;
        // -------------------------------------------------
        // removing inflight block rqsts
        // -------------------------------------------------
        block_rqst_vec_t l_brv;
        l_s = m_session.get_pickr().rm_ctx(this, l_brv);
        UNUSED(l_s);
        UNUSED(l_brv);
        // -------------------------------------------------
        // clean up phe
        // -------------------------------------------------
        if (m_phe)
        {
                delete m_phe;
                m_phe = nullptr;
        }
        if (m_ltep_handshake)
        {
                free(m_ltep_handshake);
                m_ltep_handshake = nullptr;
                m_ltep_handshake_len = 0;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void peer::reset(void)
{
        // -------------------------------------------------
        // removing inflight block rqsts
        // -------------------------------------------------
        int32_t l_s;
        block_rqst_vec_t l_brv;
        l_s = m_session.get_pickr().rm_ctx(this, l_brv);
        UNUSED(l_s);
        UNUSED(l_brv);
        // -------------------------------------------------
        // state
        // -------------------------------------------------
        m_state = STATE_NONE;
        m_num_block_rqst_inflight = 0;
        // -------------------------------------------------
        // reset queues
        // -------------------------------------------------
        m_in_q.reset_write();
        m_out_q.reset_write();
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        m_session.cancel_timer(m_timer);
        // -------------------------------------------------
        // cleanup utp state
        // -------------------------------------------------
        if (m_utp_conn)
        {
                utp_set_userdata(m_utp_conn, nullptr);
                utp_close(m_utp_conn);
                m_utp_conn = nullptr;
        }
        // -------------------------------------------------
        // cleanup phe
        // -------------------------------------------------
        if (m_phe)
        {
                delete m_phe;
                m_phe = nullptr;
        }
        // -------------------------------------------------
        // reset state
        // -------------------------------------------------
        m_btp_ltep = false;
        m_btp_fext = false;
        m_btp_dht = false;
        //m_btp_info_hash
        //m_btp_peer_id
        m_btp_peer_str = "__na__";
        m_btp_pieces_have.clear_all();
        m_btp_am_choking = true;
        m_btp_am_interested = false;
        m_btp_peer_choking = true;
        m_btp_peer_interested = false;
        m_btp_cmd_flag = false;
        m_btp_cmd_len = 0;
        m_btp_cmd = 0;
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        //m_ltep_handshake
        //m_ltep_handshake_len
        m_ltep_encryption = false;
        m_ltep_metadata_size = 0;
        m_ltep_reqq = NTRNT_SESSION_PEER_MAX_INFLIGHT;
        m_ltep_upload_only = false;
        m_ltep_peer_id.clear();
        m_ltep_complete_ago = 0;
        m_ltep_peer_port = 0;
        m_ltep_msg_support_ut_metadata = false;
        m_ltep_msg_support_ut_pex = false;
        m_ltep_msg_support_ut_holepunch = false;
        m_ltep_ut_metadata_id = LTEP_CMD_METADATA;
        m_ltep_ut_pex_id = LTEP_CMD_PEX;
        m_ltep_ut_holepunch_id = 0;
        // -------------------------------------------------
        // stats
        // -------------------------------------------------
        m_stat_expired_br = 0;
        m_stat_bytes_sent = 0;
        m_stat_bytes_sent_last = 0;
        m_stat_bytes_sent_per_s = 0;
        m_stat_bytes_recv = 0;
        m_stat_bytes_recv_last = 0;
        m_stat_bytes_recv_per_s = 0;
        m_stat_last_recvd_time_s = 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::connect(void)
{
        int32_t l_s;
        // -------------------------------------------------
        // phe setup
        // TODO -only if phe enabled???
        //      -otherwise cleartext
        // -------------------------------------------------
        if (m_phe) { delete m_phe; m_phe = nullptr; }
        m_phe = new phe();
        l_s = m_phe->init();
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing phe init");
                return NTRNT_STATUS_ERROR;
        }
        m_phe->set_cb_data(this);
        m_phe->set_skey(m_session.get_info_hash(), sizeof(id_t));
        m_phe->set_ia(m_handshake, sizeof(m_handshake));
        // -------------------------------------------------
        // utp setup
        // -------------------------------------------------
        // TODO wrap in "if utp" or in separate utp connect
        m_utp_conn = utp_create_socket(m_session.get_utp_ctx());
        if (!m_utp_conn)
        {
                TRC_ERROR("performing utp_create_socket");
                return NTRNT_STATUS_ERROR;
        }
        void* l_ptr;
        l_ptr = utp_set_userdata(m_utp_conn, this);
        // TODO -check return???
        UNUSED(l_ptr);
        // -------------------------------------------------
        // kick off timeout
        // -------------------------------------------------
        l_s = add_timer(NTRNT_PEER_CONNECT_TIMEOUT);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing add_timer");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // utp connect
        // -------------------------------------------------
        //NDBG_PRINT("[%sUTP%s]: [HOST: %s] CONNECT\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_host.c_str());
        l_s = utp_connect(m_utp_conn, (const sockaddr*)(&m_sas), sas_size(m_sas));
        if (l_s != 0)
        {
                TRC_ERROR("performing utp_connect");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // tcp conn...
        // -------------------------------------------------
        // TODO wrap in "if tcp" or in separate tcp connect
#if 0
        auto peer_io = tr_peerIo::create(session, parent, &info_hash, false, is_seed);
        if (!peer_io->socket_.is_valid())
        {
                if (auto sock = tr_netOpenPeerSocket(session, addr, port, is_seed); sock.is_valid())
                {
                        peer_io->set_socket(std::move(sock));
                        return peer_io;
                }
        }
#endif
        m_state = STATE_UTP_CONNECTING;
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::accept_utp(void *a_ctx)
{
        // -------------------------------------------------
        // phe setup
        // TODO -only if phe enabled???
        //      -otherwise cleartext
        // -------------------------------------------------
        if (m_phe) { delete m_phe; m_phe = nullptr; }
        int32_t l_s;
        m_phe = new phe();
        l_s = m_phe->init();
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing phe init");
                return NTRNT_STATUS_ERROR;
        }
        m_phe->set_cb_data(this);
        m_phe->set_ia(m_handshake, sizeof(m_handshake));
        // -------------------------------------------------
        // utp setup
        // -------------------------------------------------
        m_utp_conn = (utp_socket*)a_ctx;
        void* l_ptr;
        l_ptr = utp_set_userdata(m_utp_conn, this);
        // TODO -check return???
        UNUSED(l_ptr);
        // -------------------------------------------------
        // kick off timeout
        // -------------------------------------------------
        l_s = add_timer(NTRNT_PEER_CONNECT_TIMEOUT);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing add_timer");
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
uint64_t peer::utp_cb(utp_socket* a_utp_conn,
                      int a_type,
                      int a_state,
                      const uint8_t* a_buf,
                      size_t a_len)
{
        //NDBG_PRINT("[UTP] [HOST: %s]: type: %d state: %d\n", m_host.c_str(), a_type, a_state);
        // -------------------------------------------------
        // for msg type...
        // -------------------------------------------------
        switch(a_type)
        {
        // -------------------------------------------------
        // UTP_ON_OVERHEAD_STATISTICS
        // -------------------------------------------------
        case UTP_ON_OVERHEAD_STATISTICS:
        {
                //NDBG_PRINT("[%sUTP%s]: ON_OVERHEAD_STATISTICS: direction: %d len: %lu\n",
                //           ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF,
                //           a_args->send,
                //           a_args->len);
                // TODO
#if 0
                tr_logAddTraceIo(io, fmt::format("{:d} overhead bytes via utp", args->len));
                io->bandwidth().notifyBandwidthConsumed(args->u1.send != 0 ? TR_UP : TR_DOWN, args->len, false, tr_time_msec());
#endif
                break;
        }
        // -------------------------------------------------
        // UTP_ON_STATE_CHANGE
        // -------------------------------------------------
        case UTP_ON_STATE_CHANGE:
        {
                //NDBG_PRINT("[%sUTP%s]: ON_STATE_CHANGE: state: %d\n",
                //           ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF,
                //           a_state);
                switch(a_state)
                {
                // -----------------------------------------
                // UTP_STATE_CONNECT
                // -----------------------------------------
                case UTP_STATE_CONNECT:
                {
                        switch(m_state)
                        {
                        // ---------------------------------
                        // STATE_NONE
                        // ---------------------------------
                        case STATE_UTP_CONNECTING:
                        {
                                // set state to setup
                                m_state = STATE_PHE_SETUP;
                                //NDBG_PRINT("[%sUTP%s]: ON_STATE_CHANGE: state: CONNECT\n", ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF);
                                // set state to none -indicates outbound
                                m_phe->set_state(phe::PHE_STATE_NONE);
                                // setup channel
                                int32_t l_s;
                                l_s = m_phe->connect(m_in_q, m_out_q);
                                if (l_s == NTRNT_STATUS_AGAIN)
                                {
                                        return NTRNT_STATUS_OK;
                                }
                                else if (l_s != NTRNT_STATUS_OK)
                                {
                                        TRC_ERROR("performing phe connect");
                                        return NTRNT_STATUS_ERROR;
                                }
                                // send handhake
                                // utp support for peer
                                break;
                        }
                        // ---------------------------------
                        // default
                        // ---------------------------------
                        default:
                        {
                                TRC_ERROR("STATE_CONNECT from peer state[%d] != STATE_UTP_CONNECTING", m_state);
                                break;
                        }
                        }
                        break;
                }
                // -----------------------------------------
                // UTP_STATE_WRITABLE
                // -----------------------------------------
                case UTP_STATE_WRITABLE:
                {
                        //NDBG_PRINT("[%sUTP%s]: [HOST: %s] ON_STATE_CHANGE: state: WRITABLE\n",
                        //           ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_host.c_str());
                        break;
                }
                // -----------------------------------------
                // UTP_STATE_EOF
                // -----------------------------------------
                case UTP_STATE_EOF:
                {
                        //NDBG_PRINT("[%sUTP%s]: [HOST: %s] ON_STATE_CHANGE: state: EOF\n",
                        //           ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_host.c_str());
                        shutdown(ERROR_EOF);
                        return NTRNT_STATUS_DONE;
                }
                // -----------------------------------------
                // UTP_STATE_DESTROYING
                // -----------------------------------------
                case UTP_STATE_DESTROYING:
                {
                        //NDBG_PRINT("[%sUTP%s]: [HOST: %s] ON_STATE_CHANGE: state: DESTROYING\n",
                        //           ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_host.c_str());
                        break;
                }
                // -----------------------------------------
                // default
                // -----------------------------------------
                default:
                {
                        NDBG_PRINT("[%sUTP%s]: [HOST: %s] ON_STATE_CHANGE: state: ???\n",
                                   ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_host.c_str());
                        break;
                }
                }
                break;
        }
        // -------------------------------------------------
        // UTP_ON_READ
        // -------------------------------------------------
        case UTP_ON_READ:
        {
                //NDBG_PRINT("[%sUTP%s]: [HOST: %s] ON_READ: len: %lu\n",
                //           ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF,
                //           m_host.c_str(),
                //           a_len);
                int32_t l_s;
                l_s = utp_read(a_buf, a_len);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing utp_read");
                        return NTRNT_STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // UTP_GET_READ_BUFFER_SIZE
        // -------------------------------------------------
        case UTP_GET_READ_BUFFER_SIZE:
        {
                //NDBG_PRINT("[%sUTP%s]: GET_READ_BUFFER_SIZE: ???\n",
                //           ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF);
                return m_in_q.read_avail();
        }
        // -------------------------------------------------
        // UTP_LOG
        // -------------------------------------------------
        case UTP_LOG:
        {
                // TODO unused if trace not enabled???
                break;
        }
        // -------------------------------------------------
        // UTP_ON_ERROR
        // -------------------------------------------------
        case UTP_ON_ERROR:
        {
                // TODO unused if trace not enabled???
                TRC_ERROR("[HOST: %s] error", m_host.c_str());
                break;
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        default:
        {
                TRC_ERROR("[HOST: %s] unhandled utp msg type: %d", m_host.c_str(), a_type);
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
int32_t peer::utp_read(const uint8_t* a_buf, size_t a_len)
{
        //NDBG_PRINT("[%s---------READ-------%s]: [HOST: %s] ON_READ: len: %lu\n",
        //           ANSI_COLOR_BG_CYAN, ANSI_COLOR_OFF,
        //           m_host.c_str(),
        //           a_len);
        // -------------------------------------------------
        // stats
        // -------------------------------------------------
        m_stat_bytes_recv += a_len;
        m_stat_last_recvd_time_s = get_time_s();
        // -------------------------------------------------
        // write in
        // -------------------------------------------------
        m_in_q.write((const char*)a_buf, a_len);
        // -------------------------------------------------
        // loop until AGAIN
        // -------------------------------------------------
        while(true)
        {
        //NDBG_PRINT("[%s---------READ-------%s]: [HOST: %s] ON_READ: len: %lu state: %d\n",
        //           ANSI_COLOR_FG_CYAN, ANSI_COLOR_OFF,
        //           m_host.c_str(),
        //           a_len,
        //           m_state);
        switch(m_state)
        {
        // -------------------------------------------------
        // STATE_NONE
        // -------------------------------------------------
        case STATE_NONE:
        {
                TRC_ERROR("UTP_ON_READ: peer state == STATE_NONE");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // PHE_CONNECTING
        // -------------------------------------------------
        case STATE_PHE_SETUP:
        {
                // peek buffer for clear text
                if (_is_handshake(a_buf, a_len))
                {
                        return NTRNT_STATUS_ERROR;
                        //m_state = STATE_HANDSHAKING;
                        //goto on_read;
                }
                m_state = STATE_PHE_CONNECTING;
                break;
        }
        // -------------------------------------------------
        // STATE_NONE
        // -------------------------------------------------
        case STATE_PHE_CONNECTING:
        {
                int32_t l_s;
                //NDBG_PRINT("[PHE] CONNECT\n");
                l_s = m_phe->connect(m_in_q, m_out_q);
                if (l_s == NTRNT_STATUS_AGAIN)
                {
                        return NTRNT_STATUS_OK;
                }
                else if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing phe connect");
                        return NTRNT_STATUS_ERROR;
                }
                // -----------------------------------------
                // mark as handshaking set write filter
                // -----------------------------------------
                if (m_phe->get_state() == phe::PHE_STATE_CONNECTED)
                {
                        //NDBG_PRINT("SET DECRYPT FILTER\n");
                        m_in_q.set_filter_cb(_decrypt_filter_cb, this);
                        m_out_q.set_filter_cb(_encrypt_filter_cb, this);
                        m_state = STATE_HANDSHAKING;
                }
                // -----------------------------------------
                // check for ia
                // -----------------------------------------
                const uint8_t* l_ia_buf;
                size_t l_ia_len;
                m_phe->get_recvd_ia(&l_ia_buf, l_ia_len);
                if (l_ia_buf &&
                    (l_ia_len >= NTRNT_PEER_HANDSHAKE_SIZE))
                {
                        l_s = btp_parse_handshake_ia(l_ia_buf, l_ia_len);
                        if (l_s != NTRNT_STATUS_OK)
                        {
                                if (l_s == NTRNT_STATUS_AGAIN)
                                {
                                        // need more data
                                        NDBG_PRINT("NEED MORE DATA\n");
                                        return NTRNT_STATUS_OK;
                                }
                                TRC_ERROR("performing _parse_handshake");
                                return NTRNT_STATUS_ERROR;
                        }
                        // ---------------------------------
                        // connected
                        // ---------------------------------
                        m_state = STATE_CONNECTED;
                        // -----------------------------------------
                        // reset timer
                        // -----------------------------------------
                        int32_t l_s;
                        l_s = cancel_timer();
                        if (l_s != NTRNT_STATUS_OK)
                        {
                                TRC_ERROR("performing cancel_timer");
                                return NTRNT_STATUS_ERROR;
                        }
                }
                break;
        }
        // -------------------------------------------------
        // HANDSHAKING
        // -------------------------------------------------
        case STATE_HANDSHAKING:
        {
                //NDBG_PRINT("[%sUTP%s]: [HOST: %s] HANDSHAKE!\n",
                //           ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF,
                //           m_host.c_str());
                // -----------------------------------------
                // parse handshake
                // -----------------------------------------
                //NDBG_PRINT("INQ READAVAIL: %lu\n", m_in_q.read_avail());
                int32_t l_s;
                l_s = btp_parse_handshake();
                if (l_s != NTRNT_STATUS_OK)
                {
                        if (l_s == NTRNT_STATUS_AGAIN)
                        {
                                // need more data
                                //NDBG_PRINT("NEED MORE DATA\n");
                                return NTRNT_STATUS_OK;
                        }
                        //TRC_ERROR("performing _parse_handshake");
                        return NTRNT_STATUS_ERROR;
                }
                // -----------------------------------------
                // connected
                // -----------------------------------------
                m_state = STATE_CONNECTED;
                // -----------------------------------------
                // reset timer
                // -----------------------------------------
                l_s = cancel_timer();
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing cancel_timer");
                        return NTRNT_STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // STATE_CONNECTED
        // -------------------------------------------------
        case STATE_CONNECTED:
        {
                //NDBG_PRINT("[%sUTP%s]: [HOST: %s] CONNECTED!!\n",
                //           ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF,
                //           m_host.c_str());
                // -----------------------------------------
                // process
                // -----------------------------------------
                int32_t l_s;
                l_s = btp_read_until();
                if (l_s == NTRNT_STATUS_AGAIN)
                {
                        return NTRNT_STATUS_OK;
                }
                else if (l_s != NTRNT_STATUS_OK)
                {
                        return NTRNT_STATUS_ERROR;
                }
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                NDBG_PRINT("[%sUTP%s]: [HOST: %s] UNHANDLED STATE: %u\n",
                           ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF,
                           m_host.c_str(),
                           m_state);
                return NTRNT_STATUS_OK;
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
void peer::shutdown(error_t a_reason)
{
        if (m_state == STATE_NONE)
        {
                return;
        }
        m_error = a_reason;
        reset();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::cancel_timer(void)
{
        int32_t l_s;
        // -------------------------------------------------
        // cancel last
        // -------------------------------------------------
        if (m_timer)
        {
                l_s = m_session.cancel_timer(m_timer);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing cancel_timer");
                        return NTRNT_STATUS_ERROR;
                }
                m_timer = nullptr;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::add_timer(uint32_t a_ms)
{
        // -------------------------------------------------
        // add new
        // -------------------------------------------------
        int32_t l_s;
        l_s = m_session.add_timer(a_ms,
                                  _timeout,
                                  (void*)this,
                                  &m_timer);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing add_timer");
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                B I T T O R R E N T   P R O T O C O L
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void peer::btp_create_handshake(void)
{
        // -------------------------------------------------
        // handshake format:
        // =================================================
        // 20 - "<character 19 (decimal)>BitTorrent protocol"
        // 28 - 8 reserved bytes (flags -including extensions)
        // 48 - 20 byte sha1 infohash
        // 68 - 20 byte peer id
        // =================================================
        // ref:
        // - https://www.bittorrent.org/beps/bep_0003.html#peer-protocol
        // - https://wiki.theory.org/BitTorrentSpecification#Handshake
        // -------------------------------------------------
        memset(m_handshake, 0, NTRNT_PEER_HANDSHAKE_SIZE);
        off_t l_off = 0;
        // -------------------------------------------------
        // preamble
        // -------------------------------------------------
        static const uint8_t s_msg_pre = (uint8_t)19;
        static const char s_msg_preamble[20] = "BitTorrent protocol";
        memcpy(m_handshake+l_off, &s_msg_pre, sizeof(s_msg_pre));
        l_off += sizeof(s_msg_pre);
        memcpy(m_handshake+l_off, s_msg_preamble, sizeof(s_msg_preamble)-1);
        l_off += sizeof(s_msg_preamble)-1;
        // -------------------------------------------------
        // flags
        // -------------------------------------------------
        btfield l_btfield;
        l_btfield.set_size(64);
        l_btfield.set(_BT_RSVD_BITS_LTEP, true);
        // TODO -no support for now
        l_btfield.set(_BT_RSVD_BITS_FEXT, false);
        // TODO -no support for now
        l_btfield.set(_BT_RSVD_BITS_DHT, false);
        int32_t l_s;
        size_t l_len;
        uint8_t *l_buf = nullptr;
        l_s = l_btfield.export_raw(&l_buf, l_len);
        UNUSED(l_s);
        memcpy(m_handshake+l_off, l_buf, l_len);
        l_off += l_len;
        // -------------------------------------------------
        // infohash
        // -------------------------------------------------
        memcpy(m_handshake+l_off, m_session.get_info_hash(), sizeof(id_t));
        l_off += sizeof(id_t);
        // -------------------------------------------------
        // peer id
        // -------------------------------------------------
        const std::string& l_pid = m_session.get_peer_id();
        memcpy(m_handshake+l_off, l_pid.data(), l_pid.length());
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_parse_handshake_ia(const uint8_t* a_buf, size_t a_len)
{
        // -------------------------------------------------
        // check len
        // -------------------------------------------------
        if (a_len < NTRNT_PEER_HANDSHAKE_SIZE)
        {
                return NTRNT_STATUS_AGAIN;
        }
        // -------------------------------------------------
        // check appears to be handshake
        // -------------------------------------------------
        size_t l_off = 0;
        bool l_f = false;
        l_f = _is_handshake(a_buf+l_off, 20);
        if (!l_f)
        {
                TRC_ERROR("performing _is_handshake");
                return NTRNT_STATUS_ERROR;
        }
        l_off += 20;
        // -------------------------------------------------
        // read flags
        // -------------------------------------------------
        int32_t l_s;
        btfield l_btfield;
        l_s = l_btfield.import_raw((const uint8_t*)(a_buf+l_off), 8, 64);
        l_off += 8;
        m_btp_ltep = l_btfield.test(_BT_RSVD_BITS_LTEP);
        m_btp_fext = l_btfield.test(_BT_RSVD_BITS_FEXT);
        m_btp_dht = l_btfield.test(_BT_RSVD_BITS_DHT);
        //NDBG_PRINT("HANDSHAKE: flags: ltep: %s\n", m_btp_ltep?"true":"false");
        //NDBG_PRINT("HANDSHAKE: flags: fext: %s\n", m_btp_ltep?"true":"false");
        //NDBG_PRINT("HANDSHAKE: flags: dht:  %s\n", m_btp_dht?"true":"false");
        // -------------------------------------------------
        // read info hash
        // -------------------------------------------------
        memcpy(m_btp_info_hash.m_data, a_buf+l_off, sizeof(m_btp_info_hash));
        l_off += sizeof(m_btp_info_hash);
        // -------------------------------------------------
        // read peer id
        // -------------------------------------------------
        memcpy(m_btp_peer_id.m_data, a_buf+l_off, sizeof(m_btp_peer_id));
        l_off += sizeof(m_btp_peer_id);
        m_btp_peer_str = peer_id_to_str(m_btp_peer_id);
        // -------------------------------------------------
        // check for self
        // -------------------------------------------------
        if (memcmp(m_btp_peer_id.m_data, m_session.get_peer_id().c_str(), sizeof(m_btp_peer_id)) == 0)
        {
                m_error = ERROR_HANDSHAKE_SELF;
                // -----------------------------------------
                // check for session self address
                // -----------------------------------------
                const std::string& l_self = m_session.get_ext_address();
                if (l_self.empty())
                {
                        m_session.set_ext_address(sas_to_str(m_sas));
                }
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // send ltep handshake if supported
        // -------------------------------------------------
        // TODO FIX!!!
#if 0
        if (m_btp_ltep)
        {
                l_s = ltep_send_handshake();
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing ltep_send_handshake");
                        return NTRNT_STATUS_ERROR;
                }
                l_s = ltep_send_pex();
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing ltep_send_pex");
                        return NTRNT_STATUS_ERROR;
                }
        }
#endif
        // -------------------------------------------------
        // send btfield
        // -------------------------------------------------
        l_s = btp_send_bitfield();
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing btp_send_bitfield");
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_parse_handshake(void)
{
        // -------------------------------------------------
        // find needle
        // -------------------------------------------------
        size_t l_discarded = 0;
        while (true)
        {
                if (m_in_q.read_avail() < NTRNT_PEER_HANDSHAKE_SIZE)
                {
                        return NTRNT_STATUS_AGAIN;
                }
                if (m_in_q.starts_with((const char*)g_btp_str, sizeof(g_btp_str)))
                {
                        break;
                }
                m_in_q.discard(1);
                ++l_discarded;
        }
        // -------------------------------------------------
        // read into buf
        // -------------------------------------------------
        size_t l_off = 0;
        uint8_t l_buf[NTRNT_PEER_HANDSHAKE_SIZE];
        m_in_q.read((char*)l_buf, NTRNT_PEER_HANDSHAKE_SIZE);
        l_off += 20;
        // -------------------------------------------------
        // read flags
        // -------------------------------------------------
        int32_t l_s;
        btfield l_btfield;
        l_s = l_btfield.import_raw((const uint8_t*)(l_buf+l_off), 8, 64);
        l_off += 8;
        m_btp_ltep = l_btfield.test(_BT_RSVD_BITS_LTEP);
        m_btp_fext = l_btfield.test(_BT_RSVD_BITS_FEXT);
        m_btp_dht = l_btfield.test(_BT_RSVD_BITS_DHT);
        //NDBG_PRINT("HANDSHAKE: flags: ltep: %s\n", m_btp_ltep?"true":"false");
        //NDBG_PRINT("HANDSHAKE: flags: fext: %s\n", m_btp_ltep?"true":"false");
        //NDBG_PRINT("HANDSHAKE: flags: dht:  %s\n", m_btp_dht?"true":"false");
        // -------------------------------------------------
        // read info hash
        // -------------------------------------------------
        memcpy(m_btp_info_hash.m_data, l_buf+l_off, sizeof(m_btp_info_hash));
        l_off += sizeof(m_btp_info_hash);
        // -------------------------------------------------
        // read peer id
        // -------------------------------------------------
        memcpy(m_btp_peer_id.m_data, l_buf+l_off, sizeof(m_btp_peer_id));
        l_off += sizeof(m_btp_peer_id);
        m_btp_peer_str = peer_id_to_str(m_btp_peer_id);
        // -------------------------------------------------
        // check for self
        // -------------------------------------------------
        if (memcmp(m_btp_peer_id.m_data, m_session.get_peer_id().data(), sizeof(m_btp_peer_id)) == 0)
        {
                m_error = ERROR_HANDSHAKE_SELF;
                // -----------------------------------------
                // check for session self address
                // -----------------------------------------
                const std::string& l_self = m_session.get_ext_address();
                if (l_self.empty())
                {
                        m_session.set_ext_address(sas_to_str(m_sas));
                }
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // send ltep handshake if supported
        // -------------------------------------------------
#if 0
        if (m_btp_ltep)
        {
                l_s = ltep_send_handshake();
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing ltep_send_handshake");
                        return NTRNT_STATUS_ERROR;
                }
                l_s = ltep_send_pex();
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing ltep_send_pex");
                        return NTRNT_STATUS_ERROR;
                }
        }
#endif
        // -------------------------------------------------
        // send btfield
        // -------------------------------------------------
        l_s = btp_send_bitfield();
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing btp_send_bitfield");
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_read_until(void)
{
        int32_t l_s;
        do
        {
                l_s = btp_read_cmd();
                if (l_s == NTRNT_STATUS_AGAIN)
                {
                        //NDBG_PRINT("[CMD_READ_UNTIL: break AGAIN.\n");
                        return NTRNT_STATUS_AGAIN;
                }
                if (l_s != NTRNT_STATUS_OK)
                {
                        return NTRNT_STATUS_ERROR;
                }
        } while(true);
        //NDBG_PRINT("[CMD_READ_UNTIL: done...\n");
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_read_cmd(void)
{
        //NDBG_PRINT("[%sBTP COMMAND%s]: [READ_AVAIL: %ld] [CMD: %u] [CMD_LEN: %u]\n",
        //           ANSI_COLOR_BG_MAGENTA, ANSI_COLOR_OFF,
        //           m_in_q.read_avail(),
        //           m_btp_cmd,
        //           m_btp_cmd_len);
        //NDBG_PRINT("[%sBTP COMMAND%s]: NEED MORE!\n", ANSI_COLOR_BG_MAGENTA, ANSI_COLOR_OFF);
#define _CHECK_LEN(_len) do { \
        if (m_in_q.read_avail() < _len) { \
                return NTRNT_STATUS_AGAIN; \
        } } while (0)
        // -------------------------------------------------
        // if not currently processing cmd,
        // read in len+id
        // -------------------------------------------------
        if (!m_btp_cmd_len)
        {
                // -----------------------------------------
                // get len
                // -----------------------------------------
                _CHECK_LEN(sizeof(uint32_t));
                m_in_q.read((char*)&m_btp_cmd_len, sizeof(m_btp_cmd_len));
                m_btp_cmd_len = ntohl(m_btp_cmd_len);
                // -----------------------------------------
                //  keep-alive: <len=0000>
                // -----------------------------------------
                if (!m_btp_cmd_len)
                {
                        return NTRNT_STATUS_OK;
                }
                // -----------------------------------------
                // basic corruption test
                // nothing is requested over 16k really so
                // receiving data > 256k shouldn't happen
                // and could indicate channel is corrupted
                // -----------------------------------------
                if (m_btp_cmd_len > 262144)
                {
                        TRC_ERROR("[HOST: %s] [CLIENT: %s] btp_cmd_len: %d >> than expected -channel could be corrupted",
                                  m_host.c_str(),
                                  m_ltep_peer_id.c_str(),
                                  m_btp_cmd_len);
                        return NTRNT_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // check for command
        // -------------------------------------------------
        if (!m_btp_cmd_flag)
        {
                // -----------------------------------------
                // get id
                // -----------------------------------------
                _CHECK_LEN(sizeof(uint8_t));
                m_in_q.read((char*)&m_btp_cmd, sizeof(m_btp_cmd));
                // -----------------------------------------
                // set in cmd
                // -----------------------------------------
                m_btp_cmd_flag = true;
        }
        // -------------------------------------------------
        // for cmd
        // -------------------------------------------------
        switch(m_btp_cmd)
        {
        // -------------------------------------------------
        // BTP_CMD_CHOKE
        // choke: <len=0001><id=0>
        // -------------------------------------------------
        case BTP_CMD_CHOKE:
        {
                m_btp_peer_choking = true;
                // -----------------------------------------
                // removing inflight block rqsts
                // -----------------------------------------
                int32_t l_s;
                block_rqst_vec_t l_brv;
                l_s = m_session.get_pickr().rm_ctx(this, l_brv);
                UNUSED(l_s);
                UNUSED(l_brv);
                break;
        }
        // -------------------------------------------------
        // BTP_CMD_UNCHOKE
        // unchoke: <len=0001><id=1>
        // -------------------------------------------------
        case BTP_CMD_UNCHOKE:
        {
                //NDBG_PRINT("[BTP] [CMD: BTP_CMD_UNCHOKE]\n");
                m_btp_peer_choking = false;
                break;
        }
        // -------------------------------------------------
        // BTP_CMD_INTERESTED
        // interested: <len=0001><id=2>
        // -------------------------------------------------
        case BTP_CMD_INTERESTED:
        {
                m_btp_peer_interested = true;
                // -----------------------------------------
                // send unchoke
                // -----------------------------------------
                // -----------------------------------------
                // TODO -ask peer manager if can unchoke???
                //       ie if limits on num unchoked peers
                // -----------------------------------------
                int32_t l_s;
                l_s = btp_send_unchoke();
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing btp_send_unchoke");
                        return NTRNT_STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // BTP_CMD_NOT_INTERESTED
        // not interested: <len=0001><id=3>
        // -------------------------------------------------
        case BTP_CMD_NOT_INTERESTED:
        {
                //NDBG_PRINT("[BTP] [CMD: BTP_CMD_NOT_INTERESTED]\n");
                m_btp_peer_interested = false;
                break;
        }
        // -------------------------------------------------
        // BTP_CMD_HAVE
        // have: <len=0005><id=4><piece index>
        // -------------------------------------------------
        case BTP_CMD_HAVE:
        {
                _CHECK_LEN(m_btp_cmd_len-1);
                int32_t l_s;
                l_s = btp_recv_have();
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing btp_recv_have");
                        return NTRNT_STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // BTP_CMD_BITFIELD
        // bitfield: <len=0001+X><id=5><bitfield>
        // -------------------------------------------------
        case BTP_CMD_BITFIELD:
        {
                _CHECK_LEN(m_btp_cmd_len-1);
                int32_t l_s;
                l_s = btp_recv_bitfield();
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing btp_recv_bitfield");
                        return NTRNT_STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // BTP_CMD_REQUEST
        // request: <len=0013><id=6><index><begin><length>
        // -------------------------------------------------
        case BTP_CMD_REQUEST:
        {
                _CHECK_LEN(m_btp_cmd_len-1);
                int32_t l_s;
                l_s = btp_recv_request();
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing btp_recv_request");
                        return NTRNT_STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // BTP_CMD_PIECE
        // piece: <len=0009+X><id=7><index><begin><block>
        // -------------------------------------------------
        case BTP_CMD_PIECE:
        {
                _CHECK_LEN(m_btp_cmd_len-1);
                int32_t l_s;
                l_s = btp_recv_piece();
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing btp_recv_piece");
                        return NTRNT_STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // BTP_CMD_CANCEL
        // cancel: <len=0013><id=8><index><begin><length>
        // -------------------------------------------------
        case BTP_CMD_CANCEL:
        {
                _CHECK_LEN(m_btp_cmd_len-1);
                int32_t l_s;
                l_s = btp_recv_cancel();
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing btp_recv_cancel");
                        return NTRNT_STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // BTP_CMD_PORT
        // port: <len=0003><id=9><listen-port>
        // -------------------------------------------------
        case BTP_CMD_PORT:
        {
                _CHECK_LEN(m_btp_cmd_len-1);
                int32_t l_s;
                l_s = btp_recv_port();
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing btp_recv_port");
                        return NTRNT_STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // *************************************************
        //                    F E X T
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // BTP_CMD_FEXT_SUGGEST
        // TODO: <len=????><id=?><????>
        // -------------------------------------------------
        case BTP_CMD_FEXT_SUGGEST:
        {
                _CHECK_LEN(m_btp_cmd_len-1);
                //NDBG_PRINT("[BTP] [RECV] BTP_CMD_FEXT_SUGGEST\n");
                // TODO discard for now
                m_in_q.discard(m_btp_cmd_len-1);
                break;
        }
        // -------------------------------------------------
        // BTP_CMD_FEXT_HAVE_ALL
        // TODO: <len=????><id=?><????>
        // -------------------------------------------------
        case BTP_CMD_FEXT_HAVE_ALL:
        {
                _CHECK_LEN(m_btp_cmd_len-1);
                //NDBG_PRINT("[BTP] [RECV] BTP_CMD_FEXT_HAVE_ALL\n");
                // TODO discard for now
                m_in_q.discard(m_btp_cmd_len-1);
                break;
        }
        // -------------------------------------------------
        // BTP_CMD_FEXT_HAVE_NONE
        // TODO: <len=????><id=?><????>
        // -------------------------------------------------
        case BTP_CMD_FEXT_HAVE_NONE:
        {
                _CHECK_LEN(m_btp_cmd_len-1);
                //NDBG_PRINT("[BTP] [RECV] BTP_CMD_FEXT_HAVE_NONE\n");
                // TODO discard for now
                m_in_q.discard(m_btp_cmd_len-1);
                break;
        }
        // -------------------------------------------------
        // BTP_CMD_FEXT_REJECT
        // TODO: <len=????><id=?><????>
        // -------------------------------------------------
        case BTP_CMD_FEXT_REJECT:
        {
                _CHECK_LEN(m_btp_cmd_len-1);
                //NDBG_PRINT("[BTP] [RECV] BTP_CMD_FEXT_REJECT\n");
                // TODO discard for now
                m_in_q.discard(m_btp_cmd_len-1);
                break;
        }
        // -------------------------------------------------
        // BTP_CMD_FEXT_ALLOWED_FAST
        // TODO: <len=????><id=?><????>
        // -------------------------------------------------
        case BTP_CMD_FEXT_ALLOWED_FAST:
        {
                _CHECK_LEN(m_btp_cmd_len-1);
                //NDBG_PRINT("[BTP] [RECV] BTP_CMD_FEXT_ALLOWED_FAST\n");
                // TODO discard for now
                m_in_q.discard(m_btp_cmd_len-1);
                break;
        }
        // -------------------------------------------------
        // BTP_CMD_LTEP
        // port: <len=????><id=20><ltep message>
        // -------------------------------------------------
        case BTP_CMD_LTEP:
        {
                _CHECK_LEN(m_btp_cmd_len-1);
                int32_t l_s;
                l_s = ltep_read_cmd();
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing btp_recv_bitfield");
                        return NTRNT_STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // default ???
        // -------------------------------------------------
        default:
        {
                _CHECK_LEN(m_btp_cmd_len-1);
                NDBG_PRINT("[HOST: %s] [CLIENT: %s] [BTP] [RECV] unhandled btp cmd: %u\n",
                           m_host.c_str(),
                           m_ltep_peer_id.c_str(),
                           m_btp_cmd);
                // TODO discard for now
                m_in_q.discard(m_btp_cmd_len-1);
                break;
        }
        }
        // -------------------------------------------------
        // set NOT in cmd
        // -------------------------------------------------
        m_btp_cmd = 0;
        m_btp_cmd_len = 0;
        m_btp_cmd_flag = false;
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_send_keepalive(void)
{
        //NDBG_PRINT("[BTP] [SEND] BTP_KEEPALIVE\n");
        // -------------------------------------------------
        // keep-alive: <len=0000>
        // -------------------------------------------------
        m_out_q.write_n32(0);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_send_choke(void)
{
        //NDBG_PRINT("[BTP] [SEND] BTP_CMD_CHOKE\n");
        // -------------------------------------------------
        // BTP_CMD_CHOKE
        // choke: <len=0001><id=0>
        // -------------------------------------------------
        m_out_q.write_n32(1);
        m_out_q.write_n8(BTP_CMD_CHOKE);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_send_unchoke(void)
{
        //NDBG_PRINT("[BTP] [SEND] BTP_CMD_UNCHOKE\n");
        // -------------------------------------------------
        // BTP_CMD_UNCHOKE
        // unchoke: <len=0001><id=1>
        // -------------------------------------------------
        m_out_q.write_n32(1);
        m_out_q.write_n8(BTP_CMD_UNCHOKE);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_send_interested(void)
{
        //NDBG_PRINT("[BTP] [SEND] BTP_CMD_INTERESTED\n");
        // -------------------------------------------------
        // BTP_CMD_INTERESTED
        // interested: <len=0001><id=2>
        // -------------------------------------------------
        m_out_q.write_n32(1);
        m_out_q.write_n8(BTP_CMD_INTERESTED);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_send_not_interested(void)
{
        //NDBG_PRINT("[BTP] [SEND] BTP_CMD_NOT_INTERESTED\n");
        // -------------------------------------------------
        // BTP_CMD_NOT_INTERESTED
        // not interested: <len=0001><id=3>
        // -------------------------------------------------
        m_out_q.write_n32(1);
        m_out_q.write_n8(BTP_CMD_NOT_INTERESTED);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_send_have(uint32_t a_idx)
{
        //NDBG_PRINT("[BTP] [SEND] BTP_CMD_HAVE\n");
        // -------------------------------------------------
        // BTP_CMD_REQUEST
        // have: <len=0005><id=4><piece index>
        // -------------------------------------------------
        m_out_q.write_n32(5);
        m_out_q.write_n8(BTP_CMD_HAVE);
        m_out_q.write_n32(a_idx);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_send_bitfield(void)
{
        //NDBG_PRINT("[BTP] [SEND] BTP_CMD_BITFIELD\n");
        // -------------------------------------------------
        // get bitfield
        // -------------------------------------------------
        btfield& l_bt = m_session.get_pickr().get_pieces();
        int32_t l_s;
        uint8_t* l_bt_raw;
        size_t l_bt_raw_len;
        l_s = l_bt.export_raw(&l_bt_raw, l_bt_raw_len);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing bitfield export_raw");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // BTP_CMD_BITFIELD
        // bitfield: <len=0001+X><id=5><bitfield>
        // -------------------------------------------------
        m_out_q.write_n32((1+l_bt_raw_len));
        m_out_q.write_n8(BTP_CMD_BITFIELD);
        m_out_q.write((const char*)l_bt_raw, l_bt_raw_len);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_send_request(uint32_t a_idx, uint32_t a_off, uint32_t a_len)
{
        //NDBG_PRINT("[BTP] [SEND] BTP_CMD_REQUEST [IDX: %u] [OFF: %u] [LEN: %u]\n",
        //           a_idx, a_off, a_len);
        // -------------------------------------------------
        // BTP_CMD_REQUEST
        // request: <len=0013><id=6><index><begin><length>
        // -------------------------------------------------
        m_out_q.write_n32(13);
        m_out_q.write_n8(BTP_CMD_REQUEST);
        m_out_q.write_n32(a_idx);
        m_out_q.write_n32(a_off);
        m_out_q.write_n32(a_len);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_send_piece(uint32_t a_idx, uint32_t a_off, uint32_t a_len)
{
        //NDBG_PRINT("[BTP] [SEND] BTP_CMD_PIECE [IDX: %u] [OFF: %u] [len: %u]\n",
        //           a_idx, a_off, a_len);
        // -------------------------------------------------
        // prevent overly large piece sending
        // -------------------------------------------------
        if (a_len > (16*1024*1024))
        {
                TRC_ERROR("requesting piece len %u > 16MB", a_len);
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get buffer for metadata piece
        // -------------------------------------------------
        int32_t l_s;
        const char* l_buf = nullptr;
        l_s = m_session.get_pickr().get_piece(this, a_idx, a_off, a_len, &l_buf);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing pickr get piece: [IDX: %u] [OFF: %u] [len: %u]",
                          a_idx, a_off, a_len);
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // BTP_CMD_PIECE
        // piece: <len=0009+X><id=7><index><begin><block>
        // -------------------------------------------------
        m_out_q.write_n32(9+a_len);
        m_out_q.write_n8(BTP_CMD_PIECE);
        m_out_q.write_n32(a_idx);
        m_out_q.write_n32(a_off);
        m_out_q.write((const char*)l_buf, a_len);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_send_cancel(uint32_t a_idx, uint32_t a_off, uint32_t a_len)
{
        //NDBG_PRINT("[BTP] [SEND] BTP_CMD_CANCEL\n");
        // -------------------------------------------------
        // BTP_CMD_CANCEL
        // cancel: <len=0013><id=8><index><begin><length>
        // -------------------------------------------------
        m_out_q.write_n32(13);
        m_out_q.write_n8(BTP_CMD_CANCEL);
        m_out_q.write_n32(a_idx);
        m_out_q.write_n32(a_off);
        m_out_q.write_n32(a_len);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_recv_have(void)
{
        //NDBG_PRINT("[BTP] [RECV] BTP_CMD_HAVE\n");
        int64_t l_rd;
        // -------------------------------------------------
        // BTP_CMD_HAVE
        // have: <len=0005><id=4><piece index>
        // -------------------------------------------------
        // read index
        uint32_t l_idx;
        l_rd = m_in_q.read((char*)&l_idx, sizeof(l_idx));
        UNUSED(l_rd);
        l_idx = ntohl(l_idx);
        int32_t l_s;
        l_s = m_btp_pieces_have.set(l_idx, true);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("perofrming pieces have set with index: %u -btfield size: %lu",
                          l_idx, m_btp_pieces_have.get_size());
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_recv_bitfield(void)
{
        //NDBG_PRINT("[BTP] [RECV] BTP_CMD_BITFIELD\n");
        // -------------------------------------------------
        // BTP_CMD_BITFIELD
        // bitfield: <len=0001+X><id=5><bitfield>
        // -------------------------------------------------
        uint32_t l_len = m_btp_cmd_len-1;
        char* l_btfield = (char*)malloc(sizeof(char)*l_len);
        int64_t l_rd;
        l_rd = m_in_q.read(l_btfield, l_len);
        //NDBG_HEXDUMP(l_btfield, l_len);
        UNUSED(l_rd);
        int32_t l_s;
        l_s = m_btp_pieces_have.import_raw((const uint8_t*)l_btfield,
                                           l_len,
                                           m_session.get_info_num_pieces());
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing pieces_have.import_raw");
                if (l_btfield) { free(l_btfield); l_btfield = nullptr; }
                return NTRNT_STATUS_ERROR;
        }
        if (l_btfield) { free(l_btfield); l_btfield = nullptr; }
        // -------------------------------------------------
        // TODO check bitfield if really interested
        //      send NOT INTERESTED if not match???
        // -------------------------------------------------
        // for now just sending interested for all
        // -------------------------------------------------
        // send interested
        // -------------------------------------------------
        m_btp_am_interested = true;
        l_s = btp_send_interested();
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing btp_send_interested");
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_recv_piece(void)
{
        //NDBG_PRINT("[BTP] [RECV] BTP_CMD_PIECE\n");
        int64_t l_rd;
        // -------------------------------------------------
        // BTP_CMD_PIECE
        // piece: <len=0009+X><id=7><index><begin><block>
        // -------------------------------------------------
        // read index
        uint32_t l_idx;
        l_rd = m_in_q.read((char*)&l_idx, sizeof(l_idx));
        UNUSED(l_rd);
        l_idx = ntohl(l_idx);
        // read offset
        uint32_t l_off;
        l_rd = m_in_q.read((char*)&l_off, sizeof(l_off));
        UNUSED(l_rd);
        l_off = ntohl(l_off);
        // -------------------------------------------------
        // read piece
        // -------------------------------------------------
        uint32_t l_len = m_btp_cmd_len-1-4-4;
        int32_t l_s;
        //NDBG_PRINT("[BTP] [RECV] BTP_CMD_PIECE [IDX: %u] [OFF: %u] [LEN: %u]\n",
        //           l_idx, l_off, l_len);
        l_s = m_session.get_pickr().recv_piece(this, m_in_q, l_idx, l_off, l_len);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing peer mgr recv_piece");
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_recv_request(void)
{
        //NDBG_PRINT("[BTP] [RECV] BTP_CMD_REQUEST\n");
        int64_t l_rd;
        // -------------------------------------------------
        // BTP_CMD_REQUEST
        // request: <len=0013><id=6><index><begin><length>
        // -------------------------------------------------
        // read index
        uint32_t l_idx;
        l_rd = m_in_q.read((char*)&l_idx, sizeof(l_idx));
        UNUSED(l_rd);
        l_idx = ntohl(l_idx);
        // read offset
        uint32_t l_off;
        l_rd = m_in_q.read((char*)&l_off, sizeof(l_off));
        UNUSED(l_rd);
        l_off = ntohl(l_off);
        // read length
        uint32_t l_len;
        l_rd = m_in_q.read((char*)&l_len, sizeof(l_len));
        UNUSED(l_rd);
        l_len = ntohl(l_len);
        // -------------------------------------------------
        // send piece
        // -------------------------------------------------
        //NDBG_PRINT("[BTP] [RECV] BTP_CMD_REQUEST [IDX: %u] [OFF: %u] [LEN: %u]\n",
        //           l_idx, l_off, l_len);
        int32_t l_s;
        l_s = btp_send_piece(l_idx, l_off, l_len);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing btp_send_piece");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // send piece
        // -------------------------------------------------
        // TODO
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_recv_cancel(void)
{
        //NDBG_PRINT("[BTP] [RECV] BTP_CMD_CANCEL\n");
        int64_t l_rd;
        // -------------------------------------------------
        // BTP_CMD_CANCEL
        // cancel: <len=0013><id=8><index><begin><length>
        // -------------------------------------------------
        // read index
        uint32_t l_idx;
        l_rd = m_in_q.read((char*)&l_idx, sizeof(l_idx));
        UNUSED(l_rd);
        l_idx = ntohl(l_idx);
        // read offset
        uint32_t l_off;
        l_rd = m_in_q.read((char*)&l_off, sizeof(l_off));
        UNUSED(l_rd);
        l_off = ntohl(l_off);
        // read length
        uint32_t l_len;
        l_rd = m_in_q.read((char*)&l_len, sizeof(l_len));
        UNUSED(l_rd);
        l_len = ntohl(l_len);
        //NDBG_PRINT("[BTP] [RECV] BTP_CMD_CANCEL [IDX: %u] [OFF: %u] [LEN: %u]\n",
        //                l_idx, l_off, l_len);
        //NDBG_PRINT("[PEER: %s]\n", m_btp_peer_str.c_str());
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::btp_recv_port(void)
{
        //NDBG_PRINT("[BTP] [RECV] BTP_CMD_PORT\n");
        int64_t l_rd;
        // -------------------------------------------------
        // BTP_CMD_PORT
        // port: <len=0003><id=9><listen-port>
        // -------------------------------------------------
        // read length
        uint16_t l_port;
        l_rd = m_in_q.read((char*)&l_port, sizeof(l_port));
        UNUSED(l_rd);
        l_port = ntohs(l_port);
        //NDBG_PRINT("[BTP] [RECV] BTP_CMD_PORT [PORT: %u]\n", l_port);
        // TODO -add to DHT ??? <peer ip>+<this port>
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                       L T E P   P R O T O C O L
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void peer::ltep_create_handshake(void)
{
        // -------------------------------------------------
        // remove old
        // -------------------------------------------------
        if (m_ltep_handshake)
        {
                free(m_ltep_handshake);
                m_ltep_handshake = nullptr;
                m_ltep_handshake_len = 0;
        }
        // -------------------------------------------------
        // write bencode
        // -------------------------------------------------
        ns_ntrnt::bencode_writer l_bw;
        // -------------------------------------------------
        // TODO
        // - 'yourip'
        // - 'ipv6'
        // -------------------------------------------------
        // -------------------------------------------------
        // encryption
        // -------------------------------------------------
        l_bw.w_key("e");
        l_bw.w_int(1);
        // -------------------------------------------------
        // metadata size (if have)
        // -------------------------------------------------
        if (m_session.get_info_pickr().get_info_buf_len())
        {
                l_bw.w_key("metadata_size");
                l_bw.w_int(m_session.get_info_pickr().get_info_buf_len());
        }
        // -------------------------------------------------
        // expternal port
        // -------------------------------------------------
        l_bw.w_key("p");
        l_bw.w_int(m_session.get_ext_port());
        // -------------------------------------------------
        // request queue size (512 is reasonable?)
        // http://bittorrent.org/beps/bep_0010.html
        // An integer, the number of outstanding request
        // messages this client supports without dropping.
        // -------------------------------------------------
        l_bw.w_key("reqq");
        l_bw.w_int(512);
        // -------------------------------------------------
        // upload only if seeding
        // http://bittorrent.org/beps/bep_0021.html
        // A peer that is a partial seed SHOULD include an
        // extra header in the extension handshake:
        // 'upload_only'.
        // Setting the value of this key to 1 indicatesthis
        // peer is not interested in downloadin anything.
        // -------------------------------------------------
        if (m_session.get_pickr().complete())
        {
                l_bw.w_key("upload_only");
                l_bw.w_int(1);
        }
        // -------------------------------------------------
        // peer id
        // TODO make constant
        // -------------------------------------------------
        std::string l_id = "Ntrnt ";
        l_id += NTRNT_VERSION;
        l_bw.w_key("v");
        l_bw.w_string(l_id);
        // -------------------------------------------------
        // ltep command dict
        // -------------------------------------------------
        l_bw.w_key("m");
        l_bw.w_start_dict();
        // -------------------------------------------------
        // ltep pex command id
        // -------------------------------------------------
        l_bw.w_key("ut_pex");
        l_bw.w_int(LTEP_CMD_PEX);
        // -------------------------------------------------
        // ltep metadata command id
        // -------------------------------------------------
        l_bw.w_key("ut_metadata");
        l_bw.w_int(LTEP_CMD_METADATA);
        // -------------------------------------------------
        // end ltep command dict
        // -------------------------------------------------
        l_bw.w_end_dict();
        // -------------------------------------------------
        // serialize to buf
        // -------------------------------------------------
        const uint8_t* l_buf = nullptr;
        size_t l_buf_len = 0;
        l_bw.serialize(&l_buf, l_buf_len);
        // -------------------------------------------------
        // copy in
        // -------------------------------------------------
        m_ltep_handshake_len = l_buf_len;
        m_ltep_handshake = (uint8_t*)malloc((sizeof(uint8_t)*m_ltep_handshake_len));
        memcpy(m_ltep_handshake, l_buf, m_ltep_handshake_len);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::ltep_send_handshake(void)
{
        // -------------------------------------------------
        // recreate -changes if upload only
        // -------------------------------------------------
        ltep_create_handshake();
        // -------------------------------------------------
        // port: <len=????><id=20><ltep=0><ltep handshake (bencoded)>
        // <uint32_t> len
        // <uint8_t>  BTP_CMD_LTEP
        // <uint8_t>  LTEP_CMD_HANDSHAKE
        // <data>     bencoded
        // -------------------------------------------------
        m_out_q.write_n32(2+m_ltep_handshake_len);
        m_out_q.write_n8(BTP_CMD_LTEP);
        m_out_q.write_n8(LTEP_CMD_HANDSHAKE);
        m_out_q.write((const char*)m_ltep_handshake, m_ltep_handshake_len);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::ltep_send_pex(void)
{
        // -------------------------------------------------
        // set default flag value
        // -------------------------------------------------
        // TODO adjust for peer behavior
        // -------------------------------------------------
        uint8_t l_flags = LTEP_PEER_FLAG_PREFERS_ENCRYPTION |
                          LTEP_PEER_FLAG_SUPPORTS_UTP |
                          LTEP_PEER_FLAG_OUTGOING_CONNECTION;
        // -------------------------------------------------
        // get swarm (currently connected peers)
        // -------------------------------------------------
        uint8_vec_t l_peers4;
        uint8_vec_t l_peers4_f;
        uint8_vec_t l_peers6;
        uint8_vec_t l_peers6_f;
        peer_vec_t & l_pv = m_session.get_peer_mgr().get_peer_connected_vec();
        for (auto && i_p : l_pv)
        {
                if (!i_p) { continue; }
                peer& l_p = *i_p;
                const sockaddr_storage& l_sas = l_p.get_sas();
                // -----------------------------------------
                // add ipv4 peer
                // -----------------------------------------
                if (l_sas.ss_family == AF_INET)
                {
                        const struct sockaddr_in* l_sin = (const struct sockaddr_in*)(&l_sas);
                        const struct in_addr* l_in = &(l_sin->sin_addr);
                        uint16_t l_port = l_sin->sin_port;
                        // add address
                        l_peers4.insert(l_peers4.end(), (char*)l_in, ((char*)l_in)+4);
                        // add port
                        l_peers4.insert(l_peers4.end(), (char*)(&l_port), ((char*)(&l_port))+2);
                        // add flags
                        l_peers4_f.insert(l_peers4_f.end(), &l_flags, (&l_flags)+sizeof(l_flags));
                }
                // -----------------------------------------
                // add ipv4 peer
                // -----------------------------------------
                else if(l_sas.ss_family == AF_INET6)
                {
                        const struct sockaddr_in6* l_sin6 = (const struct sockaddr_in6*)(&l_sas);
                        const struct in6_addr* l_in = &(l_sin6->sin6_addr);
                        uint16_t l_port = l_sin6->sin6_port;
                        // add address
                        l_peers6.insert(l_peers6.end(), (char*)l_in, ((char*)l_in)+16);
                        // add port
                        l_peers6.insert(l_peers6.end(), (char*)(&l_port), ((char*)(&l_port))+2);
                        // add flags
                        l_peers6_f.insert(l_peers6_f.end(), &l_flags, (&l_flags)+sizeof(l_flags));
                }
        }
        // -------------------------------------------------
        // ref: https://www.bittorrent.org/beps/bep_0011.html
        // {
        //   added: <one or more contacts in IPv4 compact format (string)>
        //   added.f: <optional, bit-flags, 1 byte per added IPv4 peer (string)>
        //   added6: <one or more contacts IPv6 compact format (string)>,
        //   added6.f: <optional, bit-flags, 1 byte per added IPv6 peer (string)>,
        //   dropped: <one or more contacts in IPv6 compact format (string)>,
        //   dropped6: <one or more contacts in IPv6 compact format (string)>
        // }
        // -------------------------------------------------
        bool l_has_one = false;
        bencode_writer l_bw;
        if (l_peers4.size())
        {
                l_bw.w_key("added");
                l_bw.w_string((const char*)l_peers4.data(), l_peers4.size());
                l_has_one = true;
        }
        if (l_peers4_f.size())
        {
                l_bw.w_key("added.f");
                l_bw.w_string((const char*)l_peers4_f.data(), l_peers4_f.size());
                l_has_one = true;
        }
        if (l_peers6.size())
        {
                l_bw.w_key("added6");
                l_bw.w_string((const char*)l_peers6.data(), l_peers6.size());
                l_has_one = true;
        }
        if (l_peers6_f.size())
        {
                l_bw.w_key("added6.f");
                l_bw.w_string((const char*)l_peers6_f.data(), l_peers6_f.size());
                l_has_one = true;
        }
        // -------------------------------------------------
        // if all empty skip
        // -------------------------------------------------
        if (l_has_one)
        {
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // serialize
        // -------------------------------------------------
        const uint8_t* l_buf = nullptr;
        size_t l_len = 0;
        l_bw.serialize(&l_buf, l_len);
        // -------------------------------------------------
        // port: <len=????><id=20><ltep=0><ltep pex (bencoded)>
        // <uint32_t> len
        // <uint8_t>  BTP_CMD_LTEP
        // <uint8_t>  LTEP_CMD_PEX
        // <data>     bencoded
        // -------------------------------------------------
        m_out_q.write_n32(2+m_ltep_handshake_len);
        m_out_q.write_n8(BTP_CMD_LTEP);
        m_out_q.write_n8(m_ltep_ut_pex_id);
        m_out_q.write((const char*)l_buf, l_len);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::ltep_send_metadata_request(uint32_t a_idx)
{
        //NDBG_PRINT("[BTP] [LTEP [SEND] METADATA_REQUEST [IDX: %u]\n", a_idx);
        // -------------------------------------------------
        // create bencoded body
        // ref:
        // https://www.bittorrent.org/beps/bep_0009.html
        // id | msg types:
        // ---+---------------------------------------------
        //  0 | request
        //  1 | data
        //  2 | reject
        // -------------------------------------------------
        // sample:
        // {'msg_type': 0, 'piece': 0}
        // -------------------------------------------------
        bencode_writer l_bw;
        l_bw.w_key("msg_type");
        l_bw.w_int(LTEP_METADATA_CMD_RQST);
        l_bw.w_key("piece");
        l_bw.w_int(a_idx);
        // -------------------------------------------------
        // serialize
        // -------------------------------------------------
        const uint8_t* l_buf = nullptr;
        size_t l_len = 0;
        l_bw.serialize(&l_buf, l_len);
        // -------------------------------------------------
        // port: <len=????><id=20><ltep=<cmd_id>><ltep pex (bencoded)>
        // <uint32_t> len
        // <uint8_t>  BTP_CMD_LTEP
        // <uint8_t>  LTEP_CMD_PEX
        // <data>     bencoded
        // -------------------------------------------------
        m_out_q.write_n32(2+l_len);
        m_out_q.write_n8(BTP_CMD_LTEP);
        m_out_q.write_n8(m_ltep_ut_metadata_id);
        m_out_q.write((const char*)l_buf, l_len);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::ltep_send_metadata(uint32_t a_idx)
{
        //NDBG_PRINT("[BTP] [LTEP [SEND] METADATA [IDX: %u]\n", a_idx);
        // -------------------------------------------------
        // get buffer for metadata piece
        // -------------------------------------------------
        int32_t l_s;
        const char* l_metadata_buf = nullptr;
        size_t l_metadata_buf_len = 0;
        l_s = m_session.get_info_pickr().get_info_piece(this, a_idx, &l_metadata_buf, l_metadata_buf_len);
        if (l_s != NTRNT_STATUS_OK)
        {
                // send rejection if error or don't have
                return ltep_send_metadata_reject(a_idx);
        }
        // -------------------------------------------------
        // create bencoded body
        // ref:
        // https://www.bittorrent.org/beps/bep_0009.html
        // id | msg types:
        // ---+---------------------------------------------
        //  0 | request
        //  1 | data
        //  2 | reject
        // -------------------------------------------------
        // sample:
        // {'msg_type': 1, 'piece': <P>, 'total_size': <N>}<data<N bytes>>
        // -------------------------------------------------
        bencode_writer l_bw;
        l_bw.w_key("msg_type");
        l_bw.w_int(LTEP_METADATA_CMD_DATA);
        l_bw.w_key("piece");
        l_bw.w_int(a_idx);
        l_bw.w_key("total_size");
        l_bw.w_int(l_metadata_buf_len);
        // -------------------------------------------------
        // serialize
        // -------------------------------------------------
        const uint8_t* l_buf = nullptr;
        size_t l_len = 0;
        l_bw.serialize(&l_buf, l_len);
        // -------------------------------------------------
        // port: <len=????><id=20><ltep=<cmd_id>><ltep pex (bencoded)><piece data>
        // <uint32_t> len
        // <uint8_t>  BTP_CMD_LTEP
        // <uint8_t>  LTEP_CMD_PEX
        // <data>     bencoded
        // <piece>    piece data
        // -------------------------------------------------
        m_out_q.write_n32(2+l_len);
        m_out_q.write_n8(BTP_CMD_LTEP);
        m_out_q.write_n8(m_ltep_ut_metadata_id);
        m_out_q.write((const char*)l_buf, l_len);
        m_out_q.write((const char*)l_metadata_buf, l_metadata_buf_len);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::ltep_send_metadata_reject(uint32_t a_idx)
{
        //NDBG_PRINT("[BTP] [LTEP [SEND] METADATA_REJECT [IDX: %u]\n", a_idx);
        // -------------------------------------------------
        // create bencoded body
        // ref:
        // https://www.bittorrent.org/beps/bep_0009.html
        // id | msg types:
        // ---+---------------------------------------------
        //  0 | request
        //  1 | data
        //  2 | reject
        // -------------------------------------------------
        // sample:
        // {'msg_type': 1, 'piece': <P>, 'total_size': <N>}<data<N bytes>>
        // -------------------------------------------------
        bencode_writer l_bw;
        l_bw.w_key("msg_type");
        l_bw.w_int(LTEP_METADATA_CMD_REJECT);
        l_bw.w_key("piece");
        l_bw.w_int(a_idx);
        // -------------------------------------------------
        // serialize
        // -------------------------------------------------
        const uint8_t* l_buf = nullptr;
        size_t l_len = 0;
        l_bw.serialize(&l_buf, l_len);
        // -------------------------------------------------
        // port: <len=????><id=20><ltep=<cmd_id>><ltep pex (bencoded)>
        // <uint32_t> len
        // <uint8_t>  BTP_CMD_LTEP
        // <uint8_t>  LTEP_CMD_PEX
        // <data>     bencoded
        // <piece>    piece data
        // -------------------------------------------------
        m_out_q.write_n32(2+l_len);
        m_out_q.write_n8(BTP_CMD_LTEP);
        m_out_q.write_n8(m_ltep_ut_metadata_id);
        m_out_q.write((const char*)l_buf, l_len);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::ltep_read_cmd(void)
{
        int32_t l_s;
        size_t l_rem = m_btp_cmd_len-1;
        // -------------------------------------------------
        // get cmd byte
        // -------------------------------------------------
        uint8_t l_cmd;
        m_in_q.read((char*)&l_cmd, sizeof(l_cmd));
        --l_rem;
        // -------------------------------------------------
        // for cmd
        // -------------------------------------------------
        // -------------------------------------------------
        // LTEP_CMD_HANDSHAKE
        // TODO: <id=?><????>
        // -------------------------------------------------
        if (l_cmd == LTEP_CMD_HANDSHAKE)
        {
                l_s = ltep_recv_handshake(l_rem);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing ltep_recv_handshake");
                        return NTRNT_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // LTEP_CMD_PEX
        // TODO: <id=?><????>
        // -------------------------------------------------
        else if(l_cmd == LTEP_CMD_PEX)
        {
                l_s = ltep_recv_pex(l_rem);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing ltep_recv_pex");
                        return NTRNT_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // LTEP_CMD_METADATA
        // TODO: <id=?><????>
        // -------------------------------------------------
        else if((l_cmd == LTEP_CMD_METADATA) ||
                // TODO qBittorrent seems to send 20 for meta data
                 (l_cmd == 20))
        {
                l_s = ltep_recv_metadata(l_rem);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing ltep_recv_metadata");
                        return NTRNT_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // default ???
        // -------------------------------------------------
        else
        {
                NDBG_PRINT("[HOST: %s] [CLIENT: %s] unhandled ltep cmd: %u\n",
                           m_host.c_str(),
                           m_ltep_peer_id.c_str(),
                           m_btp_cmd);
                char* l_buf = nullptr;
                l_buf = (char*)malloc(l_rem);
                m_in_q.read(l_buf, l_rem);
                NDBG_HEXDUMP(l_buf, 128);
                if (l_buf) { free(l_buf); l_buf = nullptr; }
                // TODO discard for now
                //m_in_q.discard(l_rem);
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::ltep_recv_handshake(size_t a_len)
{
        //NDBG_PRINT("[BTP] [RECV] [LTEP] LTEP_CMD_HANDSHAKE LEN: %lu\n", a_len);
        // -------------------------------------------------
        // read up to max size
        // -------------------------------------------------
        uint8_t l_buf[NTRNT_PEER_LTEP_HANDSHAKE_SIZE];
        size_t l_rem = 0;
        size_t l_len;
        l_len = a_len < NTRNT_PEER_LTEP_HANDSHAKE_SIZE ? a_len : NTRNT_PEER_LTEP_HANDSHAKE_SIZE;
        if (a_len > NTRNT_PEER_LTEP_HANDSHAKE_SIZE)
        {
                l_rem = a_len - NTRNT_PEER_LTEP_HANDSHAKE_SIZE;
        }
        off_t l_read = 0;
        l_read = m_in_q.read((char*)l_buf, l_len);
        if (l_read != l_len)
        {
                TRC_ERROR("read < required [read: %d] [requested: %lu]", (int)l_read, l_len);
                return NTRNT_STATUS_ERROR;
        }
        // discard anything left over
        if (l_rem)
        {
                NDBG_PRINT("[BTP] [RECV] [LTEP] LTEP_CMD_HANDSHAKE discard: %lu\n", l_rem);
                m_in_q.discard(l_rem);
        }
        // -------------------------------------------------
        // decode
        // -------------------------------------------------
        int32_t l_s;
        bdecode l_be;
        l_s = l_be.init((const char*)l_buf, l_len);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing bdecode init");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // loop over dict items
        // -------------------------------------------------
        for (auto && i_itm : l_be.m_dict)
        {
#define _ELIF_FIELD(_str) else if(i_itm.first == _str)
                const be_obj_t& i_obj = i_itm.second;
                if (0) {}
                // -----------------------------------------
                // 'e': encryption preference
                // -----------------------------------------
                _ELIF_FIELD("e")
                {
                        if (i_obj.m_type != BE_OBJ_INT)
                        {
                                continue;
                        }
                        const be_int_t& i_int = *((const be_int_t*)i_obj.m_obj);
                        if (i_int)
                        {
                                m_ltep_encryption = true;
                        }
                }
                // -----------------------------------------
                // 'm': supported ltep messages
                // -----------------------------------------
                _ELIF_FIELD("m")
                {
                        if (i_obj.m_type != BE_OBJ_DICT)
                        {
                                continue;
                        }
                        const be_dict_t& l_m_dict = *((const be_dict_t*)i_obj.m_obj);
                        for (auto && i_mitm : l_m_dict)
                        {
#define _ELIF_MFIELD(_str) else if(i_mitm.first == _str)
                                const be_obj_t& i_mobj = i_mitm.second;
                                if (0) {}
                                // -------------------------
                                // ut_metadata
                                // -------------------------
                                _ELIF_MFIELD("ut_metadata")
                                {
                                        if (i_mobj.m_type != BE_OBJ_INT)
                                        {
                                                continue;
                                        }
                                        const be_int_t& i_int = *((const be_int_t*)i_mobj.m_obj);
                                        m_ltep_ut_metadata_id = i_int;
                                        m_ltep_msg_support_ut_metadata = true;
                                }
                                // -------------------------
                                // ut_pex
                                // -------------------------
                                _ELIF_MFIELD("ut_pex")
                                {
                                        if (i_mobj.m_type != BE_OBJ_INT)
                                        {
                                                continue;
                                        }
                                        const be_int_t& i_int = *((const be_int_t*)i_mobj.m_obj);
                                        m_ltep_ut_pex_id = i_int;
                                        m_ltep_msg_support_ut_pex = true;
                                }
                                // -------------------------
                                // ut_holepunch
                                // -------------------------
                                _ELIF_MFIELD("ut_holepunch")
                                {
                                        if (i_mobj.m_type != BE_OBJ_INT)
                                        {
                                                continue;
                                        }
                                        const be_int_t& i_int = *((const be_int_t*)i_mobj.m_obj);
                                        m_ltep_ut_holepunch_id = i_int;
                                        m_ltep_msg_support_ut_holepunch = true;
                                }
                                // -------------------------
                                // ???
                                // -------------------------
                                else
                                {

                                }
                        }
                }
                // -----------------------------------------
                // metadata_size
                // -----------------------------------------
                _ELIF_FIELD("metadata_size")
                {
                        if (i_obj.m_type != BE_OBJ_INT)
                        {
                                continue;
                        }
                        const be_int_t& i_int = *((const be_int_t*)i_obj.m_obj);
                        m_ltep_metadata_size = i_int;
                }
                // -----------------------------------------
                // reqq
                // -----------------------------------------
                _ELIF_FIELD("reqq")
                {
                        if (i_obj.m_type != BE_OBJ_INT)
                        {
                                continue;
                        }
                        const be_int_t& i_int = *((const be_int_t*)i_obj.m_obj);
                        m_ltep_reqq = i_int;
                }
                // -----------------------------------------
                // upload_only
                // -----------------------------------------
                _ELIF_FIELD("upload_only")
                {
                        if (i_obj.m_type != BE_OBJ_INT)
                        {
                                continue;
                        }
                        const be_int_t& i_int = *((const be_int_t*)i_obj.m_obj);
                        if (i_int)
                        {
                                m_ltep_upload_only = true;
                        }
                }
                // -----------------------------------------
                // v: peer id string
                // -----------------------------------------
                _ELIF_FIELD("v")
                {
                        if (i_obj.m_type != BE_OBJ_STRING)
                        {
                                continue;
                        }
                        const be_string_t& i_str = *((const be_string_t*)i_obj.m_obj);
                        m_ltep_peer_id.assign(i_str.m_data, i_str.m_len);
                }
                // -----------------------------------------
                // yourip
                // -----------------------------------------
                _ELIF_FIELD("yourip")
                {
                        if (i_obj.m_type != BE_OBJ_STRING)
                        {
                                continue;
                        }
                        const be_string_t& i_str = *((const be_string_t*)i_obj.m_obj);
                        //NDBG_PRINT("yourip\n");
                        //NDBG_HEXDUMP(i_str.m_data, i_str.m_len);
                        UNUSED(i_str);
                }
                // -----------------------------------------
                // complete_ago
                // -----------------------------------------
                _ELIF_FIELD("complete_ago")
                {
                        if (i_obj.m_type != BE_OBJ_INT)
                        {
                                continue;
                        }
                        const be_int_t& i_int = *((const be_int_t*)i_obj.m_obj);
                        m_ltep_complete_ago = i_int;
                }
                // -----------------------------------------
                // p: peer port
                // -----------------------------------------
                _ELIF_FIELD("p")
                {
                        if (i_obj.m_type != BE_OBJ_INT)
                        {
                                continue;
                        }
                        const be_int_t& i_int = *((const be_int_t*)i_obj.m_obj);
                        m_ltep_peer_port = i_int;
                }
                // -----------------------------------------
                // 'ipv4'
                // -----------------------------------------
                _ELIF_FIELD("ipv4")
                {
                        // TODO
                }
                // -----------------------------------------
                // 'ipv6'
                // -----------------------------------------
                _ELIF_FIELD("ipv6")
                {
                        // TODO
                }
                // -----------------------------------------
                // ???
                // -----------------------------------------
                else
                {
                        TRC_VERBOSE("unrecognized key in dict: %s\n", i_itm.first.c_str());
                }
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::ltep_recv_pex(size_t a_len)
{
        //NDBG_PRINT("[BTP] [RECV] [LTEP] LTEP_CMD_PEX AVAIL: %lu\n", m_in_q.read_avail());
        // -------------------------------------------------
        // parse pex message
        // -------------------------------------------------
        char* l_buf = nullptr;
        l_buf = (char*)malloc(a_len);
        m_in_q.read(l_buf, a_len);
        int32_t l_s;
        bdecode l_bd;
        l_s = l_bd.init(l_buf, a_len);
        if (l_s != NTRNT_STATUS_OK)
        {
                if (l_buf) { free(l_buf); l_buf = nullptr; }
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // read pex fields
        // -------------------------------------------------
        for(auto && i_m : l_bd.m_dict)
        {
#define _ELIF_UT_FIELD(_str) else if(i_m.first == _str)
                const be_obj_t& i_obj = i_m.second;
                if (0) {}
                // -----------------------------------------
                // added
                // -----------------------------------------
                _ELIF_UT_FIELD("added")
                {
                        if (i_obj.m_type != BE_OBJ_STRING) { continue; }
                        const be_string_t& i_str = *((const be_string_t*)i_obj.m_obj);
                        int32_t l_s;
                        l_s = m_session.add_peer_raw(AF_INET, (const uint8_t*)i_str.m_data, i_str.m_len, NTRNT_PEER_FROM_PEX);
                        if (l_s != NTRNT_STATUS_OK)
                        {
                                TRC_ERROR("performing add_peer_raw(AF_INET)");
                                if (l_buf) { free(l_buf); l_buf = nullptr; }
                        }
                }
                // -----------------------------------------
                // added.f
                // -----------------------------------------
                // ref: https://www.bittorrent.org/beps/bep_0011.html
                // -----+-----------------------------------
                // Bit  |  when set
                // -----+-----------------------------------
                // 0x01 |  prefers encryption, as indicated by e field in extension handshake
                // 0x02 |  seed/upload_only
                // 0x04 |  supports uTP
                // 0x08 |  peer indicated ut_holepunch support in extension handshake
                // 0x10 |  outgoing connection, peer is reachable
                // -----------------------------------------
                _ELIF_UT_FIELD("added.f")
                {
                        if (i_obj.m_type != BE_OBJ_STRING) { continue; }
                        const be_string_t& i_str = *((const be_string_t*)i_obj.m_obj);
                        UNUSED(i_str);
                        // TODO -add flags to add peer
                }
                // -----------------------------------------
                // added6
                // -----------------------------------------
                _ELIF_UT_FIELD("added6")
                {
                        if (i_obj.m_type != BE_OBJ_STRING) { continue; }
                        const be_string_t& i_str = *((const be_string_t*)i_obj.m_obj);
                        int32_t l_s;
                        l_s = m_session.add_peer_raw(AF_INET6, (const uint8_t*)i_str.m_data, i_str.m_len, NTRNT_PEER_FROM_PEX);
                        if (l_s != NTRNT_STATUS_OK)
                        {
                                TRC_ERROR("performing add_peer_raw(AF_INET)");
                                if (l_buf) { free(l_buf); l_buf = nullptr; }
                        }
                }
                // -----------------------------------------
                // added6.f
                // -----------------------------------------
                _ELIF_UT_FIELD("added6.f")
                {
                        if (i_obj.m_type != BE_OBJ_STRING) { continue; }
                        const be_string_t& i_str = *((const be_string_t*)i_obj.m_obj);
                        UNUSED(i_str);
                        // TODO -add flags to add peer
                }
                // -----------------------------------------
                // dropped
                // -----------------------------------------
                _ELIF_UT_FIELD("dropped")
                {
                        if (i_obj.m_type != BE_OBJ_STRING) { continue; }
                        const be_string_t& i_str = *((const be_string_t*)i_obj.m_obj);
                        UNUSED(i_str);
                }
                // -----------------------------------------
                // dropped6
                // -----------------------------------------
                _ELIF_UT_FIELD("dropped6")
                {
                        if (i_obj.m_type != BE_OBJ_STRING) { continue; }
                        const be_string_t& i_str = *((const be_string_t*)i_obj.m_obj);
                        UNUSED(i_str);
                }
                else
                {
                        TRC_WARN("[BPT] [LTEP] [PEX] unrecognized field: %s", i_m.first.c_str());
                }
        }
        // -------------------------------------------------
        // done
        // -------------------------------------------------
        if (l_buf) { free(l_buf); l_buf = nullptr; }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer::ltep_recv_metadata(size_t a_len)
{
        //NDBG_PRINT("[BTP] [LTEP] [RECV] METADATA_REQUEST\n");
        // -------------------------------------------------
        // decode
        // -------------------------------------------------
        char* l_buf = nullptr;
        l_buf = (char*)malloc(a_len);
        m_in_q.read(l_buf, a_len);
        int32_t l_s;
        bdecode l_bd;
        l_s = l_bd.init(l_buf, a_len);
        if (l_s != NTRNT_STATUS_OK)
        {
                if (l_buf) { free(l_buf); l_buf = nullptr; }
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // id | msg types:
        // ---+---------------------------------------------
        //  0 | request
        //  1 | data
        //  2 | reject
        // -------------------------------------------------
        // -------------------------------------------------
        // sample:
        // {'msg_type': 1, 'piece': 0, 'total_size': 3425}
        // d8:msg_typei1e5:piecei0e10:total_sizei34256eexxxxxxxx...
        // NOTE: piece data is appended to the end of the
        // dict!
        // -------------------------------------------------
        uint32_t l_type = 0;
        uint32_t l_idx = 0;
        uint32_t l_size = 0;
        // -------------------------------------------------
        // read msg fields
        // -------------------------------------------------
        for(auto && i_m : l_bd.m_dict)
        {
                const be_obj_t& i_obj = i_m.second;
                if (0) {}
                // -----------------------------------------
                // msg_type
                // -----------------------------------------
                _ELIF_UT_FIELD("msg_type")
                {
                        if (i_obj.m_type != BE_OBJ_INT) { continue; }
                        const be_int_t& i_int = *((const be_int_t*)i_obj.m_obj);
                        if (i_int < 0)
                        {
                                TRC_ERROR("msg_type is < 0?");
                                if (l_buf) { free(l_buf); l_buf = nullptr; }
                                return NTRNT_STATUS_ERROR;
                        }
                        l_type = (uint32_t)i_int;
                }
                // -----------------------------------------
                // piece
                // -----------------------------------------
                _ELIF_UT_FIELD("piece")
                {
                        if (i_obj.m_type != BE_OBJ_INT) { continue; }
                        const be_int_t& i_int = *((const be_int_t*)i_obj.m_obj);
                        if (i_int < 0)
                        {
                                TRC_ERROR("piece is < 0?");
                                if (l_buf) { free(l_buf); l_buf = nullptr; }
                                return NTRNT_STATUS_ERROR;
                        }
                        l_idx = (uint32_t)i_int;
                }
                // -----------------------------------------
                // total_size
                // -----------------------------------------
                _ELIF_UT_FIELD("total_size")
                {
                        if (i_obj.m_type != BE_OBJ_INT) { continue; }
                        const be_int_t& i_int = *((const be_int_t*)i_obj.m_obj);
                        if (i_int < 0)
                        {
                                TRC_ERROR("total_size is < 0?");
                                if (l_buf) { free(l_buf); l_buf = nullptr; }
                                return NTRNT_STATUS_ERROR;
                        }
                        l_size = (uint32_t)i_int;
                        UNUSED(l_size);
                }
        }
        // -------------------------------------------------
        // receive data
        // -------------------------------------------------
        if (l_type == LTEP_METADATA_CMD_DATA)
        {
                char* l_cur_ptr = nullptr;
                size_t l_cur_off = 0;
                size_t l_cur_len = 0;
                l_bd.get_cur_ptr(&l_cur_ptr, l_cur_off, l_cur_len);
                l_s = m_session.get_info_pickr().recv_info_piece(this, l_idx, l_cur_ptr, l_cur_len - l_cur_off);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing pickr recv_metadata_piece");
                        if (l_buf) { free(l_buf); l_buf = nullptr; }
                        return NTRNT_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // reject
        // -------------------------------------------------
        else if (l_type == LTEP_METADATA_CMD_RQST)
        {
                l_s = ltep_send_metadata(l_idx);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing pickr recv_metadata_piece");
                        if (l_buf) { free(l_buf); l_buf = nullptr; }
                        return NTRNT_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // reject
        // -------------------------------------------------
        else if (l_type == LTEP_METADATA_CMD_REJECT)
        {
                TRC_WARN("received metadata rejection message [piece: %u]", l_idx);
                if (l_buf) { free(l_buf); l_buf = nullptr; }
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // done
        // -------------------------------------------------
        if (l_buf) { free(l_buf); l_buf = nullptr; }
        return NTRNT_STATUS_OK;
}
}
