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
#include "support/net_util.h"
#include "support/nbq.h"
#include "support/string_util.h"
#include "support/tls_util.h"
#include "support/geoip2_mmdb.h"
#include "support/sha1.h"
#include "conn/nconn.h"
#include "conn/nconn_tls.h"
#include "dns/nresolver.h"
#include "core/tracker.h"
#include "core/tracker_udp.h"
#include "core/tracker_tcp.h"
#include "core/dht_mgr.h"
#include "core/session.h"
#include "core/pickr.h"
#include "core/peer.h"
#include "core/peer_mgr.h"
// ---------------------------------------------------------
// utp
// ---------------------------------------------------------
#include "libutp/utp.h"
// ---------------------------------------------------------
// system includes
// ---------------------------------------------------------
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
// ---------------------------------------------------------
// openssl includes
// ---------------------------------------------------------
#include <openssl/ssl.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _MSG_SIZE_MAX 8192
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
// Set socket option macro...
#define _SET_SOCK_OPT(_sock_fd, _sock_opt_level, _sock_opt_name, _sock_opt_val) \
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
                        TRC_ERROR("Failed to set sock_opt: %s.  Reason: %s.\n", #_sock_opt_name, strerror(errno)); \
                        return NTRNT_STATUS_ERROR;\
                } \
        } while(0)
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static uint64 _utp_cb(utp_callback_arguments* a_args)
{
        //NDBG_PRINT("[%sUTP%s]: cb type: %d ctx: %p conn: %p\n",
        //           ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF,
        //           a_args->callback_type,
        //           a_args->context,
        //           a_args->socket);
        // -------------------------------------------------
        // get session
        // -------------------------------------------------
        session* l_ses = static_cast<session*>(utp_context_get_userdata(a_args->context));
        if (!l_ses)
        {
                TRC_ERROR("session == null");
                return 0;
        }
        int32_t l_s;
        peer_mgr& l_peer_mgr = l_ses->get_peer_mgr();
        l_s = l_peer_mgr.utp_cb(a_args->socket,
                                a_args->address,
                                a_args->address_len,
                                a_args->callback_type,
                                a_args->state,
                                a_args->buf,
                                a_args->len);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing session utp_cb");
                return 0;
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
session::session(void):
        m_tid_tracker_udp_map(),
        m_is_initd(false),
        m_info_hash(),
        m_info_hash_str(),
        m_announce(),
        m_announce_list(),
        m_creation_date(),
        m_created_by(),
        m_encoding(),
        m_comment(),
        m_stopped(true),
        m_trackers_enable(true),
        m_peer_id(),
        m_ext_ip(),
        m_ext_port(NTRNT_DEFAULT_PORT),
        m_ext_address(),
        m_peer(),
        m_tracker_list(),
        m_nresolver(nullptr),
        m_client_ssl_ctx(nullptr),
#if defined(__linux__)
         m_evr_loop_type(EVR_LOOP_EPOLL),
#elif defined(__FreeBSD__) || defined(__APPLE__)
        m_evr_loop_type(EVR_LOOP_SELECT),
#else
        m_evr_loop_type(EVR_LOOP_SELECT),
#endif
        m_evr_loop(nullptr),
        m_evr_udp_fd(),
        m_evr_udp6_fd(),
        m_udp_fd(-1),
        m_udp6_fd(-1),
        m_dht_enable(true),
        m_dht_mgr(nullptr),
        m_utp_ctx(nullptr),
        m_peer_mgr(*this),
        m_info_pickr(*this),
        m_pickr(*this),
        m_geoip2_mmdb(nullptr),
        m_geoip2_db()
{
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
session::~session(void)
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
        // dht
        // -------------------------------------------------
        if (m_dht_mgr)
        {
                delete m_dht_mgr;
                m_dht_mgr = nullptr;
        }
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
                m_nresolver = nullptr;
        }
        // -------------------------------------------------
        // evr loop
        // -------------------------------------------------
        if (m_evr_loop)
        {
                delete m_evr_loop;
                m_evr_loop = nullptr;
        }
        // -------------------------------------------------
        // tls cleanup
        // -------------------------------------------------
        if (m_client_ssl_ctx)
        {
                SSL_CTX_free(m_client_ssl_ctx);
                m_client_ssl_ctx = nullptr;
        }
        // -------------------------------------------------
        // dht
        // -------------------------------------------------
        if (m_geoip2_mmdb)
        {
                delete m_geoip2_mmdb;
                m_geoip2_mmdb = nullptr;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::init_w_metainfo(const std::string& a_path)
{
        // -------------------------------------------------
        // bdecode decode
        // -------------------------------------------------
        int32_t l_s;
        bdecode l_be;
        l_s = l_be.init(a_path.c_str());
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing be init");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // find info
        // -------------------------------------------------
        be_dict_t::const_iterator i_obj;
        i_obj = l_be.m_dict.find("info");
        if (i_obj == l_be.m_dict.end())
        {
                TRC_ERROR("missing info section in torrent");
                return NTRNT_STATUS_ERROR;
        }
        const be_obj_t& l_info = i_obj->second;
        // -------------------------------------------------
        // get info hash
        // -------------------------------------------------
        sha1 l_sha1;
        l_sha1.update((const uint8_t*)l_info.m_ptr, l_info.m_len);
        l_sha1.finish();
        memcpy(m_info_hash.m_data, l_sha1.get_hash(), sizeof(m_info_hash));
        // -------------------------------------------------
        // hex encode
        // -------------------------------------------------
        char* l_buf = nullptr;
        l_s = bin2hex(&l_buf, m_info_hash.m_data, sizeof(m_info_hash));
        if (l_s != NTRNT_STATUS_OK)
        {
                NTRNT_PERROR("performing bin2hex of sha1 hash");
                if (l_buf) { free(l_buf); l_buf = nullptr; }
                return NTRNT_STATUS_ERROR;
        }
        m_info_hash_str.assign(l_buf);
        if (l_buf) { free(l_buf); l_buf = nullptr; }
        // -------------------------------------------------
        // parse info
        // -------------------------------------------------
        if (l_info.m_type == BE_OBJ_DICT)
        {
                const be_dict_t& l_info_dict = *((const be_dict_t*)l_info.m_obj);
                l_s = m_info_pickr.parse_info(l_info_dict);
                if (l_s != NTRNT_STATUS_OK)
                {
                        NTRNT_PERROR("performing parse_info");
                        if (l_buf) { free(l_buf); l_buf = nullptr; }
                        return NTRNT_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // helper
        // -------------------------------------------------
#define _SET_FIELD_STR(_str, _field) do { \
                i_obj = l_be.m_dict.find(_str); \
                if (i_obj != l_be.m_dict.end()) { \
                        const be_obj_t& l_obj = i_obj->second; \
                        if (l_obj.m_type == BE_OBJ_STRING) { \
                                be_string_t* l_be_str = (be_string_t*)(l_obj.m_obj); \
                                _field.assign(l_be_str->m_data, l_be_str->m_len); \
        } } } while(0)
#define _SET_FIELD_INT(_str, _field) do { \
                i_obj = l_be.m_dict.find(_str); \
                if (i_obj != l_be.m_dict.end()) { \
                        const be_obj_t& l_obj = i_obj->second; \
                        if (l_obj.m_type == BE_OBJ_INT) { \
                                be_int_t* l_be_int = (be_int_t*)(l_obj.m_obj); \
                                _field = *l_be_int; \
        } } } while(0)
        // -------------------------------------------------
        // set meta
        // -------------------------------------------------
        _SET_FIELD_STR("announce", m_announce);
        _SET_FIELD_INT("creation date", m_creation_date);
        _SET_FIELD_STR("created by", m_created_by);
        _SET_FIELD_STR("encoding", m_encoding);
        _SET_FIELD_STR("comment", m_comment);
        // -------------------------------------------------
        // announce list
        // -------------------------------------------------
        // ref:
        //   http://bittorrent.org/beps/bep_0012.html
        // TODO this impl is terrible -something like
        // json lib get by dict "[<key>]" would be ideal
        // -------------------------------------------------
        i_obj = l_be.m_dict.find("announce-list");
        if ((i_obj != l_be.m_dict.end()) &&
            (i_obj->second.m_type == BE_OBJ_LIST))
        {
                const be_obj_t& l_obj = i_obj->second;
                be_list_t* l_bl = (be_list_t*)(l_obj.m_obj);
                for(auto && i_l : *l_bl)
                {
                        if (i_l.m_type != BE_OBJ_LIST)
                        {
                                continue;
                        }
                        be_list_t* i_ll = (be_list_t*)(i_l.m_obj);
                        for(auto && i_t : *i_ll)
                        {
                                if (i_t.m_type != BE_OBJ_STRING)
                                {
                                        continue;
                                }
                                std::string l_t;
                                be_string_t* l_str = (be_string_t*)(i_t.m_obj);
                                l_t.assign(l_str->m_data, l_str->m_len);
                                m_announce_list.push_back(l_t);
                        }
                }
        }
        // -------------------------------------------------
        // internal init
        // -------------------------------------------------
        l_s = init();
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing init");
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::init_w_magnet(const std::string& a_path)
{
        // TODO check for prefix
        std::string l_uri_enc = a_path.substr(sizeof(NTRNT_MAGNET_PREFIX)-1, a_path.length()-sizeof(NTRNT_MAGNET_PREFIX)+1);
        // -------------------------------------------------
        // create query list
        // -------------------------------------------------
        mutable_arg_list_t l_q_list;
        // parse args
        uint32_t l_invalid_cnt = 0;
        int32_t l_s;
        l_s = parse_args(l_q_list,
                         l_invalid_cnt,
                         l_uri_enc.c_str(),
                         l_uri_enc.length(),
                         '&');
        if (l_s != NTRNT_STATUS_OK)
        {
                // TODO log reason???
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // parse list
        // ref: https://en.wikipedia.org/wiki/Magnet_URI_scheme
        // -------------------------------------------------
#define _ELIF_Q_KEY(_str) \
        else if(strncasecmp(i_q.m_key, _str, i_q.m_key_len) == 0)
        for (auto && i_q : l_q_list)
        {
                if(0) {}
                // -----------------------------------------
                // exact topic
                // -----------------------------------------
                _ELIF_Q_KEY("xt")
                {
                        //NDBG_PRINT("%.*s: %.*s\n",
                        //           (int)i_q.m_key_len, i_q.m_key,
                        //           (int)i_q.m_val_len, i_q.m_val);
                        // format "urn:<type>"
                        // only support for:
                        // BitTorrent info hash (BTIH) "btih"
#define _URN_BTIH "urn:btih:"
                        if(strncmp(i_q.m_val, _URN_BTIH, sizeof(_URN_BTIH)-1) == 0)
                        {
                                m_info_hash_str.assign(i_q.m_val + sizeof(_URN_BTIH)-1, i_q.m_val_len - sizeof(_URN_BTIH)+1);
                                // convert to bin
                                size_t l_size;
                                l_s = hex2bin((uint8_t*)(m_info_hash.m_data),
                                              l_size,
                                              m_info_hash_str.c_str(),
                                              m_info_hash_str.length());
                                // TODO check status
                        }
                }
                // -----------------------------------------
                // display name
                // -----------------------------------------
                _ELIF_Q_KEY("dn")
                {
                        // TODO ???
                }
                // -----------------------------------------
                // address TRacker
                // -----------------------------------------
                _ELIF_Q_KEY("tr")
                {
                        std::string l_tr(i_q.m_val, i_q.m_val_len);
                        m_announce_list.push_back(l_tr);
                }
        }
        if (m_announce.empty())
        {
                m_announce = m_announce_list.front();
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        for (auto && i_a : l_q_list)
        {
                if (i_a.m_key) { free(i_a.m_key); i_a.m_key = nullptr; }
                if (i_a.m_val) { free(i_a.m_val); i_a.m_val = nullptr; }
        }
        // -------------------------------------------------
        // internal init
        // -------------------------------------------------
        l_s = init();
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing init");
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::init_w_hash(const std::string& a_hash)
{
        // -------------------------------------------------
        // init info hash
        // -------------------------------------------------
        m_info_hash_str.assign(a_hash);
        // convert to bin
        size_t l_size;
        int32_t l_s;
        l_s = hex2bin((uint8_t*)(m_info_hash.m_data),
                      l_size,
                      m_info_hash_str.c_str(),
                      m_info_hash_str.length());
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing hex2bin");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // internal init
        // -------------------------------------------------
        l_s = init();
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing init");
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
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
        // seed rand
        // -------------------------------------------------
        srand(time(NULL));
        // -------------------------------------------------
        // setup peer id
        // -------------------------------------------------
        // peer_id is exactly 20 bytes (characters) long.
        // ref: https://wiki.theory.org/BitTorrentSpecification#peer_id
        // -------------------------------------------------
#define _PEER_ID_REFIX "-NT000Z-"
        m_peer_id = _PEER_ID_REFIX;
        m_peer_id += rand_str(20-strlen(_PEER_ID_REFIX));
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
                TRC_ERROR("Error: performing ssl_init(client)");
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
                TRC_ERROR("Error performing resolver init with ai_cache: %s",
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
                TRC_ERROR("m_evr_loop == nullptr");
                return NTRNT_STATUS_ERROR;
        }
        m_is_initd = true;
        // -------------------------------------------------
        // setup udp sockets
        // -------------------------------------------------
        l_s = setup_udp();
        if (l_s != NTRNT_STATUS_OK)
        {
                return NTRNT_STATUS_ERROR;
        }
        l_s = setup_udp6();
        if (l_s != NTRNT_STATUS_OK)
        {
                return NTRNT_STATUS_ERROR;
        }
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
        utp_set_callback(m_utp_ctx, UTP_ON_ACCEPT, _utp_cb);
        utp_set_callback(m_utp_ctx, UTP_SENDTO, _utp_cb);
        utp_set_callback(m_utp_ctx, UTP_ON_READ, _utp_cb);
        // TODO -don't implement for now...
#if 0
        utp_set_callback(m_utp_ctx, UTP_GET_READ_BUFFER_SIZE, _utp_cb);
#endif
        utp_set_callback(m_utp_ctx, UTP_ON_ERROR, _utp_cb);
        utp_set_callback(m_utp_ctx, UTP_ON_OVERHEAD_STATISTICS, _utp_cb);
        utp_set_callback(m_utp_ctx, UTP_ON_STATE_CHANGE, _utp_cb);
        // tracing
//#ifdef UTP_DEBUG_LOGGING
#if 0
        utp_set_callback(m_utp_ctx, UTP_LOG, &_utp_cb);
        utp_context_set_option(m_utp_ctx, UTP_LOG_NORMAL, 1);
        utp_context_set_option(m_utp_ctx, UTP_LOG_MTU, 1);
        utp_context_set_option(m_utp_ctx, UTP_LOG_DEBUG, 1);
#endif
        // set recv buffer size?
        l_s = utp_context_set_option(m_utp_ctx, UTP_RCVBUF, NTRNT_SESSION_UTP_RECV_BUF_SIZE);
        if (l_s != 0)
        {
                TRC_ERROR("performing utp_context_set_option");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // dht
        // -------------------------------------------------
        if (m_dht_enable)
        {
                m_dht_mgr = new dht_mgr(*this);
                l_s = m_dht_mgr->init();
                if (l_s != NTRNT_STATUS_OK)
                {
                        return NTRNT_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // configure peer manager
        // -------------------------------------------------
        m_peer_mgr.set_cfg_max_conn(NTRNT_SESSION_MAX_CONNS);
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
        if (m_stopped)
        {
                return;
        }
        m_stopped = true;
        signal();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::add_peer(struct sockaddr_storage& a_sas, peer_from_t a_from)
{
        int32_t l_s;
        //NDBG_OUTPUT("%s\n", sas_to_str(a_sas).c_str());
        // -------------------------------------------------
        // add to peer mgr
        // -------------------------------------------------
        peer* l_peer = nullptr;
        l_s = m_peer_mgr.add_peer(a_sas, a_from, &l_peer);
        if (l_s != NTRNT_STATUS_OK)
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // ping dht
        // -------------------------------------------------
        if (m_dht_mgr)
        {
                l_s = m_dht_mgr->ping(a_sas);
                if (l_s != NTRNT_STATUS_OK)
                {
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
int32_t session::add_peer_raw(int a_family, const uint8_t* a_buf, size_t a_len, peer_from_t a_from)
{
        off_t l_off = 0;
        // -------------------------------------------------
        // get peer addresses (ipv4)
        // -------------------------------------------------
        if (a_family == AF_INET)
        {
                //NDBG_OUTPUT("peers: raw: %lu -- ipv4: %lu\n", a_len, a_len/6);
                for (size_t i_p = 0; i_p <a_len/6; ++i_p)
                {
                        // ---------------------------------
                        // get offset
                        // ---------------------------------
                        off_t i_off = i_p*6;
                        const uint8_t* l_buf = a_buf + l_off + i_off;
                        // ---------------------------------
                        // port
                        // ---------------------------------
                        uint16_t l_port;
                        memcpy(&l_port, l_buf+4, sizeof(l_port));
                        // ---------------------------------
                        // copy in
                        // ---------------------------------
                        sockaddr_in l_sin;
                        memcpy(&(l_sin.sin_addr.s_addr), l_buf, 4);
                        l_sin.sin_port = l_port;
                        l_sin.sin_family = AF_INET;
                        sockaddr_storage l_sas;
                        memcpy(&l_sas, &l_sin, sizeof(l_sin));
                        //struct in_addr l_ip_addr;
                        //l_ip_addr.s_addr = l_ipv4;
                        //NDBG_OUTPUT("%s:%u\n", inet_ntoa(l_ip_addr), l_port);
                        // ---------------------------------
                        // add
                        // ---------------------------------
                        int32_t l_s;
                        l_s = add_peer(l_sas, a_from);
                        UNUSED(l_s);
                }
        }
        // -------------------------------------------------
        // get peer addresses (ipv6)
        // -------------------------------------------------
        else if (a_family == AF_INET6)
        {
                //NDBG_OUTPUT("peers: raw: %lu -- ipv6: %lu\n", a_len, a_len/18);
                for (size_t i_p = 0; i_p <a_len/18; ++i_p)
                {
                        // ---------------------------------
                        // get offset
                        // ---------------------------------
                        off_t i_off = i_p*18;
                        const uint8_t* l_buf = a_buf + l_off + i_off;
                        // ---------------------------------
                        // port
                        // ---------------------------------
                        uint16_t l_port;
                        memcpy(&l_port, l_buf+16, sizeof(l_port));
                        // ---------------------------------
                        // copy in
                        // ---------------------------------
                        sockaddr_in6 l_sin6;
                        memcpy(&(l_sin6.sin6_addr), l_buf, 16);
                        l_sin6.sin6_port = l_port;
                        l_sin6.sin6_family = AF_INET6;
                        sockaddr_storage l_sas;
                        memcpy(&l_sas, &l_sin6, sizeof(l_sin6));
                        int32_t l_s;
                        // ---------------------------------
                        // add
                        // ---------------------------------
                        l_s = add_peer(l_sas, a_from);
                        UNUSED(l_s);
                }
        }
        return NTRNT_STATUS_OK;
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
void session::display_info(void)
{
        NDBG_OUTPUT("+-----------------------------------------------------------\n");
        NDBG_OUTPUT("|             T O R R E N T   M E T A   I N F O\n");
        NDBG_OUTPUT("+-----------------------------------------------------------\n");
        NDBG_OUTPUT("| announce:      %s\n", m_announce.c_str());
        NDBG_OUTPUT("| announce_list: \n");
        for(auto && i_m : m_announce_list)
        {
        NDBG_OUTPUT("|                %s\n", i_m.c_str());
        }
        NDBG_OUTPUT("| creation_date: %u\n",  (unsigned int)m_creation_date);
        NDBG_OUTPUT("| created_by:    %s\n",  m_created_by.c_str());
        NDBG_OUTPUT("| encoding:      %s\n",  m_encoding.c_str());
        NDBG_OUTPUT("| comment:       %s\n",  m_comment.c_str());
        NDBG_OUTPUT("| info_hash:     %s\n",  m_info_hash_str.c_str());
        NDBG_OUTPUT("| name:          %s\n",  m_info_pickr.m_info_name.c_str());
        NDBG_OUTPUT("| length:        %u\n",  (unsigned int)m_info_pickr.m_info_length);
        NDBG_OUTPUT("| num_pieces:    %ld\n", m_info_pickr.m_info_pieces.size());
        NDBG_OUTPUT("| piece_length:  %u\n",  (unsigned int)m_info_pickr.m_info_piece_length);
#if 0
        NDBG_OUTPUT("| pieces: [num: %lu] --------------->\n", m_info_pieces.size());
        uint32_t l_p = 0;
        for (auto && i_p : m_info_pieces)
        {
                char* l_h = nullptr;
                bin2hex(&l_h, i_p.m_data, 20);
                NDBG_OUTPUT("| [%08d]:  %s\n", l_p, l_h);
                if (l_h) { free(l_h); l_h = nullptr; }
                ++l_p;
        }
#endif
        if (m_info_pickr.m_info_files.size())
        {
        NDBG_OUTPUT("| files: [num: %lu] --------------->\n", m_info_pickr.m_info_files.size());
        for(auto && i_f : m_info_pickr.m_info_files)
        {
        NDBG_OUTPUT("| ");
        for(auto& i_p : i_f.m_path)
        {
        NDBG_OUTPUT("%s", i_p.c_str());
        if (i_p != i_f.m_path.back())
        {
        NDBG_OUTPUT("/");
        }
        }
        NDBG_OUTPUT("\n");
        }
        }
        NDBG_OUTPUT("+-----------------------------------------------------------\n");
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::udp_mux(struct sockaddr_storage& a_ss,
                         socklen_t& a_ss_len,
                         uint8_t* a_msg,
                         uint32_t a_msg_len)
{
        if (!a_msg ||
            !a_msg_len)
        {
                return NTRNT_STATUS_OK;
        }
        int32_t l_s;
        // -------------------------------------------------
        // multiplex incoming udp messages based on
        // hueristics below:
        // - DHT packets start with 'd'
        // - UDP tracker msg start w/ 32-bit (!) "action":
        //     w/ values between 0 and 3
        // - else assume µTP packets:
        //     since start w/ 4-bit version number (1).
        //
        // From transmission BitTorrent Client
        // ref: https://github.com/transmission/transmission
        // -------------------------------------------------
        // -------------------------------------------------
        // DHT
        // -------------------------------------------------
        // DHT packets start with 'd'
        // -------------------------------------------------
        if (a_msg[0] == 'd')
        {
                //NDBG_PRINT("DHT msg\n");
                //NDBG_HEXDUMP(a_msg, a_msg_len);
                if (m_dht_mgr)
                {
                        l_s = m_dht_mgr->recv_msg(a_ss, a_ss_len, a_msg, a_msg_len);
                        if (l_s != NTRNT_STATUS_OK)
                        {
                                TRC_ERROR("performing dht recv msg");
                                return NTRNT_STATUS_ERROR;
                        }
                }
        }
        // -------------------------------------------------
        // UDP tracker
        // -------------------------------------------------
        // UDP tracker msg start w/ 32-bit (!) "action":
        //     w/ values between 0 and 3
        // -------------------------------------------------
        else if((a_msg_len >= 8) &&
                (a_msg[0] == 0) &&
                (a_msg[1] == 0) &&
                (a_msg[2] == 0) &&
                (a_msg[3] <= 3))
        {
                //NDBG_PRINT("UDP tracker msg: 0x%08x\n", ((*(uint32_t*)(a_msg))));
                int32_t l_s;
                l_s = tracker_udp::handle_resp(m_tid_tracker_udp_map, a_msg, a_msg_len);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing tracker_udp handle_resp");
                        return NTRNT_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // UTP
        // -------------------------------------------------
        else
        {
                //std::string l_host;
                //NDBG_PRINT("[%sUTP%s] [HOST: %s] msg len: %u\n", ANSI_COLOR_BG_YELLOW, ANSI_COLOR_OFF, sas_to_str(a_ss).c_str(), a_msg_len);
                //NDBG_HEXDUMP(a_msg, a_msg_len);
                // TODO
                // add inactivity timer???
#if 0
                if (!ss->isClosing() && !ss->utp_timer)
                {
                    ss->utp_timer = ss->timerMaker().create(timer_callback, ss);
                    reset_timer(ss);
                }
#endif
                int32_t l_s;
                l_s = utp_process_udp(m_utp_ctx, a_msg, a_msg_len, (const sockaddr*)(&a_ss), sas_size(a_ss));
                // -----------------------------------------
                // ref: utp_internal.cpp
                // - "Should be called each time the UDP
                //  socket is drained" ???
                // -----------------------------------------
                utp_issue_deferred_acks(m_utp_ctx);
                if (l_s != 1)
                {
                        // TODO noisy due to versioning mismatch with libutp???
                        //TRC_ERROR("performing utp_process_udp");
                        // TODO soft fail???
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
int32_t session::setup_udp(void)
{
        int32_t l_s;
        // -------------------------------------------------
        // *************************************************
        //                   I P v 4
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // socket
        // -------------------------------------------------
        errno = 0;
        m_udp_fd = socket(AF_INET,
                          SOCK_DGRAM,
                          0);
        if (m_udp_fd < 0)
        {
                TRC_ERROR("error performing socket. Reason: %s\n", strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // socket options
        // -------------------------------------------------
        // TODO --set to REUSE????
        _SET_SOCK_OPT(m_udp_fd, SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef SO_REUSEPORT
        _SET_SOCK_OPT(m_udp_fd, SOL_SOCKET, SO_REUSEPORT, 1);
#endif
        // -------------------------------------------------
        // set faster recv timeout
        // -------------------------------------------------
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(m_udp_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
        // -------------------------------------------------
        // Can set with set_sock_opt???
        // -------------------------------------------------
        // Set the file descriptor to no-delay mode.
        const int l_flags = ::fcntl(m_udp_fd, F_GETFL, 0);
        if (l_flags == -1)
        {
                TRC_ERROR("Error getting flags for fd. Reason: %s\n", ::strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        if (::fcntl(m_udp_fd, F_SETFL, l_flags | O_NONBLOCK) < 0)
        {
                TRC_ERROR("Error setting fd to non-block mode. Reason: %s\n", ::strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // bind
        // -------------------------------------------------
        struct sockaddr_in l_sa;
        l_sa.sin_family = AF_INET;
        // bind ANY for now...
        l_sa.sin_addr.s_addr = INADDR_ANY;
        //l_sa.sin_addr.s_addr = inet_addr("127.0.0.1");
        l_sa.sin_port = htons(m_ext_port);
        l_s = bind(m_udp_fd, (struct sockaddr *)&l_sa, sizeof((l_sa)));
        if(l_s < 0)
        {
                TRC_ERROR("Error bind() failed (port: %d). Reason[%d]: %s\n", m_udp_fd, errno, strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // setup callbacks
        // -------------------------------------------------
        m_evr_udp_fd.m_magic = EVR_EVENT_FD_MAGIC;
        m_evr_udp_fd.m_read_cb = udp_fd_readable_cb;
        m_evr_udp_fd.m_write_cb = udp_fd_writeable_cb;
        m_evr_udp_fd.m_error_cb = udp_fd_error_cb;
        m_evr_udp_fd.m_data = this;
        // -------------------------------------------------
        // Add to reactor
        // -------------------------------------------------
        l_s = m_evr_loop->add_fd(m_udp_fd,
                                 EVR_FILE_ATTR_MASK_READ |
                                 EVR_FILE_ATTR_MASK_WRITE |
                                 EVR_FILE_ATTR_MASK_RD_HUP|
                                 EVR_FILE_ATTR_MASK_ET,
                                 &m_evr_udp_fd);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("Error: Couldn't add socket file descriptor\n");
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::udp_fd_readable_cb(void *a_data)
{
        if (!a_data)
        {
                TRC_ERROR("a_data == null\n");
                return NTRNT_STATUS_ERROR;
        }
        session* l_ses = (session*)(a_data);
        int32_t l_fd = l_ses->get_udp_fd();
        // -------------------------------------------------
        // buffer setup
        // -------------------------------------------------
        static uint8_t* s_msg = nullptr;
        if (!s_msg)
        {
                s_msg = (uint8_t*)malloc(_MSG_SIZE_MAX);
        }
        // -------------------------------------------------
        // recvfrom
        // -------------------------------------------------
        while (true)
        {
                // -----------------------------------------
                // clear buffer
                // -----------------------------------------
                memset(s_msg, 0, _MSG_SIZE_MAX);
                struct sockaddr_storage l_from;
                socklen_t l_from_len = sizeof(l_from);
                int32_t l_s;
                errno = 0;
                l_s = recvfrom(l_fd,
                               s_msg,
                               _MSG_SIZE_MAX,
                               0,
                               (struct sockaddr*)&l_from,
                               &l_from_len);
                //NDBG_PRINT("[%srecvfrom%s: %d] [fd: %d] [errno[%d]: %s]\n",
                //           ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF,
                //           l_s, l_fd,
                //           errno, strerror(errno));
                if (l_s < 0)
                {
                        if (errno == EAGAIN)
                        {
                                l_s = l_ses->get_peer_mgr().dequeue_out_v4();
                                if (l_s != NTRNT_STATUS_OK)
                                {
                                        if (l_s == NTRNT_STATUS_AGAIN)
                                        {
                                                return NTRNT_STATUS_OK;
                                        }
                                        TRC_ERROR("performing dequeue_out");
                                        NDBG_PRINT("exit...\n");
                                        return NTRNT_STATUS_ERROR;
                                }
                                //NDBG_PRINT("[%sREADABLE%s] exit ...\n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF);
                                return NTRNT_STATUS_OK;
                        }
                        TRC_ERROR("error performing recvfrom. Reason: %s\n", strerror(errno));
                        return NTRNT_STATUS_ERROR;
                }
                if (l_s == 0)
                {
                        return NTRNT_STATUS_OK;
                }
                // -----------------------------------------
                // mux
                // -----------------------------------------
                uint32_t l_len = (uint32_t)l_s;
                l_s = l_ses->udp_mux(l_from, l_from_len, s_msg, l_len);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing udp_mux");
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
int32_t session::udp_fd_writeable_cb(void *a_data)
{
        if (!a_data)
        {
                TRC_ERROR("data == null");
                return NTRNT_STATUS_ERROR;
        }
        int32_t l_s;
        session* l_ses = (session*)(a_data);
        l_s = l_ses->get_peer_mgr().dequeue_out_v4();
        if (l_s != NTRNT_STATUS_OK)
        {
                if (l_s == NTRNT_STATUS_AGAIN)
                {
                        return NTRNT_STATUS_OK;
                }
                TRC_ERROR("performing dequeue_out");
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::udp_fd_error_cb(void *a_data)
{
        NDBG_PRINT("[%sERROR%s]\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::setup_udp6(void)
{
        // -------------------------------------------------
        // *************************************************
        //                   I P v 6
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // socket
        // -------------------------------------------------
        errno = 0;
        m_udp6_fd = socket(AF_INET6,
                           SOCK_DGRAM,
                           0);
        if (m_udp6_fd < 0)
        {
                TRC_ERROR("error performing socket. Reason: %s\n", strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // socket options
        // -------------------------------------------------
        // TODO --set to REUSE????
        _SET_SOCK_OPT(m_udp6_fd, SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef SO_REUSEPORT
        _SET_SOCK_OPT(m_udp6_fd, SOL_SOCKET, SO_REUSEPORT, 1);
#endif
        // -------------------------------------------------
        // set faster recv timeout
        // -------------------------------------------------
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(m_udp6_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
        // -------------------------------------------------
        // Can set with set_sock_opt???
        // -------------------------------------------------
        // Set the file descriptor to no-delay mode.
        const int l_flags = ::fcntl(m_udp6_fd, F_GETFL, 0);
        if (l_flags == -1)
        {
                TRC_ERROR("Error getting flags for fd. Reason: %s\n", ::strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        if (::fcntl(m_udp6_fd, F_SETFL, l_flags | O_NONBLOCK) < 0)
        {
                TRC_ERROR("Error setting fd to non-block mode. Reason: %s\n", ::strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // bind
        // -------------------------------------------------
        struct sockaddr_in6 l_sa;
        l_sa.sin6_family = AF_INET6;
        // bind ANY for now...
        l_sa.sin6_addr = in6addr_any;
        //l_sa.sin6_addr = in6addr_loopback;
        l_sa.sin6_port = htons(m_ext_port);
        int32_t l_s;
        l_s = bind(m_udp6_fd, (struct sockaddr *)&l_sa, sizeof((l_sa)));
        if(l_s < 0)
        {
                TRC_ERROR("Error bind() failed (port: %d). Reason[%d]: %s\n", m_udp6_fd, errno, strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // setup callbacks
        // -------------------------------------------------
        m_evr_udp6_fd.m_magic = EVR_EVENT_FD_MAGIC;
        m_evr_udp6_fd.m_read_cb = udp6_fd_readable_cb;
        m_evr_udp6_fd.m_write_cb = udp6_fd_writeable_cb;
        m_evr_udp6_fd.m_error_cb = udp6_fd_error_cb;
        m_evr_udp6_fd.m_data = this;
        // -------------------------------------------------
        // Add to reactor
        // -------------------------------------------------
        l_s = m_evr_loop->add_fd(m_udp6_fd,
                                 EVR_FILE_ATTR_MASK_READ |
                                 EVR_FILE_ATTR_MASK_WRITE |
                                 EVR_FILE_ATTR_MASK_RD_HUP|
                                 EVR_FILE_ATTR_MASK_ET,
                                 &m_evr_udp6_fd);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("Error: Couldn't add socket file descriptor\n");
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::udp6_fd_readable_cb(void *a_data)
{
        if (!a_data)
        {
                TRC_ERROR("a_data == null\n");
                return NTRNT_STATUS_ERROR;
        }
        session* l_ses = (session*)(a_data);
        int32_t l_fd = l_ses->get_udp6_fd();
        // -------------------------------------------------
        // buffer setup
        // -------------------------------------------------
        static uint8_t* s6_msg = nullptr;
        if (!s6_msg)
        {
                s6_msg = (uint8_t*)malloc(_MSG_SIZE_MAX);
        }
        // -------------------------------------------------
        // recvfrom
        // -------------------------------------------------
        while (true)
        {
                // -----------------------------------------
                // clear buffer
                // -----------------------------------------
                memset(s6_msg, 0, _MSG_SIZE_MAX);
                // -----------------------------------------
                // recvfrom
                // -----------------------------------------
                struct sockaddr_storage l_from;
                socklen_t l_from_len = sizeof(l_from);
                int32_t l_s;
                errno = 0;
                l_s = recvfrom(l_fd,
                                s6_msg,
                               _MSG_SIZE_MAX,
                               0,
                               (struct sockaddr*)&l_from,
                               &l_from_len);
                //NDBG_PRINT("[%srecvfrom%s: %d] [fd: %d] [errno[%d]: %s]\n",
                //           ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF,
                //           l_s, l_fd,
                //           errno, strerror(errno));
                if (l_s < 0)
                {
                        if (errno == EAGAIN)
                        {
                                l_s = l_ses->get_peer_mgr().dequeue_out_v6();
                                if (l_s != NTRNT_STATUS_OK)
                                {
                                        if (l_s == NTRNT_STATUS_AGAIN)
                                        {
                                                return NTRNT_STATUS_OK;
                                        }
                                        TRC_ERROR("performing dequeue_out");
                                        return NTRNT_STATUS_ERROR;
                                }
                                return NTRNT_STATUS_OK;
                        }
                        TRC_ERROR("error performing recvfrom. Reason: %s\n", strerror(errno));
                        return NTRNT_STATUS_ERROR;
                }
                else if (l_s == 0)
                {
                        return NTRNT_STATUS_OK;
                }
                // -----------------------------------------
                // mux
                // -----------------------------------------
                else
                {
                        uint32_t l_len = (uint32_t)l_s;
                        l_s = l_ses->udp_mux(l_from, l_from_len, s6_msg, l_len);
                        if (l_s != NTRNT_STATUS_OK)
                        {
                                return NTRNT_STATUS_ERROR;
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
int32_t session::udp6_fd_writeable_cb(void *a_data)
{
        if (!a_data)
        {
                TRC_ERROR("data == null");
                return NTRNT_STATUS_ERROR;
        }
        int32_t l_s;
        session* l_ses = (session*)(a_data);
        l_s = l_ses->get_peer_mgr().dequeue_out_v6();
        if (l_s != NTRNT_STATUS_OK)
        {
                if (l_s == NTRNT_STATUS_AGAIN)
                {
                        return NTRNT_STATUS_OK;
                }
                TRC_ERROR("performing dequeue_out");
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::udp6_fd_error_cb(void *a_data)
{
        NDBG_PRINT("[%sERROR%s]\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::add_timer(uint32_t a_time_ms,
                           evr_event_cb_t a_cb,
                           void *a_data,
                           void **ao_event)
{
        if(!m_evr_loop)
        {
                return NTRNT_STATUS_ERROR;
        }
        evr_event_t *l_e = nullptr;
        int32_t l_s;
        //++m_stat.m_total_add_timer;
        l_s = m_evr_loop->add_event(a_time_ms,
                                    a_cb,
                                    a_data,
                                    &l_e);
        if(l_s != NTRNT_STATUS_OK)
        {
                return NTRNT_STATUS_ERROR;
        }
        *ao_event = l_e;
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::cancel_timer(void* a_timer)
{
        evr_event_t* l_e = (evr_event_t*)a_timer;
        int32_t l_s;
        l_s = m_evr_loop->cancel_event(l_e);
        if(l_s != NTRNT_STATUS_OK)
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
int32_t session::set_geoip_db(const std::string& a_db)
{
        int32_t l_s;
        m_geoip2_db = a_db;
        m_geoip2_mmdb = new geoip2_mmdb();
        l_s = m_geoip2_mmdb->init(m_geoip2_db);
        if(l_s != NTRNT_STATUS_OK)
        {
                 TRC_ERROR("performing geoip2 mmdb init");
                 return NTRNT_STATUS_OK;
        }
        return NTRNT_STATUS_OK;
}
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
static int32_t _t_trackers(void *a_data)
{
        if(!a_data)
        {
                return NTRNT_STATUS_ERROR;
        }
        session* l_ses = static_cast<session*>(a_data);
        int32_t l_s;
        l_s = l_ses->t_trackers();
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
int32_t session::t_trackers(void)
{
        int32_t l_s;
        // -------------------------------------------------
        // send announce
        // -------------------------------------------------
        uint64_t l_now_s = get_time_s();
        for(auto && i_t : m_tracker_list)
        {
                // -----------------------------------------
                // announce if time
                // -----------------------------------------
                if (l_now_s > i_t->m_next_announce_s)
                {
                        i_t->m_next_announce_s = l_now_s + NTRNT_SESSION_TRACKER_ANNOUNCE_RETRY_S;
                        NDBG_PRINT(": %sannounce%s: %s\n", ANSI_COLOR_BG_MAGENTA, ANSI_COLOR_OFF, i_t->str().c_str());
                        l_s = i_t->announce();
                        if (l_s != NTRNT_STATUS_OK)
                        {
                                TRC_WARN("performing send announce for: %s", i_t->str().c_str());
                                continue;
                        }
                }
                // -----------------------------------------
                // scrape if time
                // -----------------------------------------
                if (l_now_s > i_t->m_next_scrape_s)
                {
                        i_t->m_next_scrape_s = l_now_s + NTRNT_SESSION_TRACKER_SCRAPE_RETRY_S;
                        //NDBG_PRINT(": scrape: %s\n", i_t->str().c_str());
                        l_s = i_t->scrape();
                        if (l_s != NTRNT_STATUS_OK)
                        {
                                TRC_WARN("performing send announce for: %s", i_t->str().c_str());
                                continue;
                        }
                }
        }
        // -------------------------------------------------
        // send scrape
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        // fire again
        // -------------------------------------------------
        void *l_timer = NULL;
        l_s = add_timer((uint32_t)(NTRNT_SESSION_T_TRACKERS_MS),
                         _t_trackers,
                         (void *)this,
                         &l_timer);
        UNUSED(l_s);
        // TODO check status
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t _t_btp(void *a_data)
{
        if(!a_data)
        {
                return NTRNT_STATUS_ERROR;
        }
        session* l_ses = static_cast<session*>(a_data);
        int32_t l_s;
        l_s = l_ses->t_btp();
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing btp");
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::t_btp(void)
{
        int32_t l_s;
        // -------------------------------------------------
        // request info if missing
        // -------------------------------------------------
        if (!m_info_pickr.complete())
        {
                l_s = m_info_pickr.request_info_pieces();
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing connect peers");
                }
        }
        // -------------------------------------------------
        // request blocks
        // -------------------------------------------------
        else
        {
                l_s = m_pickr.request_blocks();
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing connect peers");
                }
        }
        // -------------------------------------------------
        // dequeue messages
        // -------------------------------------------------
        l_s = m_peer_mgr.dequeue_out();
        if (l_s == NTRNT_STATUS_ERROR)
        {
                TRC_ERROR("performing dequeue_out");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // fire again
        // -------------------------------------------------
        void *l_timer = NULL;
        l_s = add_timer((uint32_t)(NTRNT_SESSION_T_BTP_MS),
                         _t_btp,
                         (void *)this,
                         &l_timer);
        UNUSED(l_s);
        // TODO check status
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t _t_connect_peers(void *a_data)
{
        if(!a_data)
        {
                return NTRNT_STATUS_ERROR;
        }
        session* l_ses = static_cast<session*>(a_data);
        int32_t l_s;
        l_s = l_ses->t_connect_peers();
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing periodic");
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::t_connect_peers(void)
{
        int32_t l_s;
        // -------------------------------------------------
        // connect_peers
        // -------------------------------------------------
        l_s = m_peer_mgr.connect_peers();
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing connect peers");
        }
        // -------------------------------------------------
        // fire again
        // -------------------------------------------------
        void *l_timer = NULL;
        l_s = add_timer((uint32_t)(NTRNT_SESSION_T_CONNECT_PEERS_MS),
                         _t_connect_peers,
                         (void *)this,
                         &l_timer);
        UNUSED(l_s);
        // TODO check status
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t _t_check_timeouts(void *a_data)
{
        if(!a_data)
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // perform utp maintenance
        // -------------------------------------------------
        session* l_ses = static_cast<session*>(a_data);
        int32_t l_s;
        l_s = l_ses->t_check_timeouts();
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
int32_t session::t_check_timeouts(void)
{
        // -------------------------------------------------
        // utp maintenance
        // -------------------------------------------------
        // TODO -issue defer-d acks???
        utp_issue_deferred_acks(m_utp_ctx);
        // check timeouts
        utp_check_timeouts(m_utp_ctx);
        // -------------------------------------------------
        // fire again
        // -------------------------------------------------
        void *l_timer = NULL;
        int32_t l_s;
        l_s = add_timer((uint32_t)(NTRNT_SESSION_T_CHECK_TIMEOUTS_MS),
                         _t_check_timeouts,
                         (void *)this,
                         &l_timer);
        UNUSED(l_s);
        // TODO check status
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                                 R  U N
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::run(void)
{
        int32_t l_s;
        if (!m_is_initd)
        {
                return NTRNT_STATUS_ERROR;
        }
        //NDBG_PRINT(": run...\n");
        m_stopped = false;
        // -------------------------------------------------
        // init trackers
        // -------------------------------------------------
        if (m_trackers_enable)
        {
                for(auto && i_a : m_announce_list)
                {
                        const std::string& l_a = i_a;
                        tracker* l_t;
                        l_s = init_tracker_w_url(&l_t, *this, l_a.c_str(), l_a.length());
                        if (l_s != NTRNT_STATUS_OK)
                        {
                                TRC_WARN("error initializing tracker with announce: %s", l_a.c_str());
                                if (l_t) { delete l_t; l_t = nullptr; }
                                continue;
                        }
                        m_tracker_list.push_back(l_t);
                }
        }
        // -------------------------------------------------
        // add peer
        // -------------------------------------------------
        if (!m_peer.empty())
        {
                sockaddr_storage l_sas;
                l_s = str_to_sas(m_peer, l_sas);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing str_to_sas -not a valid ip address+port?");
                        return NTRNT_STATUS_ERROR;
                }
                peer* l_peer = nullptr;
                m_peer_mgr.add_peer(l_sas, NTRNT_PEER_FROM_SELF, &l_peer);
        }
        // -------------------------------------------------
        // *************************************************
        //           T I M E R (S)   K I C K O F F
        // *************************************************
        // -------------------------------------------------
        void *l_timer = NULL;
        // -------------------------------------------------
        // kick off tracker handling
        // -------------------------------------------------
        if (m_trackers_enable)
        {
                l_s = add_timer(0,
                                _t_trackers,
                                (void *)this,
                                &l_timer);
        }
        // -------------------------------------------------
        // kick off bittorrent protocol handling
        // -------------------------------------------------
        l_s = add_timer(NTRNT_SESSION_T_BTP_MS,
                        _t_btp,
                        (void *)this,
                        &l_timer);
        // -------------------------------------------------
        // kick off connect peers
        // -------------------------------------------------
        l_s = add_timer(NTRNT_SESSION_T_CONNECT_PEERS_MS,
                        _t_connect_peers,
                        (void *)this,
                        &l_timer);
        // -------------------------------------------------
        // kick off utp timeouts checking
        // -------------------------------------------------
        l_s = add_timer(NTRNT_SESSION_T_CHECK_TIMEOUTS_MS,
                        _t_check_timeouts,
                        (void *)this,
                        &l_timer);
        // -------------------------------------------------
        // run
        // -------------------------------------------------
        while(!m_stopped)
        {
                // -----------------------------------------
                // run event loop
                // -----------------------------------------
                //++m_stat.m_total_run;
                l_s = m_evr_loop->run();
                if (l_s != NTRNT_STATUS_OK)
                {
                        // TODO log error
                }
        }
        NDBG_PRINT(": stopped\n");
        m_stopped = true;
        return NTRNT_STATUS_OK;
}
}
