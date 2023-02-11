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
#include "support/net_util.h"
#include "core/dht_mgr.h"
// ---------------------------------------------------------
// openssl
// ---------------------------------------------------------
#include <openssl/evp.h>
#include <openssl/rand.h>
// ---------------------------------------------------------
// system
// ---------------------------------------------------------
#include <string.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _DEFAULT_DHT_STATE_FILE "/tmp/ntrnt.dht.json"
#define _DHT_BOOTSTRAP_DEQUEUE_TIME_MS 100
#define _DHT_ANNOUNCE_TIME_MS 1000
#define _DHT_PERIODIC_FIRST_TIME_MS 1000
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                            U S E R   D E F I N E D
//! ****************************************************************************
//! ----------------------------------------------------------------------------
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int _dhsco_sendto(int a_sockfd,
                         const void* a_buf,
                         int a_len,
                         int a_flags,
                         const struct sockaddr* a_to,
                         int a_to_len)
{
        return sendto(a_sockfd, a_buf, a_len, a_flags, a_to, a_to_len);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static bool _dhsco_blacklisted(const struct sockaddr* a_sa, int a_sa_len)
{
        return false;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static void _dhsco_hash(void* a_hash_return,
                        int a_hash_size,
                        const void* a_v1,
                        int a_len1,
                        const void* a_v2,
                        int a_len2,
                        const void* a_v3,
                        int a_len3)
{
        // -------------------------------------------------
        // sha1 impl
        // -------------------------------------------------
        static const uint16_t s_hash_len = 20;
        uint8_t l_hash[s_hash_len];
        EVP_MD_CTX* l_ctx = nullptr;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        l_ctx = EVP_MD_CTX_new();
#else
        l_ctx = EVP_MD_CTX_create();
#endif
        EVP_DigestInit_ex(l_ctx, EVP_sha1(), nullptr);
        EVP_DigestUpdate(l_ctx, (const uint8_t*)a_v1, a_len1);
        EVP_DigestUpdate(l_ctx, (const uint8_t*)a_v2, a_len2);
        EVP_DigestUpdate(l_ctx, (const uint8_t*)a_v3, a_len3);
        EVP_DigestFinal_ex(l_ctx, (uint8_t*)l_hash, nullptr);
        if(a_hash_size > 20)
        {
                memset((char*)a_hash_return + 20, 0, a_hash_size - 20);
        }
        memcpy(a_hash_return, l_hash, a_hash_size > 20 ? 20 : a_hash_size);
        if (l_ctx) { EVP_MD_CTX_free(l_ctx); l_ctx = nullptr; }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int _dhsco_random_bytes(void* a_buf, size_t a_size)
{
        int l_s;
        l_s = RAND_bytes((uint8_t*)a_buf, a_size);
        if (l_s != 1)
        {
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
}
//! ----------------------------------------------------------------------------
//! dhsco cb
//! ----------------------------------------------------------------------------
dhsco_sendto_cb_t g_dhsco_sendto_cb = ns_ntrnt::_dhsco_sendto;
dhsco_blacklisted_cb_t g_dhsco_blacklisted_cb = ns_ntrnt::_dhsco_blacklisted;
dhsco_hash_cb_t g_dhsco_hash_cb = ns_ntrnt::_dhsco_hash;
dhsco_random_bytes_cb_t g_dhsco_random_bytes_cb = ns_ntrnt::_dhsco_random_bytes;
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                       T I M E R   C A L L B A C K S
//! ****************************************************************************
//! ----------------------------------------------------------------------------
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t _periodic(void *a_data)
{
        if(!a_data)
        {
                return NTRNT_STATUS_ERROR;
        }
        dht_mgr* l_dhm = static_cast<dht_mgr*>(a_data);
        int32_t l_s;
        l_s = l_dhm->periodic();
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing dht_periodic");
        }
        // TODO check status???
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t _bootstrap(void *a_data)
{
        if(!a_data)
        {
                return NTRNT_STATUS_ERROR;
        }
        dht_mgr* l_dhm = static_cast<dht_mgr*>(a_data);
        int32_t l_s;
        l_s = l_dhm->bootstrap_dq();
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing dht_bootstrap_dq");
        }
        // TODO check status???
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t _announce(void *a_data)
{
        if(!a_data)
        {
                return NTRNT_STATUS_ERROR;
        }
        dht_mgr* l_dhm = static_cast<dht_mgr*>(a_data);
        int32_t l_s;
        l_s = l_dhm->announce();
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing dht_announce");
        }
        // TODO check status???
        return l_s;
}
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                            D H T   M A N A G E R
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
dht_mgr::dht_mgr(session& a_session):
        m_session(a_session),
        m_dhsco(nullptr),
        m_id()
{
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
dht_mgr::~dht_mgr(void)
{
        // -------------------------------------------------
        // dht
        // -------------------------------------------------
        int32_t l_s;
        l_s = m_dhsco->save(_DEFAULT_DHT_STATE_FILE);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("saving dht state to: %s", _DEFAULT_DHT_STATE_FILE);
        }
        if (m_dhsco)
        {
                delete m_dhsco;
                m_dhsco = nullptr;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t dht_mgr::init(void)
{
        int32_t l_s;
        // -------------------------------------------------
        // *************************************************
        //                 D H T  S E T U P
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // dht id
        // -------------------------------------------------
        l_s = _dhsco_random_bytes(m_id.m_data, sizeof(m_id));
        if (l_s != NTRNT_STATUS_OK)
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // setup dht
        // -------------------------------------------------
        m_dhsco = new dhsco(m_session.get_udp_fd(),
                            m_session.get_udp6_fd(),
                            m_id.m_data,
                            nullptr);
        // -------------------------------------------------
        // load dht state from file
        // -------------------------------------------------
        l_s = m_dhsco->load(_DEFAULT_DHT_STATE_FILE);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("loading dht from file: %s", _DEFAULT_DHT_STATE_FILE);
                // soft error -file may be missing
        }
        // -------------------------------------------------
        // *************************************************
        //           T I M E R (S)   K I C K O F F
        // *************************************************
        // -------------------------------------------------
        void *l_timer = NULL;
        // -------------------------------------------------
        // kick off bootstrap
        // -------------------------------------------------
        l_s = m_session.add_timer(_DHT_BOOTSTRAP_DEQUEUE_TIME_MS,
                                  _bootstrap,
                                  (void *)this,
                                  &l_timer);
        UNUSED(l_s);
        UNUSED(l_timer);
        // -------------------------------------------------
        // kick off announce
        // -------------------------------------------------
        l_s = m_session.add_timer(_DHT_ANNOUNCE_TIME_MS,
                                  _announce,
                                  (void *)this,
                                  &l_timer);
        UNUSED(l_s);
        UNUSED(l_timer);
        // -------------------------------------------------
        // kick off periodic
        // -------------------------------------------------
        l_s = m_session.add_timer(_DHT_PERIODIC_FIRST_TIME_MS,
                                  _periodic,
                                  (void *)this,
                                  &l_timer);
        UNUSED(l_s);
        UNUSED(l_timer);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t dht_mgr::recv_msg(struct sockaddr_storage& a_ss,
                          socklen_t& a_ss_len,
                          uint8_t* a_msg,
                          uint32_t a_msg_len)
{
        if (!a_msg ||
            !a_msg_len)
        {
                TRC_ERROR("bad message length msg: %p msg_len: %u", a_msg, a_msg_len);
                return NTRNT_STATUS_ERROR;
        }
        // dht requires zero-terminated messages
#if 0
        if (a_msg[a_msg_len] != '\0')
        {
                TRC_ERROR("bad message length msg: %p msg_len: %u -missing null terminator", a_msg, a_msg_len);
                return NTRNT_STATUS_ERROR;
        }
#else
        a_msg[a_msg_len] = '\0';
#endif
        // -------------------------------------------------
        // run periodic
        // -------------------------------------------------
        time_t l_to_sleep;
        int32_t l_s;
        l_s = m_dhsco->periodic((const void*)a_msg,
                                (size_t)a_msg_len,
                                (const struct sockaddr*)&a_ss,
                                a_ss_len,
                                &l_to_sleep,
                                dht_cb,
                                this);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing dht_periodic.");
                return NTRNT_STATUS_ERROR;
        }
        //m_dhsco->display();
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t dht_mgr::ping(struct sockaddr_storage& a_sas)
{
        int32_t l_s;
        l_s = m_dhsco->ping_node((const sockaddr*)&a_sas, sas_size(a_sas));
        UNUSED(l_s);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void dht_mgr::dht_cb(void* a_ctx,
                     dht_event_t a_event,
                     uint8_t const* a_info_hash,
                     void const* a_data,
                     size_t a_data_len)
{
        if (!a_ctx)
        {
                TRC_ERROR("ctx == nullptr");
                return;
        }
        dht_mgr& l_mgr = *((dht_mgr*)a_ctx);
        session& l_ses = l_mgr.get_session();
        switch(a_event)
        {
        // -------------------------------------------------
        // DHT_EVENT_VALUES
        // -------------------------------------------------
        case DHT_EVENT_VALUES:
        {
                int32_t l_s;
                l_s = l_ses.add_peer_raw(AF_INET, (uint8_t*)a_data, a_data_len, NTRNT_PEER_FROM_DHT);
                UNUSED(l_s);
                break;
        }
        // -------------------------------------------------
        // DHT_EVENT_VALUES6
        // -------------------------------------------------
        case DHT_EVENT_VALUES6:
        {
                int32_t l_s;
                l_s = l_ses.add_peer_raw(AF_INET6, (uint8_t*)a_data, a_data_len, NTRNT_PEER_FROM_DHT);
                UNUSED(l_s);
                break;
        }
        // -------------------------------------------------
        // DHT_EVENT_SEARCH_DONE
        // -------------------------------------------------
        case DHT_EVENT_SEARCH_DONE:
        {
                break;
        }
        // -------------------------------------------------
        // DHT_EVENT_SEARCH_DONE6
        // -------------------------------------------------
        case DHT_EVENT_SEARCH_DONE6:
        {
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
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t dht_mgr::bootstrap_dq(void)
{
        // -------------------------------------------------
        // dequeue
        // -------------------------------------------------
        int32_t l_s;
        l_s = m_dhsco->bootstrap_dq();
        if (l_s != NTRNT_STATUS_OK)
        {
                //TRC_ERROR("performing dht_bootstrap_dq");
        }
        // -------------------------------------------------
        // done bootstrapping -don't fire again
        // -------------------------------------------------
        if (!m_dhsco->bootstrap_size())
        {
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // fire again
        // -------------------------------------------------
        void *l_timer = NULL;
        l_s = m_session.add_timer(_DHT_BOOTSTRAP_DEQUEUE_TIME_MS,
                                  _bootstrap,
                                  (void *)this,
                                  &l_timer);
        // TODO Check status...
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t dht_mgr::announce(void)
{
        int32_t l_s;
        // -------------------------------------------------
        // call announce
        // -------------------------------------------------
        // TODO check quality first
        // -------------------------------------------------
        // ipv4
        // -------------------------------------------------
        l_s = m_dhsco->search(m_session.get_info_hash(),
                              m_session.get_udp_fd(),
                              AF_INET,
                              dht_cb,
                              this);
        if (l_s != NTRNT_STATUS_OK)
        {
                //TRC_ERROR("performing dhsco search");
                // soft fail
        }
        // -------------------------------------------------
        // ipv6
        // -------------------------------------------------
        l_s = m_dhsco->search(m_session.get_info_hash(),
                              m_session.get_udp6_fd(),
                              AF_INET6,
                              dht_cb,
                              this);
        if (l_s != NTRNT_STATUS_OK)
        {
                //TRC_ERROR("performing dhsco search");
                // soft fail
        }
        // -------------------------------------------------
        // fire again
        // -------------------------------------------------
        void *l_timer = NULL;
        l_s = m_session.add_timer(_DHT_ANNOUNCE_TIME_MS,
                                  _announce,
                                  (void *)this,
                                  &l_timer);
        UNUSED(l_s);
        // TODO Check status...
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t dht_mgr::periodic(void)
{
        int32_t l_s;
        // -------------------------------------------------
        // call periodic
        // -------------------------------------------------
        time_t l_to_sleep;
        l_s = m_dhsco->periodic((const void*)nullptr,
                                (size_t)0,
                                (const struct sockaddr*)nullptr,
                                0,
                                &l_to_sleep,
                                dht_cb,
                                this);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing dht_periodic.");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // fire again
        // -------------------------------------------------
        void *l_timer = NULL;
        l_s = m_session.add_timer((uint32_t)(l_to_sleep*1000),
                                  _periodic,
                                  (void *)this,
                                  &l_timer);
        UNUSED(l_s);
        // TODO Check status...
        return NTRNT_STATUS_OK;
}
}
