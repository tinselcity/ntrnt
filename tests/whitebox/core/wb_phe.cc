//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <string.h>
#include "catch/catch.hpp"
#include "core/phe.h"
#include "ntrnt/def.h"
#include "support/nbq.h"
#include "support/ndebug.h"
#include "support/util.h"
#if 0
#include <openssl/evp.h>
#endif
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#if 0
#ifndef _SHA1_SIZE
#define _SHA1_SIZE 20
#endif
#ifndef _SHA1_SIZE_HEX
#define _SHA1_SIZE_HEX 40
#endif
#endif
//! ----------------------------------------------------------------------------
//! sha1 hasher
//! ----------------------------------------------------------------------------
#if 0
class _sha1void* a_data, void* a_buf, size_t a_len
{
public:
        // -------------------------------------------------
        // constructor
        // -------------------------------------------------
        _sha1():
                m_ctx(nullptr),
                m_finished(false),
                m_hash_hex()
        {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
                m_ctx = EVP_MD_CTX_new();
#else
                m_ctx = EVP_MD_CTX_create();
#endif
                EVP_DigestInit_ex(m_ctx, EVP_sha1(), nullptr);
                m_hash_hex[0] = '\0';
        }
        // -------------------------------------------------
        // destructor
        // -------------------------------------------------
        ~_sha1()
        {
                if (nullptr != m_ctx)
                {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
                        EVP_MD_CTX_free(m_ctx);
#else
                        EVP_MD_CTX_destroy(m_ctx);
#endif
                }
        }
        // -------------------------------------------------
        // update
        // -------------------------------------------------
        void update(const uint8_t* a_buf, unsigned int a_len)
        {
                EVP_DigestUpdate(m_ctx, a_buf, a_len);
        }
        // -------------------------------------------------
        // finish
        // -------------------------------------------------
        void finish()
        {
                if(m_finished)
                {
                        return;
                }
                EVP_DigestFinal_ex(m_ctx, m_hash, nullptr);
                m_finished = true;
        }
        // -------------------------------------------------
        // get_hash_hex
        // -------------------------------------------------
        const char* get_hash_hex()
        {
                finish();
                if (m_hash_hex[0] == '\0')
                {
                        static const char s_hexchars[] =
                        {
                                '0', '1', '2', '3',
                                '4', '5', '6', '7',
                                '8', '9', 'a', 'b',
                                'c', 'd', 'e', 'f'
                        };
                        for(size_t i = 0; i < _SHA1_SIZE; ++i)
                        {
                                m_hash_hex[2 * i + 0] = s_hexchars[(m_hash[i] & 0xf0) >> 4];
                                m_hash_hex[2 * i + 1] = s_hexchars[m_hash[i] & 0x0f];
                        }
                        m_hash_hex[_SHA1_SIZE_HEX] = '\0';
                }
                return m_hash_hex;
        }
        // -------------------------------------------------
        // get_hash
        // -------------------------------------------------
        const uint8_t* get_hash()
        {
                finish();
                return m_hash;
        }
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        _sha1(const _sha1&);
        _sha1& operator=(const _sha1&);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        EVP_MD_CTX* m_ctx;
        bool m_finished;
        uint8_t m_hash[_SHA1_SIZE];
        char m_hash_hex[_SHA1_SIZE_HEX+1];
};
#endif
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
#define _SKEY "abcdefghijklmnopqrst"
static int _select_skey_cb(void* a_data, void* a_cb_ctx, void* a_buf,
                           size_t a_len) {
  if (!a_data) {
    return NTRNT_STATUS_ERROR;
  }
  std::string l_obfs_key;
  ns_ntrnt::bin2hex_str(l_obfs_key, (const uint8_t*)a_buf, a_len);
  NDBG_PRINT("obfs_key: %s\n", l_obfs_key.c_str());
  // -------------------------------------------------
  // compare
  // -------------------------------------------------
#if 0
        _sha1 l_req3_sha;
        l_req3_sha.update((const uint8_t*)("req2"), sizeof("req2")-1);
        l_req3_sha.update((const uint8_t*)(_SKEY), sizeof(_SKEY)-1);
        l_req3_sha.finish();
        NDBG_PRINT("compare:  %s\n", l_req3_sha.get_hash_hex());
#endif
  // -------------------------------------------------
  //
  // -------------------------------------------------
  ns_ntrnt::phe* l_phe = (ns_ntrnt::phe*)a_data;
  l_phe->set_skey((const uint8_t*)_SKEY, sizeof(_SKEY) - 1);
  return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! phe tests
//! ----------------------------------------------------------------------------
TEST_CASE("protocol header encryption", "[phe]") {
  ns_ntrnt::phe::s_phe_select_skey_cb = _select_skey_cb;
  srand(time(NULL));
  // -------------------------------------------------
  // validate sha1 sum
  // -------------------------------------------------
#if 0
        SECTION("sha1") {
                char const l_str[] = "hello world";
                std::string l_sha1 = ns_ntrnt::phe::sha1sum((const uint8_t*)l_str, sizeof(l_str)-1);
                REQUIRE((l_sha1 == "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"));
        }
#endif
  SECTION("two peers connecting") {
#define _HANDSHAKE_PEER1 "HELLO FROM PEER 1"
#define _HANDSHAKE_PEER2 "HELLO FROM PEER 2"
    ns_ntrnt::phe l_peer1;
    ns_ntrnt::nbq l_peer1_in_q(4096);
    ns_ntrnt::nbq l_peer1_out_q(4096);
    ns_ntrnt::phe l_peer2;
    ns_ntrnt::nbq l_peer2_in_q(4096);
    ns_ntrnt::nbq l_peer2_out_q(4096);
    NDBG_PRINT("[%sPHE%s]: SKEY\n", ANSI_COLOR_BG_MAGENTA, ANSI_COLOR_OFF);
    ns_ntrnt::mem_display((const uint8_t*)_SKEY, sizeof(_SKEY) - 1);
    // -----------------------------------------
    // init
    // -----------------------------------------
    int32_t l_s;
    l_s = l_peer1.init();
    REQUIRE((l_s == NTRNT_STATUS_OK));
    l_peer1.set_skey((const uint8_t*)_SKEY, sizeof(_SKEY) - 1);
    l_peer1.set_ia((const uint8_t*)_HANDSHAKE_PEER1,
                   sizeof(_HANDSHAKE_PEER1) - 1);
    // TODO -should only add skey if initiating
    l_s = l_peer2.init();
    REQUIRE((l_s == NTRNT_STATUS_OK));
    l_peer2.set_ia((const uint8_t*)_HANDSHAKE_PEER2,
                   sizeof(_HANDSHAKE_PEER2) - 1);
    // -----------------------------------------
    // send ya
    // -----------------------------------------
    l_peer1.set_state(ns_ntrnt::phe::PHE_STATE_NONE);
    l_s = l_peer1.connect(l_peer1_in_q, l_peer1_out_q);
    REQUIRE((l_s == NTRNT_STATUS_AGAIN));
    REQUIRE((l_peer1.get_state() == ns_ntrnt::phe::PHE_STATE_WAITING_FOR_YB));
    // -----------------------------------------
    // recv ya+send yb
    // -----------------------------------------
    NDBG_PRINT("peer2 state: %d\n", l_peer2.get_state());
    l_peer2_in_q.write_q(l_peer1_out_q);
    l_s = l_peer2.connect(l_peer2_in_q, l_peer2_out_q);
    REQUIRE((l_s == NTRNT_STATUS_AGAIN));
    NDBG_PRINT("peer2 state: %d\n", l_peer2.get_state());
    REQUIRE((l_peer2.get_state() ==
             ns_ntrnt::phe::PHE_STATE_WAITING_FOR_AB_NEEDLE));
    // -----------------------------------------
    // recv yb+send ab
    // -----------------------------------------
    NDBG_PRINT("peer1 state: %d\n", l_peer1.get_state());
    l_peer1_in_q.write_q(l_peer2_out_q);
    l_s = l_peer1.connect(l_peer1_in_q, l_peer1_out_q);
    REQUIRE((l_s == NTRNT_STATUS_AGAIN));
    NDBG_PRINT("peer1 state: %d\n", l_peer1.get_state());
    REQUIRE((l_peer1.get_state() ==
             ns_ntrnt::phe::PHE_STATE_WAITING_FOR_BA_NEEDLE));
    // -----------------------------------------
    // recv ab+send ba
    // -----------------------------------------
    NDBG_PRINT("peer2 state: %d\n", l_peer2.get_state());
    l_peer2_in_q.write_q(l_peer1_out_q);
    l_s = l_peer2.connect(l_peer2_in_q, l_peer2_out_q);
    REQUIRE((l_s == NTRNT_STATUS_OK));
    NDBG_PRINT("peer2 state: %d\n", l_peer2.get_state());
    REQUIRE((l_peer2.get_state() == ns_ntrnt::phe::PHE_STATE_CONNECTED));
    // -----------------------------------------
    // recv ba
    // -----------------------------------------
    NDBG_PRINT("peer1 state: %d\n", l_peer1.get_state());
    l_peer1_in_q.write_q(l_peer2_out_q);
    l_s = l_peer1.connect(l_peer1_in_q, l_peer1_out_q);
    REQUIRE((l_s == NTRNT_STATUS_OK));
    NDBG_PRINT("peer1 state: %d\n", l_peer1.get_state());
    REQUIRE((l_peer1.get_state() == ns_ntrnt::phe::PHE_STATE_CONNECTED));
    // -----------------------------------------
    // check handshakes p2 -is in ia
    // -----------------------------------------
    const uint8_t* l_p2_rcvd_ia;
    size_t l_p2_rcvd_ia_len;
    l_peer2.get_recvd_ia(&l_p2_rcvd_ia, l_p2_rcvd_ia_len);
    NDBG_PRINT("PEER2 RECVD IA LEN: %lu\n", l_p2_rcvd_ia_len);
    NDBG_PRINT("l_p2_rcvd_ia: %.*s\n", (int)l_p2_rcvd_ia_len, l_p2_rcvd_ia);
    REQUIRE((memcmp(l_p2_rcvd_ia, _HANDSHAKE_PEER1, l_p2_rcvd_ia_len) == 0));
    // -----------------------------------------
    // p1 is in remainder of buffer
    // -----------------------------------------
    size_t l_p1_rcvd_ia_len = l_peer1_in_q.read_avail();
    uint8_t* l_p1_rcvd_ia =
        (uint8_t*)malloc(sizeof(uint8_t) * l_p1_rcvd_ia_len);
    off_t l_off;
    l_off = l_peer1_in_q.read((char*)l_p1_rcvd_ia, l_p1_rcvd_ia_len);
    UNUSED(l_off);
    // decrypt
    l_peer1.decrypt(l_p1_rcvd_ia, l_p1_rcvd_ia_len);
    NDBG_PRINT("PEER1 RECVD IA LEN: %lu\n", l_p1_rcvd_ia_len);
    NDBG_PRINT("l_p1_rcvd_ia: %.*s\n", (int)l_p1_rcvd_ia_len, l_p1_rcvd_ia);
    //REQUIRE((memcmp(l_p1_rcvd_ia, _HANDSHAKE_PEER2, l_p1_rcvd_ia_len) == 0));
    if (l_p1_rcvd_ia) {
      free(l_p1_rcvd_ia);
      l_p1_rcvd_ia = nullptr;
    }
  }
}
