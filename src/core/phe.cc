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
#include "core/phe.h"
#include "core/peer.h"
#include "support/ndebug.h"
#include "support/trace.h"
#include "support/sha1.h"
// ---------------------------------------------------------
// openssl
// ---------------------------------------------------------
#include <openssl/rand.h>
#include <openssl/bn.h>
// ---------------------------------------------------------
// c++ stdlib
// ---------------------------------------------------------
#include <vector>
// ---------------------------------------------------------
// system
// ---------------------------------------------------------
#include <string.h>
#include <arpa/inet.h>
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::vector<uint8_t> uint8_vec_t;
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _PHE_MAX_RAND_PAD 512
#define _PHE_ARC4_DISCARD 1024
#define _PHE_ENCRYPT_KEYA "keyA"
#define _PHE_ENCRYPT_KEYB "keyB"
#define _AB_MSG_STR_REQ1 "req1"
#define _AB_MSG_STR_REQ2 "req2"
#define _AB_MSG_STR_REQ3 "req3"
// ---------------------------------------------------------
// MSE constants.
// http://wiki.vuze.com/w/Message_Stream_Encryption
// crypto_provide and crypto_select are 32 bit bitfields.
//  - 0x01: plaintext
//  - 0x02: RC4
// ...
// Remaining bits reserved for future use.
// ---------------------------------------------------------
typedef enum {
        PHE_CRYPTO_PROVIDE_NONE = 0,
        PHE_CRYPTO_PROVIDE_PLAINTEXT = 1 << 0,
        PHE_CRYPTO_PROVIDE_RC4 = 1 << 1,
} _phe_crypto_provide_t;
// ---------------------------------------------------------
// ##### DH Parameters
// ...
// Prime P is a 768 bit safe prime, "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563"
// Generator G is "2"
// ...
// ref: https://wiki.vuze.com/w/Message_Stream_Encryption
// ---------------------------------------------------------
static const uint8_t _g_dhe_generator[] = {
        2
};
static const uint8_t _g_dhe_prime[] = {
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2,
        0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B,
        0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08,
        0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6,
        0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79,
        0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3,
        0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D,
        0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76,
        0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9,
        0xA6, 0x3A, 0x36, 0x21,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x09, 0x05, 0x63,
};
// ---------------------------------------------------------
// verification constant
// ---------------------------------------------------------
// VC is a verification constant used to verify whether the
// other side knows S and SKEY and thus defeats replay
// attacks of the SKEY hash.
// As of this version VC is a String of 8 bytes set to 0x00.
// ---------------------------------------------------------
static const uint8_t _g_dhe_vc[] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
};
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! arc4
//! ----------------------------------------------------------------------------
class arc4 {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        arc4():
                m_i(0),
                m_j(0),
                m_s()
        {}
        ~arc4() {}
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        void init(void const* a_key, size_t a_key_len)
        {
                m_i = 0;
                m_j = 0;
                for (size_t i = 0; i < 256; ++i)
                {
                        m_s[i] = (uint8_t)i;
                }
                for (size_t i = 0, j = 0; i < 256; ++i)
                {
                        j = (uint8_t)(j + m_s[i] + ((uint8_t const*)a_key)[i % a_key_len]);
                        swap(i, j);
                }
        }
        // -------------------------------------------------
        // process
        // -------------------------------------------------
        void process(void* a_dst, void const* a_src, size_t a_len)
        {
                for (size_t i = 0; i < a_len; ++i)
                {
                        ((uint8_t*)a_dst)[i] = ((uint8_t const*)a_src)[i] ^ next();
                }
        }
        // -------------------------------------------------
        // discard
        // -------------------------------------------------
        void discard(size_t a_len)
        {
                for (size_t i = 0; i < a_len; ++i)
                {
                        next();
                }
        }
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // disallow copy/assign
        arc4(const arc4&);
        arc4& operator=(const arc4&);
        // -------------------------------------------------
        // swap
        // -------------------------------------------------
        void swap(size_t a_i, size_t a_j)
        {
                uint8_t const l_t = m_s[a_i];
                m_s[a_i] = m_s[a_j];
                m_s[a_j] = l_t;
        }
        // -------------------------------------------------
        // next
        // -------------------------------------------------
        uint8_t next(void)
        {
                m_i += 1;
                m_j += m_s[m_i];
                swap(m_i, m_j);
                return m_s[(uint8_t)(m_s[m_i] + m_s[m_j])];
        }
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        uint8_t m_i;
        uint8_t m_j;
        uint8_t m_s[256];
};
//! ----------------------------------------------------------------------------
//! select key callback
//! ----------------------------------------------------------------------------
phe_select_skey_cb_t phe::s_phe_select_skey_cb = nullptr;
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
phe::phe(void):
        m_state(PHE_STATE_WAITING_FOR_YA),
        m_prv_key(),
        m_pub_key(),
        m_secret(),
        m_cb_data(nullptr),
        m_skey(nullptr),
        m_skey_len(0),
        m_crypto_provide(0),
        m_crypto_select(0),
        m_padc_len(0),
        m_padd_len(0),
        m_ia(nullptr),
        m_ia_len(0),
        m_recvd_ia(nullptr),
        m_recvd_ia_len(0),
        m_encrypt(nullptr),
        m_decrypt(nullptr)
{
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
phe::~phe(void)
{
        if (m_skey)
        {
                free(m_skey);
                m_skey = nullptr;
                m_skey_len = 0;
        }
        if (m_ia)
        {
                free(m_ia);
                m_ia = nullptr;
                m_ia_len = 0;
        }
        if (m_recvd_ia)
        {
                free(m_recvd_ia);
                m_recvd_ia = nullptr;
                m_recvd_ia_len = 0;
        }
        if (m_encrypt)
        {
                delete m_encrypt;
                m_encrypt = nullptr;
        }
        if (m_decrypt)
        {
                delete m_decrypt;
                m_decrypt = nullptr;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t phe::init(void)
{
        int32_t l_ret = NTRNT_STATUS_OK;
        int l_s;
        // -------------------------------------------------
        // create keys per
        // ref: https://wiki.vuze.com/w/Message_Stream_Encryption
        // -------------------------------------------------
        // Pubkey of A: Ya = (G^Xa) mod P
        // Pubkey of B: Yb = (G^Xb) mod P
        //
        // DH secret: S = (Ya^Xb) mod P = (Yb^Xa) mod P
        //
        // P, S, Ya and Yb are 768bits long
        // -------------------------------------------------
        // -------------------------------------------------
        // generate private key
        // -------------------------------------------------
        l_s = RAND_bytes((uint8_t*)m_prv_key, sizeof(m_prv_key));
        if (l_s != 1)
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // generate public key
        // Pubkey of A: Ya = (G^Xa) mod P
        // where:
        //   G (generator):    "2"
        //   P (prime):        "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563"
        //   Xa (private key): variable sized random integers
        // -------------------------------------------------
        BIGNUM* const l_g = BN_bin2bn(_g_dhe_generator, sizeof(_g_dhe_generator), nullptr);
        BIGNUM* const l_p = BN_bin2bn(_g_dhe_prime, sizeof(_g_dhe_prime), nullptr);
        BIGNUM* const l_xa = BN_bin2bn(m_prv_key, sizeof(m_prv_key), nullptr);
        BIGNUM *l_ya = BN_new();
        BN_CTX *l_ctx = BN_CTX_new();
        //  ("Ya=G^Xa % P")
        l_s = BN_mod_exp(l_ya, l_g, l_xa, l_p, l_ctx);
        if (l_s != 1)
        {
                TRC_ERROR("performing BN_mod_exp");
                l_ret = NTRNT_STATUS_ERROR;
                goto done;
        }
        l_s = BN_bn2bin(l_ya, m_pub_key);
        // -------------------------------------------------
        // DH can generate key sizes smaller than size of
        // pub key buffer, in which case msb's of key buffer
        // need to be zeroed appropriately
        // -------------------------------------------------
        if (l_s != sizeof(m_pub_key))
        {
                size_t const l_off = sizeof(m_pub_key) - l_s;
                memmove(m_pub_key + l_off, m_pub_key, l_s);
                memset(m_pub_key, 0, l_off);
        }
done:
        if (l_g) { BN_free(l_g);}
        if (l_p) { BN_free(l_p);}
        if (l_xa) { BN_free(l_xa);}
        if (l_ya) { BN_free(l_ya); l_ya = nullptr; }
        if (l_ctx) { BN_CTX_free(l_ctx); l_ctx = nullptr; }
        return l_ret;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void phe::set_skey(const uint8_t* a_buf, uint16_t a_len)
{
        if (!a_buf ||
            !a_len)
        {
                return;
        }
        if (m_skey)
        {
                free(m_skey);
                m_skey = nullptr;
                m_skey_len = 0;
        }
        m_skey_len = a_len;
        m_skey = (uint8_t*)malloc(sizeof(uint8_t)*m_skey_len);
        memcpy(m_skey, a_buf, m_skey_len);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void phe::set_ia(const uint8_t* a_buf, uint16_t a_len)
{
        if (!a_buf ||
            !a_len)
        {
                return;
        }
        if (m_ia)
        {
                free(m_ia);
                m_ia = nullptr;
                m_ia_len = 0;
        }
        m_ia_len = a_len;
        m_ia = (uint8_t*)malloc(sizeof(uint8_t)*m_ia_len);
        memcpy(m_ia, a_buf, m_ia_len);
}
//! ----------------------------------------------------------------------------
//! \details: send public key + random padding (up to 512 bytes)
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t phe::send_ya(nbq& a_out_q)
{
        //NDBG_PRINT("[PHE] send_ya\n");
        //NDBG_HEXDUMP(m_pub_key, sizeof(m_pub_key));
        // -------------------------------------------------
        // 1 A->B: Diffie Hellman Ya, PadA
        // -------------------------------------------------
        int32_t l_s;
        l_s = padded_send(a_out_q, m_pub_key, sizeof(m_pub_key));
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing padded_send");
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: send public key + random padding (up to 512 bytes)
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t phe::send_yb(nbq& a_out_q)
{
        //NDBG_PRINT("[PHE] send_yb\n");
        // -------------------------------------------------
        // 2 B->A: Diffie Hellman Yb, PadB
        // -------------------------------------------------
        int32_t l_s;
        l_s = padded_send(a_out_q, m_pub_key, sizeof(m_pub_key));
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing padded_send");
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t phe::recv_ya(nbq& a_in_q)
{
        //NDBG_PRINT("[PHE] recv_ya [READ_AVAIL: %lu]\n", a_in_q.read_avail());
        int32_t l_s;
        //NDBG_HEXDUMP(a_buf, a_len);
        // -------------------------------------------------
        // check len
        // -------------------------------------------------
        if (a_in_q.read_avail() < PHE_PUBLIC_KEY_SIZE)
        {
                //TRC_ERROR("Ya < %d bytes (public key size)", PHE_PUBLIC_KEY_SIZE);
                return NTRNT_STATUS_AGAIN;
        }
        // -------------------------------------------------
        // read in key size
        // -------------------------------------------------
        char* l_buf = nullptr;
        ssize_t l_ss;
        l_buf = (char*)malloc(sizeof(char)*PHE_PUBLIC_KEY_SIZE);
        l_ss = a_in_q.read(l_buf, PHE_PUBLIC_KEY_SIZE);
        //NDBG_PRINT("[PHE] recv_ya [READ_AVAIL: %lu]\n", a_in_q.read_avail());
        UNUSED(l_ss);
        // -------------------------------------------------
        // create bignum
        // -------------------------------------------------
        BIGNUM* const l_ya = BN_bin2bn((const unsigned char*)l_buf, PHE_PUBLIC_KEY_SIZE, nullptr);
        // -------------------------------------------------
        // get secret
        // S = (Yb ^ Xa) mod P
        // -------------------------------------------------
        BIGNUM* const l_p = BN_bin2bn(_g_dhe_prime, sizeof(_g_dhe_prime), nullptr);
        BIGNUM* const l_xb = BN_bin2bn(m_prv_key, sizeof(m_prv_key), nullptr);
        BIGNUM *l_secret = BN_new();
        BN_CTX *l_ctx = BN_CTX_new();
        l_s = BN_mod_exp(l_secret, l_ya, l_xb, l_p, l_ctx);
        if (l_s != 1)
        {
                TRC_ERROR("performing BN_mod_exp");
                if (l_secret) { BN_free(l_secret);}
                if (l_ya) { BN_free(l_ya);}
                if (l_buf) { free(l_buf); l_buf = nullptr; }
                if (l_p) { BN_free(l_p);}
                if (l_xb) { BN_free(l_xb);}
                if (l_ctx) { BN_CTX_free(l_ctx); l_ctx = nullptr; }
                return NTRNT_STATUS_ERROR;
        }
        // TODO -cleanup
        if (l_ya) { BN_free(l_ya);}
        if (l_buf) { free(l_buf); l_buf = nullptr; }
        if (l_p) { BN_free(l_p);}
        if (l_xb) { BN_free(l_xb);}
        if (l_ctx) { BN_CTX_free(l_ctx); l_ctx = nullptr; }
        l_s = BN_bn2bin(l_secret, m_secret);
        // TODO -check status
        if (l_secret) { BN_free(l_secret);}
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
int32_t phe::recv_yb(nbq& a_in_q)
{
        //NDBG_PRINT("[PHE] recv_yb\n");
        int32_t l_s;
        // -------------------------------------------------
        // get public key
        // -------------------------------------------------
        if (a_in_q.read_avail() < PHE_PUBLIC_KEY_SIZE)
        {
                //TRC_ERROR("Yb < %d bytes (public key size) [avail: %lu]", PHE_PUBLIC_KEY_SIZE, a_in_q.read_avail());
                return NTRNT_STATUS_AGAIN;
        }
        // -------------------------------------------------
        // read in key size
        // -------------------------------------------------
        char* l_buf = nullptr;
        ssize_t l_ss;
        l_buf = (char*)malloc(sizeof(char)*PHE_PUBLIC_KEY_SIZE);
        l_ss = a_in_q.read(l_buf, PHE_PUBLIC_KEY_SIZE);
        UNUSED(l_ss);
        // -------------------------------------------------
        // create bignum
        // -------------------------------------------------
        BIGNUM* const l_yb = BN_bin2bn((const unsigned char*)l_buf, PHE_PUBLIC_KEY_SIZE, nullptr);
        // -------------------------------------------------
        // get secret
        // S = (Yb ^ Xa) mod P
        // -------------------------------------------------
        BIGNUM* const l_p = BN_bin2bn(_g_dhe_prime, sizeof(_g_dhe_prime), nullptr);
        BIGNUM* const l_xa = BN_bin2bn(m_prv_key, sizeof(m_prv_key), nullptr);
        BIGNUM *l_secret = BN_new();
        BN_CTX *l_ctx = BN_CTX_new();
        l_s = BN_mod_exp(l_secret, l_yb, l_xa, l_p, l_ctx);
        if (l_s != 1)
        {
                TRC_ERROR("performing BN_mod_exp");
                if (l_secret) { BN_free(l_secret);}
                if (l_yb) { BN_free(l_yb);}
                if (l_buf) { free(l_buf); l_buf = nullptr; }
                if (l_p) { BN_free(l_p);}
                if (l_xa) { BN_free(l_xa);}
                if (l_ctx) { BN_CTX_free(l_ctx); l_ctx = nullptr; }
                return NTRNT_STATUS_ERROR;
        }
        // TODO -cleanup
        if (l_yb) { BN_free(l_yb);}
        if (l_buf) { free(l_buf); l_buf = nullptr; }
        if (l_p) { BN_free(l_p);}
        if (l_xa) { BN_free(l_xa);}
        if (l_ctx) { BN_CTX_free(l_ctx); l_ctx = nullptr; }
        l_s = BN_bn2bin(l_secret, m_secret);
        // TODO -check status
        if (l_secret) { BN_free(l_secret);}
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
int32_t phe::send_ab(nbq& a_out_q)
{
        //NDBG_PRINT("[PHE] send_ab\n");
        if (!m_skey ||
            !m_skey_len)
        {
                TRC_ERROR("skey == null");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // send:
        // - HASH('req1', S),
        // - HASH('req2', SKEY) xor HASH('req3', S),
        // - ENCRYPT(VC, crypto_provide, len(PadC), PadC, len(IA)),
        // - ENCRYPT(IA)
        //
        // where:
        //   HASH() is SHA1 binary output (20 bytes)
        // -------------------------------------------------
        // -------------------------------------------------
        // HASH('req1', S),
        // -------------------------------------------------
        sha1 l_req1_sha;
        l_req1_sha.update((const uint8_t*)_AB_MSG_STR_REQ1, sizeof(_AB_MSG_STR_REQ1)-1);
        l_req1_sha.update(m_secret, sizeof(m_secret));
        l_req1_sha.finish();
        a_out_q.write((const char*)(l_req1_sha.get_hash()), NTRNT_SHA1_SIZE);
        //NDBG_PRINT("[%sSENDING%s] HASH('req1', S)\n", ANSI_COLOR_BG_GREEN, ANSI_COLOR_OFF);
        // -------------------------------------------------
        // HASH('req2', SKEY) xor HASH('req3', S),
        // -------------------------------------------------
        sha1 l_req2_sha;
        l_req2_sha.update((const uint8_t*)_AB_MSG_STR_REQ2, sizeof(_AB_MSG_STR_REQ2)-1);
        l_req2_sha.update(m_skey, m_skey_len);
        l_req2_sha.finish();
        const uint8_t* l_req2_sha_dat = l_req2_sha.get_hash();
        sha1 l_req3_sha;
        l_req3_sha.update((const uint8_t*)_AB_MSG_STR_REQ3, sizeof(_AB_MSG_STR_REQ3)-1);
        l_req3_sha.update(m_secret, sizeof(m_secret));
        l_req3_sha.finish();
        const uint8_t* l_req3_sha_dat = l_req3_sha.get_hash();
        // xor
        uint8_t l_pc2_xor[NTRNT_SHA1_SIZE];
        for (uint32_t i_c = 0; i_c < NTRNT_SHA1_SIZE; ++i_c)
        {
                l_pc2_xor[i_c] = l_req2_sha_dat[i_c] ^ l_req3_sha_dat[i_c];
        }
        a_out_q.write((const char*)l_pc2_xor, NTRNT_SHA1_SIZE);
        // -------------------------------------------------
        // ENCRYPT(VC, crypto_provide, len(PadC), PadC, len(IA))
        // -------------------------------------------------
        // -------------------------------------------------
        // encrypt init
        // -------------------------------------------------
        // ENCRYPT() is RC4, that uses one of the following
        // keys to send data:
        //   "HASH('keyA', S, SKEY)" if you're A
        //   "HASH('keyB', S, SKEY)" if you're B
        // The first 1024 bytes of the RC4 output are
        // discarded.
        // consecutive calls to ENCRYPT() by one side
        // continue the encryption stream
        // (no reinitialization, no keychange).
        // They are only used to distinguish semantically
        // separate content.
        // -------------------------------------------------
        // -------------------------------------------------
        // generate key
        // -------------------------------------------------
        sha1 l_key_sha;
        l_key_sha.update((const uint8_t*)_PHE_ENCRYPT_KEYA, sizeof(_PHE_ENCRYPT_KEYA)-1);
        l_key_sha.update(m_secret, sizeof(m_secret));
        l_key_sha.update(m_skey, m_skey_len);
        l_key_sha.finish();
        // -------------------------------------------------
        // init encrypt
        // -------------------------------------------------
        m_encrypt = new arc4();
        m_encrypt->init(l_key_sha.get_hash(), NTRNT_SHA1_SIZE);
        m_encrypt->discard(_PHE_ARC4_DISCARD);
        // -------------------------------------------------
        // ENCRYPT(VC, crypto_provide, len(PadC), PadC, len(IA))
        // -------------------------------------------------
        uint32_t l_crypto_provide = PHE_CRYPTO_PROVIDE_RC4 | PHE_CRYPTO_PROVIDE_PLAINTEXT;
        l_crypto_provide = htonl(l_crypto_provide);
        uint16_t l_pad_c_len = 0;
        uint8_t l_pc3[14];
        off_t l_off = 0;
        m_encrypt->process(l_pc3+l_off, _g_dhe_vc, sizeof(_g_dhe_vc));
        l_off += sizeof(_g_dhe_vc);
        m_encrypt->process(l_pc3+l_off, &l_crypto_provide, sizeof(l_crypto_provide));
        l_off += sizeof(l_crypto_provide);
        // sending nothing for pad c -since len hard coded to 0
        m_encrypt->process(l_pc3+l_off, &l_pad_c_len, sizeof(l_pad_c_len));
        l_off += sizeof(l_pad_c_len);
        a_out_q.write((const char*)l_pc3, sizeof(l_pc3));
        // -------------------------------------------------
        // ENCRYPT(IA)
        // -------------------------------------------------
        if (m_ia &&
            m_ia_len)
        {
                // -----------------------------------------
                // append len
                // -----------------------------------------
                uint16_t l_nlen = htons(m_ia_len);
                uint8_t l_len[2];
                m_encrypt->process(l_len, &l_nlen, sizeof(l_nlen));
                a_out_q.write((const char*)l_len, sizeof(l_len));
                // -----------------------------------------
                // append message
                // -----------------------------------------
                uint8_t* l_pc4 = nullptr;
                l_pc4 = (uint8_t*)malloc(sizeof(uint8_t)*m_ia_len);
                m_encrypt->process(l_pc4, m_ia, m_ia_len);
                a_out_q.write((const char*)l_pc4, m_ia_len);
                if (l_pc4) { free(l_pc4); l_pc4 = nullptr; }
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t phe::send_ba(nbq& a_out_q)
{
        //NDBG_PRINT("[PHE] send_ba\n");
        if (!m_skey ||
            !m_skey_len)
        {
                TRC_ERROR("skey == null");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // encrypt init
        // -------------------------------------------------
        // ENCRYPT() is RC4, that uses one of the following
        // keys to send data:
        //   "HASH('keyA', S, SKEY)" if you're A
        //   "HASH('keyB', S, SKEY)" if you're B
        // The first 1024 bytes of the RC4 output are
        // discarded.
        // consecutive calls to ENCRYPT() by one side
        // continue the encryption stream
        // (no reinitialization, no keychange).
        // They are only used to distinguish semantically
        // separate content.
        // -------------------------------------------------
        // -------------------------------------------------
        // generate key
        // -------------------------------------------------
        sha1 l_key_sha;
        l_key_sha.update((const uint8_t*)_PHE_ENCRYPT_KEYB, sizeof(_PHE_ENCRYPT_KEYB)-1);
        l_key_sha.update(m_secret, sizeof(m_secret));
        l_key_sha.update(m_skey, m_skey_len);
        l_key_sha.finish();
        //NDBG_PRINT("[%sPHE%s]: ENCRYPT KEY\n", ANSI_COLOR_BG_MAGENTA, ANSI_COLOR_OFF);
        //NDBG_HEXDUMP(l_key_sha.get_hash(), NTRNT_SHA1_SIZE);
        // -------------------------------------------------
        // init encrypt
        // -------------------------------------------------
        m_encrypt = new arc4();
        m_encrypt->init(l_key_sha.get_hash(), NTRNT_SHA1_SIZE);
        m_encrypt->discard(_PHE_ARC4_DISCARD);
        // -------------------------------------------------
        // B->A: ENCRYPT(VC, crypto_select, len(padD), padD), ENCRYPT2(Payload Stream)
        // -------------------------------------------------
        uint32_t l_crypto_select = PHE_CRYPTO_PROVIDE_RC4;
        uint16_t l_pad_d_len = 0;
        uint8_t l_pc1[14];
        off_t l_off = 0;
        // vc
        m_encrypt->process(l_pc1+l_off, _g_dhe_vc, sizeof(_g_dhe_vc));
        l_off += sizeof(_g_dhe_vc);
        // crypto select
        l_crypto_select = htonl(l_crypto_select);
        m_encrypt->process(l_pc1+l_off, &l_crypto_select, sizeof(l_crypto_select));
        l_off += sizeof(l_crypto_select);
        // pad d len
        l_pad_d_len = htons(l_pad_d_len);
        m_encrypt->process(l_pc1+l_off, &l_pad_d_len, sizeof(l_pad_d_len));
        l_off += sizeof(l_pad_d_len);
        // sending nothing for pad d -since len hard coded to 0
        a_out_q.write((const char*)l_pc1, sizeof(l_pc1));
        // -------------------------------------------------
        // send initial application payload
        // -------------------------------------------------
        if (m_ia &&
            m_ia_len)
        {
                uint8_t* l_ia = (uint8_t*)malloc(sizeof(uint8_t)*m_ia_len);
                m_encrypt->process(l_ia, m_ia, m_ia_len);
                a_out_q.write((const char*)l_ia, m_ia_len);
                if (l_ia) { free(l_ia); l_ia = nullptr; }
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t phe::recv_ab_needle(nbq& a_in_q)
{
        //NDBG_PRINT("[PHE] recv_ab_needle [READ_AVAIL: %lu]\n", a_in_q.read_avail());
        if (a_in_q.read_avail() < NTRNT_SHA1_SIZE)
        {
                //TRC_ERROR("not enough bytes... read more?");
                return NTRNT_STATUS_AGAIN;
        }
        // -------------------------------------------------
        // recv msg
        // -------------------------------------------------
        // - HASH('req1', S),
        // - HASH('req2', SKEY) xor HASH('req3', S),
        // - ENCRYPT(VC, crypto_provide, len(PadC), PadC, len(IA)),
        // - ENCRYPT(IA)
        // -------------------------------------------------
        // -------------------------------------------------
        // calculate sha1
        // -------------------------------------------------
        sha1 l_req1_sha;
        l_req1_sha.update((uint8_t*)(_AB_MSG_STR_REQ1), sizeof(_AB_MSG_STR_REQ1)-1);
        l_req1_sha.update(m_secret, sizeof(m_secret));
        l_req1_sha.finish();
        // -------------------------------------------------
        // find in message
        // -------------------------------------------------
        //NDBG_PRINT("SEARCHING FOR NEEDLE\n");
        //NDBG_HEXDUMP(l_req1_sha.get_hash(), NTRNT_SHA1_SIZE);
        //NDBG_PRINT("HAYSTACK\n");
        //a_in_q.b_display_written();
        while (true)
        {
                if (a_in_q.read_avail() < NTRNT_SHA1_SIZE)
                {
                        TRC_ERROR("not enough bytes... read more?");
                        return NTRNT_STATUS_AGAIN;
                }
                if (a_in_q.starts_with((const char*)l_req1_sha.get_hash(), NTRNT_SHA1_SIZE))
                {
                        a_in_q.discard(NTRNT_SHA1_SIZE);
                        break;
                }
                a_in_q.discard(1);
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t phe::recv_ab(nbq& a_in_q)
{
        //NDBG_PRINT("[PHE] recv_ab\n");
        int32_t l_s;
        ssize_t l_ss;
        // -------------------------------------------------
        // check len
        // -------------------------------------------------
        // - HASH('req2', SKEY) xor HASH('req3', S),
        // - ENCRYPT(VC, crypto_provide, len(PadC), PadC, len(IA)),
        // - ENCRYPT(IA)
        // ...
        // 20 + 8 + 4 + 2
        // -------------------------------------------------
        size_t l_require_len = NTRNT_SHA1_SIZE + sizeof(_g_dhe_vc) + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t);
        if (l_require_len > a_in_q.read_avail())
        {
                //TRC_ERROR("not enough bytes... read more?");
                return NTRNT_STATUS_AGAIN;
        }
        // -------------------------------------------------
        // HASH('req2', SKEY) xor HASH('req3', S),
        // -------------------------------------------------
        sha1 l_req3_sha;
        l_req3_sha.update((uint8_t*)(_AB_MSG_STR_REQ3), sizeof(_AB_MSG_STR_REQ3)-1);
        l_req3_sha.update(m_secret, sizeof(m_secret));
        l_req3_sha.finish();
        const uint8_t* l_req3_sha_dat = l_req3_sha.get_hash();
        uint8_t l_obfx_sha[NTRNT_SHA1_SIZE];
        l_ss = a_in_q.read((char*)l_obfx_sha, NTRNT_SHA1_SIZE);
        UNUSED(l_ss);
        // xor
        uint8_t l_obfx_xor[NTRNT_SHA1_SIZE];
        for (uint32_t i_c = 0; i_c < NTRNT_SHA1_SIZE; ++i_c)
        {
                l_obfx_xor[i_c] = l_obfx_sha[i_c] ^ l_req3_sha_dat[i_c];
        }
        // -------------------------------------------------
        // use req2 sha to look up torrent
        // -------------------------------------------------
        if (!s_phe_select_skey_cb)
        {
                TRC_ERROR("skey selection cb not defined");
                return NTRNT_STATUS_ERROR;
        }
        l_s = s_phe_select_skey_cb(this, m_cb_data, l_obfx_xor, sizeof(l_obfx_xor));
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing s_phe_select_skey_cb");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // if skey still not selected via cb -can't proceed
        // -------------------------------------------------
        if (!m_skey ||
            !m_skey_len)
        {
                TRC_ERROR("skey == null");
                return NTRNT_STATUS_ERROR;
        }
        sha1 l_req2_sha;
        l_req2_sha.update((uint8_t*)(_AB_MSG_STR_REQ2), sizeof(_AB_MSG_STR_REQ2)-1);
        l_req2_sha.update(m_skey, m_skey_len);
        l_req2_sha.finish();
        // -------------------------------------------------
        // TODO -use req2 sha to look up torrent
        // -------------------------------------------------
        // -------------------------------------------------
        // ENCRYPT(VC, crypto_provide, len(PadC), PadC, len(IA)),
        // -------------------------------------------------
        // -------------------------------------------------
        // generate key
        // -------------------------------------------------
        sha1 l_key_sha;
        l_key_sha.update((const uint8_t*)_PHE_ENCRYPT_KEYA, sizeof(_PHE_ENCRYPT_KEYA)-1);
        l_key_sha.update(m_secret, sizeof(m_secret));
        l_key_sha.update(m_skey, m_skey_len);
        l_key_sha.finish();
        // -------------------------------------------------
        // init decrypt
        // -------------------------------------------------
        m_decrypt = new arc4();
        m_decrypt->init(l_key_sha.get_hash(), NTRNT_SHA1_SIZE);
        m_decrypt->discard(_PHE_ARC4_DISCARD);
        // -------------------------------------------------
        // read vc
        // -------------------------------------------------
        uint8_t l_vc[8];
        l_ss = a_in_q.read((char*)l_vc, sizeof(l_vc));
        m_decrypt->process(l_vc, l_vc, sizeof(l_vc));
        //NDBG_PRINT("VC:\n");
        //NDBG_HEXDUMP(&l_vc, sizeof(l_vc));
        // -------------------------------------------------
        // crypto provide
        // -------------------------------------------------
        uint32_t l_tmp32;
        l_ss = a_in_q.read((char*)(&l_tmp32), sizeof(l_tmp32));
        m_decrypt->process(&l_tmp32, &l_tmp32, sizeof(l_tmp32));
        m_crypto_provide = ntohl(l_tmp32);
        //NDBG_PRINT("CRYPTO_PROVIDE: 0x%x\n", m_crypto_provide);
        // -------------------------------------------------
        // pad c len
        // -------------------------------------------------
        uint16_t l_tmp16;
        l_ss = a_in_q.read((char*)(&l_tmp16), sizeof(l_tmp16));
        m_decrypt->process(&l_tmp16, &l_tmp16, sizeof(l_tmp16));
        m_padc_len = htons(l_tmp16);
        //NDBG_PRINT("PAD C LEN: %u\n", m_padc_len);
        // -------------------------------------------------
        // wait for pad c
        // -------------------------------------------------
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t phe::recv_ab_padc(nbq& a_in_q)
{
        //NDBG_PRINT("[PHE] recv_ab_padc\n");
        if (!m_padc_len)
        {
                goto done;
        }
        // -------------------------------------------------
        // check len
        // -------------------------------------------------
        if (a_in_q.read_avail() < m_padc_len)
        {
                //TRC_ERROR("padc len: %u -need more bytes???", m_padc_len);
                return NTRNT_STATUS_AGAIN;
        }
        // -------------------------------------------------
        // discard
        // -------------------------------------------------
        a_in_q.discard(m_padc_len);
        m_decrypt->discard(m_padc_len);
        // -------------------------------------------------
        // wait for ia len
        // -------------------------------------------------
done:
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t phe::recv_ab_ia_len(nbq& a_in_q)
{
        //NDBG_PRINT("[PHE] recv_ab_ia_len\n");
        ssize_t l_ss;
        // -------------------------------------------------
        // check len
        // -------------------------------------------------
        if (a_in_q.read_avail() < sizeof(m_recvd_ia_len))
        {
                //TRC_ERROR("sizeof(recvd_ia_len): %lu -need more bytes???", sizeof(m_recvd_ia_len));
                return NTRNT_STATUS_AGAIN;
        }
        // -------------------------------------------------
        // read ia len
        // -------------------------------------------------
        uint16_t l_tmp16;
        l_ss = a_in_q.read((char*)(&l_tmp16), sizeof(l_tmp16));
        UNUSED(l_ss);
        m_decrypt->process(&l_tmp16, &l_tmp16, sizeof(l_tmp16));
        m_recvd_ia_len = ntohs(l_tmp16);
        // -------------------------------------------------
        // wait for ia len
        // -------------------------------------------------
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t phe::recv_ab_ia(nbq& a_in_q)
{
        ssize_t l_ss;
        //NDBG_PRINT("[PHE] recv_ab_ia: recvd_ia_len: %u\n", m_recvd_ia_len);
        if (!m_recvd_ia_len)
        {
                goto done;
        }
        // -------------------------------------------------
        // check len
        // -------------------------------------------------
        if (a_in_q.read_avail() < m_recvd_ia_len)
        {
                //TRC_ERROR("recvd_ia_len: %u -need more bytes???", m_recvd_ia_len);
                return NTRNT_STATUS_AGAIN;
        }
        // -------------------------------------------------
        // read ia
        // -------------------------------------------------
        m_recvd_ia = (uint8_t*)malloc(sizeof(uint8_t)*m_recvd_ia_len);
        l_ss = a_in_q.read((char*)m_recvd_ia, m_recvd_ia_len);
        UNUSED(l_ss);
        m_decrypt->process(m_recvd_ia, m_recvd_ia, m_recvd_ia_len);
        // -------------------------------------------------
        // send_ab
        // -------------------------------------------------
done:
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t phe::recv_ba_needle(nbq& a_in_q)
{
        //NDBG_PRINT("[PHE] recv_ba_needle\n");
        if (!m_skey ||
            !m_skey_len)
        {
                TRC_ERROR("skey == null");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // pre-check
        // -------------------------------------------------
        if (a_in_q.read_avail() < sizeof(_g_dhe_vc))
        {
                //TRC_ERROR("not enough bytes... read more?");
                return NTRNT_STATUS_AGAIN;
        }
        // -------------------------------------------------
        // B->A: ENCRYPT(VC, crypto_select, len(padD), padD), ENCRYPT2(Payload Stream)
        // -------------------------------------------------
        // -------------------------------------------------
        // generate key
        // -------------------------------------------------
        sha1 l_key_sha;
        l_key_sha.update((const uint8_t*)_PHE_ENCRYPT_KEYB, sizeof(_PHE_ENCRYPT_KEYB)-1);
        l_key_sha.update(m_secret, sizeof(m_secret));
        l_key_sha.update(m_skey, m_skey_len);
        l_key_sha.finish();
        // -------------------------------------------------
        // init arc4
        // -------------------------------------------------
        arc4 l_arc4;
        l_arc4.init(l_key_sha.get_hash(), NTRNT_SHA1_SIZE);
        l_arc4.discard(_PHE_ARC4_DISCARD);
        // -------------------------------------------------
        // create encrypted vc
        // -------------------------------------------------
        uint8_t l_needle[8];
        l_arc4.process(l_needle, _g_dhe_vc, sizeof(_g_dhe_vc));
        // -------------------------------------------------
        // search for verification constant
        // -------------------------------------------------
        //NDBG_PRINT("NEEDLE:\n");
        //NDBG_HEXDUMP(l_needle, sizeof(l_needle));
        size_t l_discarded = 0;
        while (true)
        {
                if (a_in_q.read_avail() < sizeof(l_needle))
                {
                        //TRC_ERROR("not enough bytes... read more? (discarded: %lu)", l_discarded);
                        return NTRNT_STATUS_AGAIN;
                }
                if (a_in_q.starts_with((const char*)l_needle, sizeof(l_needle)))
                {
                        break;
                }
                a_in_q.discard(1);
                ++l_discarded;
        }
        // -------------------------------------------------
        // decrypt init
        // -------------------------------------------------
        m_decrypt = new arc4();
        m_decrypt->init(l_key_sha.get_hash(), NTRNT_SHA1_SIZE);
        m_decrypt->discard(_PHE_ARC4_DISCARD);
        // -------------------------------------------------
        // discard vc
        // -------------------------------------------------
        //NDBG_PRINT("DISCARD NEEDLE: (discarded: %lu)\n", l_discarded);
        a_in_q.discard(sizeof(l_needle));
        m_decrypt->discard(sizeof(l_needle));
        // -------------------------------------------------
        // wait for crypto select
        // -------------------------------------------------
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t phe::recv_ba_crypto_select(nbq& a_in_q)
{
        //NDBG_PRINT("[PHE] recv_ba_crypto_select\n");
        ssize_t l_ss;
        if (!m_skey ||
            !m_skey_len)
        {
                TRC_ERROR("skey == null");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // check len
        // -------------------------------------------------
        if (a_in_q.read_avail() < (sizeof(m_crypto_select)+sizeof(m_padd_len)))
        {
                //TRC_ERROR("crypt_select+pad_d_len: %lu -need more bytes???", (sizeof(m_crypto_select)+sizeof(m_padd_len)));
                return NTRNT_STATUS_AGAIN;
        }
        // -------------------------------------------------
        // crypto select
        // -------------------------------------------------
        uint32_t l_tmp32;
        l_ss = a_in_q.read((char*)(&l_tmp32), sizeof(l_tmp32));
        UNUSED(l_ss);
        m_decrypt->process(&l_tmp32, &l_tmp32, sizeof(l_tmp32));
        m_crypto_select = ntohl(l_tmp32);
        //NDBG_PRINT("CRYPTO_SELECT: 0x%x\n", m_crypto_select);
        if (m_crypto_select != 0x2)
        {
                TRC_ERROR("crypto_select: 0x%x -unsupported", m_crypto_select);
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // pad d len
        // -------------------------------------------------
        uint16_t l_tmp16;
        l_ss = a_in_q.read((char*)(&l_tmp16), sizeof(l_tmp16));
        UNUSED(l_ss);
        m_decrypt->process(&l_tmp16, &l_tmp16, sizeof(l_tmp16));
        m_padd_len = ntohl(l_tmp16);
        //NDBG_PRINT("PAD D LEN: %u\n", m_padd_len);
        // -------------------------------------------------
        // wait for pad d
        // -------------------------------------------------
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t phe::recv_ba_pad_d(nbq& a_in_q)
{
        //NDBG_PRINT("[PHE] recv_ba_pad_d\n");
        if (!m_padd_len)
        {
                goto done;
        }
        // -------------------------------------------------
        // check len
        // -------------------------------------------------
        if (a_in_q.read_avail() < m_padd_len)
        {
                TRC_ERROR("padd len: %u -need more bytes???", m_padd_len);
                return NTRNT_STATUS_AGAIN;
        }
        // -------------------------------------------------
        // discard
        // -------------------------------------------------
        a_in_q.discard(m_padd_len);
        m_decrypt->discard(m_padd_len);
        // -------------------------------------------------
        // connected
        // -------------------------------------------------
        if (!a_in_q.read_avail())
        {
                return NTRNT_STATUS_OK;
        }
done:
        // -------------------------------------------------
        // decrypt remainder
        // -------------------------------------------------
        size_t l_len = a_in_q.read_avail();
        // TODO -assumes block size large enough
        m_decrypt->process(a_in_q.b_read_ptr(), a_in_q.b_read_ptr(), l_len);
        //a_in_q.b_display_written();
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t phe::padded_send(nbq& a_out_q, uint8_t* a_buf, uint32_t a_len)
{
        //NDBG_PRINT("[PHE] padded_send\n");
        // -------------------------------------------------
        // create random pad
        // -------------------------------------------------
        uint8_t l_pad[_PHE_MAX_RAND_PAD];
        uint32_t l_pad_len = (((double)rand())/RAND_MAX) * (_PHE_MAX_RAND_PAD - 1);
        RAND_bytes(l_pad, l_pad_len);
        // -------------------------------------------------
        // write data
        // -------------------------------------------------
        a_out_q.write((const char*)a_buf, a_len);
        a_out_q.write((const char*)l_pad, l_pad_len);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t phe::connect(nbq& a_in_q, nbq& a_out_q)
{
        // -------------------------------------------------
        // run until eagain
        // -------------------------------------------------
        while(true)
        {
        // -------------------------------------------------
        // for state
        // -------------------------------------------------
        int32_t l_s;
        switch(m_state)
        {
        // -------------------------------------------------
        // PHE_STATE_NONE
        // -------------------------------------------------
        case PHE_STATE_NONE:
        {
                l_s = send_ya(a_out_q);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing send_ya");
                        return NTRNT_STATUS_ERROR;
                }
                m_state = PHE_STATE_WAITING_FOR_YB;
                break;
        }
        // -------------------------------------------------
        // PHE_STATE_WAITING_FOR_YA
        // -------------------------------------------------
        case PHE_STATE_WAITING_FOR_YA:
        {
                l_s = recv_ya(a_in_q);
                if (l_s == NTRNT_STATUS_AGAIN)
                {
                        return NTRNT_STATUS_AGAIN;
                }
                else if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing recv_ya");
                        return NTRNT_STATUS_ERROR;
                }
                // -----------------------------------------
                // reset
                // -----------------------------------------
                //a_in_q.reset_write();
                // -----------------------------------------
                // send_yb
                // -----------------------------------------
                l_s = send_yb(a_out_q);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing send_yb");
                        return NTRNT_STATUS_ERROR;
                }
                m_state = PHE_STATE_WAITING_FOR_AB_NEEDLE;
                return NTRNT_STATUS_AGAIN;
        }
        // -------------------------------------------------
        // PHE_STATE_WAITING_FOR_YB
        // -------------------------------------------------
        case PHE_STATE_WAITING_FOR_YB:
        {
                l_s = recv_yb(a_in_q);
                if (l_s == NTRNT_STATUS_AGAIN)
                {
                        return NTRNT_STATUS_AGAIN;
                }
                else if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing recv_yb");
                        return NTRNT_STATUS_ERROR;
                }
                // -----------------------------------------
                // reset
                // -----------------------------------------
                //a_in_q.reset_write();
                // -----------------------------------------
                // send_ab
                // -----------------------------------------
                l_s = send_ab(a_out_q);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing send_ab");
                        return NTRNT_STATUS_ERROR;
                }
                m_state = PHE_STATE_WAITING_FOR_BA_NEEDLE;
                return NTRNT_STATUS_AGAIN;
        }
        // -------------------------------------------------
        // PHE_STATE_WAITING_FOR_AB_NEEDLE
        // -------------------------------------------------
        case PHE_STATE_WAITING_FOR_AB_NEEDLE:
        {
                l_s = recv_ab_needle(a_in_q);
                if (l_s == NTRNT_STATUS_AGAIN)
                {
                        return NTRNT_STATUS_AGAIN;
                }
                else if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing recv_ab");
                        return NTRNT_STATUS_ERROR;
                }
                m_state = PHE_STATE_WAITING_FOR_AB;
                break;
        }
        // -------------------------------------------------
        // PHE_STATE_WAITING_FOR_AB
        // -------------------------------------------------
        case PHE_STATE_WAITING_FOR_AB:
        {
                l_s = recv_ab(a_in_q);
                if (l_s == NTRNT_STATUS_AGAIN)
                {
                        return NTRNT_STATUS_AGAIN;
                }
                else if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing recv_ab");
                        return NTRNT_STATUS_ERROR;
                }
                m_state = PHE_STATE_WAITING_FOR_AB_PADC;
                break;
        }
        // -------------------------------------------------
        // PHE_STATE_WAITING_FOR_AB_NEEDLE
        // -------------------------------------------------
        case PHE_STATE_WAITING_FOR_AB_PADC:
        {
                l_s = recv_ab_padc(a_in_q);
                if (l_s == NTRNT_STATUS_AGAIN)
                {
                        return NTRNT_STATUS_AGAIN;
                }
                else if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing recv_ab");
                        return NTRNT_STATUS_ERROR;
                }
                m_state = PHE_STATE_WAITING_FOR_AB_IA_LEN;
                break;
        }
        // -------------------------------------------------
        // PHE_STATE_WAITING_FOR_AB_IA_LEN
        // -------------------------------------------------
        case PHE_STATE_WAITING_FOR_AB_IA_LEN:
        {
                l_s = recv_ab_ia_len(a_in_q);
                if (l_s == NTRNT_STATUS_AGAIN)
                {
                        return NTRNT_STATUS_AGAIN;
                }
                else if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing recv_ab");
                        return NTRNT_STATUS_ERROR;
                }
                m_state = PHE_STATE_WAITING_FOR_AB_IA;
                break;
        }
        // -------------------------------------------------
        // PHE_STATE_WAITING_FOR_AB_IA
        // -------------------------------------------------
        case PHE_STATE_WAITING_FOR_AB_IA:
        {
                l_s = recv_ab_ia(a_in_q);
                if (l_s == NTRNT_STATUS_AGAIN)
                {
                        return NTRNT_STATUS_AGAIN;
                }
                else if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing recv_ab");
                        return NTRNT_STATUS_ERROR;
                }
                // -----------------------------------------
                // reset
                // -----------------------------------------
                //a_in_q.reset_write();
                // -----------------------------------------
                // send_ba
                // -----------------------------------------
                l_s = send_ba(a_out_q);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing send_ab");
                        return NTRNT_STATUS_ERROR;
                }
                m_state = PHE_STATE_CONNECTED;
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // PHE_STATE_WAITING_FOR_BA_NEEDLE
        // -------------------------------------------------
        case PHE_STATE_WAITING_FOR_BA_NEEDLE:
        {
                l_s = recv_ba_needle(a_in_q);
                if (l_s == NTRNT_STATUS_AGAIN)
                {
                        return NTRNT_STATUS_AGAIN;
                }
                else if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing recv_ba");
                        return NTRNT_STATUS_ERROR;
                }
                m_state = PHE_STATE_WAITING_FOR_BA_CRYPTO_SELECT;
                break;
        }
        // -------------------------------------------------
        // PHE_STATE_WAITING_FOR_BA_CRYPTO_SELECT
        // -------------------------------------------------
        case PHE_STATE_WAITING_FOR_BA_CRYPTO_SELECT:
        {
                l_s = recv_ba_crypto_select(a_in_q);
                if (l_s == NTRNT_STATUS_AGAIN)
                {
                        return NTRNT_STATUS_AGAIN;
                }
                else if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing recv_ba");
                        return NTRNT_STATUS_ERROR;
                }
                m_state = PHE_STATE_WAITING_FOR_BA_PAD_D;
                break;
        }
        // -------------------------------------------------
        // PHE_STATE_WAITING_FOR_BA_PAD_D
        // -------------------------------------------------
        case PHE_STATE_WAITING_FOR_BA_PAD_D:
        {
                l_s = recv_ba_pad_d(a_in_q);
                if (l_s == NTRNT_STATUS_AGAIN)
                {
                        return NTRNT_STATUS_AGAIN;
                }
                else if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing recv_ba");
                        return NTRNT_STATUS_ERROR;
                }
                m_state = PHE_STATE_CONNECTED;
        }
        // -------------------------------------------------
        // PHE_STATE_CONNECTED
        // -------------------------------------------------
        case PHE_STATE_CONNECTED:
        {
                // done
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                TRC_ERROR("unexpected state");
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
int32_t phe::decrypt(uint8_t* a_buf, size_t a_len)
{
        if (m_state != PHE_STATE_CONNECTED)
        {
                return NTRNT_STATUS_ERROR;
        }
        //NDBG_PRINT("[PHE] [DECRYPT] [LEN: %lu]\n", a_len);
        m_decrypt->process((void*)a_buf, a_buf, a_len);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t phe::encrypt(uint8_t* a_buf, uint32_t a_len)
{
        if (m_state != PHE_STATE_CONNECTED)
        {
                return NTRNT_STATUS_ERROR;
        }
        //NDBG_PRINT("[PHE] [ENCRYPT] [LEN: %u]\n", a_len);
        m_encrypt->process(a_buf, a_buf, a_len);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void phe::get_recvd_ia(const uint8_t**ao_buf, size_t& ao_len)
{
        if(!ao_buf) { return;}
        *ao_buf = m_recvd_ia;
        ao_len = m_recvd_ia_len;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void phe::clear_recvd_ia(void)
{
        if (m_recvd_ia)
        {
                free(m_recvd_ia);
                m_recvd_ia = nullptr;
        }
        m_recvd_ia_len = 0;
}
}
