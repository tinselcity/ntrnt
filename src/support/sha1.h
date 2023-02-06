#ifndef _NTRNT_SHA1_H
#define _NTRNT_SHA1_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stddef.h>
#include <stdint.h>
#include <string>
// ---------------------------------------------------------
// openssl
// ---------------------------------------------------------
#include <openssl/evp.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define NTRNT_SHA1_SIZE 20
#define NTRNT_SHA1_SIZE_HEX 40
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! sha1 hasher
//! ----------------------------------------------------------------------------
class sha1
{
public:
        // -------------------------------------------------
        // constructor
        // -------------------------------------------------
        sha1():
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
        ~sha1()
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
                        for(size_t i = 0; i < NTRNT_SHA1_SIZE; ++i)
                        {
                                m_hash_hex[2 * i + 0] = s_hexchars[(m_hash[i] & 0xf0) >> 4];
                                m_hash_hex[2 * i + 1] = s_hexchars[m_hash[i] & 0x0f];
                        }
                        m_hash_hex[NTRNT_SHA1_SIZE_HEX] = '\0';
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
        sha1(const sha1&);
        sha1& operator=(const sha1&);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        EVP_MD_CTX* m_ctx;
        bool m_finished;
        uint8_t m_hash[NTRNT_SHA1_SIZE];
        char m_hash_hex[NTRNT_SHA1_SIZE_HEX+1];
};
//! ----------------------------------------------------------------------------
//! inline prototypes
//! ----------------------------------------------------------------------------
inline std::string sha1sum(const uint8_t* a_buf, size_t a_len)
{
        std::string l_ret;
        sha1 l_sha;
        l_sha.update(a_buf, a_len);
        l_sha.finish();
        l_ret = l_sha.get_hash_hex();
        return l_ret;
}
}
#endif
