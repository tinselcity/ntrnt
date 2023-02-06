#ifndef _NTRNT_TLS_UTIL_H
#define _NTRNT_TLS_UTIL_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include <string>
#include <vector>
//! ----------------------------------------------------------------------------
//! ext fwd decl's
//! ----------------------------------------------------------------------------
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct x509_st X509;
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! globals
//! ----------------------------------------------------------------------------
extern __thread char gts_last_tls_error[256];
//! ----------------------------------------------------------------------------
//! prototypes
//! ----------------------------------------------------------------------------
void tls_init(void);
void tls_kill_locks(void);
int32_t tls_cleanup(void);
int32_t get_tls_options_str_val(const std::string a_options_str, long &ao_val);
const char *get_tls_info_cipher_str(SSL *a_ssl);
const char *get_tls_info_protocol_str(int32_t a_version);
int32_t get_tls_info_protocol_num(SSL *a_ssl);
int32_t validate_server_certificate(SSL *a_tls, const char* a_host, bool a_disallow_self_signed);
int tls_cert_verify_callback_allow_self_signed(int ok, X509_STORE_CTX* store);
int tls_cert_verify_callback(int ok, X509_STORE_CTX* store);
bool tls_x509_get_ids(X509* x509, std::vector<std::string>& ids);
} //namespace ns_ntrnt {
#endif
