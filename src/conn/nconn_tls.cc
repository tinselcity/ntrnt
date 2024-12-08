//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "conn/nconn_tls.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "support/ndebug.h"
#include "support/time_util.h"
#include "support/tls_util.h"
#include "support/trace.h"
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _HURL_EX_DATA_IDX 0
//! ****************************************************************************
//! ************************ A L P N  S U P P O R T ****************************
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ALPN/NPN support borrowed from curl...
//! ----------------------------------------------------------------------------
#define ALPN_HTTP_1_1_LENGTH 8
#define ALPN_HTTP_1_1 "http/1.1"
// Check for OpenSSL 1.0.2 which has ALPN support.
#undef HAS_ALPN
#if OPENSSL_VERSION_NUMBER >= 0x10002000L && !defined(OPENSSL_NO_TLSEXT)
#define HAS_ALPN 1
#endif
// Check for OpenSSL 1.0.1 which has NPN support.
#undef HAS_NPN
#if OPENSSL_VERSION_NUMBER >= 0x10001000L && !defined(OPENSSL_NO_TLSEXT) && \
    !defined(OPENSSL_NO_NEXTPROTONEG)
#define HAS_NPN 1
#endif
//! ****************************************************************************
//! example taken from nghttp2
//! ****************************************************************************
#define HTTP_1_1_ALPN "\x8http/1.1"
#define HTTP_1_1_ALPN_LEN (sizeof(HTTP_1_1_ALPN) - 1)
#define PROTO_ALPN "\x2h2"
#define PROTO_ALPN_LEN (sizeof(PROTO_ALPN) - 1)
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int select_next_protocol(unsigned char** out, unsigned char* outlen,
                                const unsigned char* in, unsigned int inlen,
                                const char* key, unsigned int keylen) {
  unsigned int i;
  for (i = 0; i + keylen <= inlen; i += (unsigned int)(in[i] + 1)) {
    if (memcmp(&in[i], key, keylen) == 0) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
      *out = (unsigned char*)&in[i + 1];
#pragma GCC diagnostic pop
      *outlen = in[i];
      return 0;
    }
  }
  return -1;
}
//! ----------------------------------------------------------------------------
//! \details: NPN TLS extension client callback. We check that server advertised
//!           the HTTP/2 protocol the nghttp2 library supports. If not, exit
//!           the program.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int alpn_select_next_proto_cb(SSL* a_ssl, unsigned char** a_out,
                                     unsigned char* a_outlen,
                                     const unsigned char* a_in,
                                     unsigned int a_inlen, void* a_arg) {
  // get ex data
  nconn* l_nconn = (nconn*)SSL_get_ex_data(a_ssl, _HURL_EX_DATA_IDX);
  if (!l_nconn) {
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
  l_nconn->set_alpn_result((char*)a_in, a_inlen);
#pragma GCC diagnostic pop
  if (select_next_protocol(a_out, a_outlen, a_in, a_inlen, PROTO_ALPN,
                           PROTO_ALPN_LEN) == 0) {
    l_nconn->set_alpn(nconn::ALPN_HTTP_VER_V2);
    return SSL_TLSEXT_ERR_OK;
  } else if (select_next_protocol(a_out, a_outlen, a_in, a_inlen, HTTP_1_1_ALPN,
                                  HTTP_1_1_ALPN_LEN) == 0) {
    l_nconn->set_alpn(nconn::ALPN_HTTP_VER_V1_1);
    return SSL_TLSEXT_ERR_OK;
  }
  return SSL_TLSEXT_ERR_ALERT_FATAL;
}
//! ----------------------------------------------------------------------------
//! \details: Initialize OpenSSL
//! \return:  ctx on success, NULL on failure
//! \param:   TODO
//! ----------------------------------------------------------------------------
SSL_CTX* tls_init_ctx(const std::string& a_cipher_list, long a_options,
                      const std::string& a_ca_file,
                      const std::string& a_ca_path, bool a_server_flag,
                      const std::string& a_tls_key_file,
                      const std::string& a_tls_crt_file, bool a_force_h1) {
  SSL_CTX* l_ctx;
  // TODO Make configurable
  if (a_server_flag) {
    l_ctx = SSL_CTX_new(SSLv23_server_method());
  } else {
    l_ctx = SSL_CTX_new(SSLv23_client_method());
  }
  if (l_ctx == NULL) {
    ERR_print_errors_fp(stderr);
    TRC_ERROR("SSL_CTX_new Error: %s", ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }
  if (!a_cipher_list.empty()) {
    if (!SSL_CTX_set_cipher_list(l_ctx, a_cipher_list.c_str())) {
      TRC_ERROR("cannot set m_cipher list: %s", a_cipher_list.c_str());
      ERR_print_errors_fp(stderr);
      //close_connection(con, nowP);
      return NULL;
    }
  }
  const char* l_ca_file = NULL;
  const char* l_ca_path = NULL;
  if (!a_ca_file.empty()) {
    l_ca_file = a_ca_file.c_str();
  } else if (!a_ca_path.empty()) {
    l_ca_path = a_ca_path.c_str();
  }
  int32_t l_s;
  if (l_ca_file || l_ca_path) {
    l_s = SSL_CTX_load_verify_locations(l_ctx, l_ca_file, l_ca_path);
    if (1 != l_s) {
      ERR_print_errors_fp(stdout);
      TRC_ERROR("performing SSL_CTX_load_verify_locations.  Reason: %s",
                ERR_error_string(ERR_get_error(), NULL));
      SSL_CTX_free(l_ctx);
      return NULL;
    }

    l_s = SSL_CTX_set_default_verify_paths(l_ctx);
    if (1 != l_s) {
      ERR_print_errors_fp(stdout);
      TRC_ERROR("performing SSL_CTX_set_default_verify_paths.  Reason: %s",
                ERR_error_string(ERR_get_error(), NULL));
      SSL_CTX_free(l_ctx);
      return NULL;
    }
  }
  if (a_options) {
    SSL_CTX_set_options(l_ctx, a_options);
  }
  if (!a_tls_crt_file.empty()) {
    // set the local certificate from CertFile
    if (SSL_CTX_use_certificate_chain_file(l_ctx, a_tls_crt_file.c_str()) <=
        0) {
      TRC_ERROR("performing SSL_CTX_use_certificate_file.");
      ERR_print_errors_fp(stdout);
      return NULL;
    }
  }
  if (!a_tls_key_file.empty()) {
    // set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(l_ctx, a_tls_key_file.c_str(),
                                    SSL_FILETYPE_PEM) <= 0) {
      TRC_ERROR("performing SSL_CTX_use_PrivateKey_file.");
      ERR_print_errors_fp(stdout);
      return NULL;
    }
    // verify private key
    if (!SSL_CTX_check_private_key(l_ctx)) {
      TRC_ERROR(
          "performing SSL_CTX_check_private_key. reason: private key does not "
          "match the public certificate.");
      fprintf(stdout, "Private key does not match the public certificate\n");
      return NULL;
    }
  }
  SSL_CTX_set_default_verify_paths(l_ctx);
  // set npn callback
  SSL_CTX_set_next_proto_select_cb(l_ctx, alpn_select_next_proto_cb, NULL);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  // -------------------------------------------------
  // TODO -something more extensible -list list of
  //       protocols...
  // -------------------------------------------------
#define _ALPN_PROTO_ADV "\x2h2\x5h2-16\x5h2-14\x8http/1.1"
#define _ALPN_PROTO_ADV_H1 "\x8http/1.1"
  const char* l_apln_proto_adv = _ALPN_PROTO_ADV;
  if (a_force_h1) {
    l_apln_proto_adv = _ALPN_PROTO_ADV_H1;
  }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
  l_s = SSL_CTX_set_alpn_protos(l_ctx, (unsigned char*)l_apln_proto_adv,
                                strlen(l_apln_proto_adv));
#pragma GCC diagnostic pop
  UNUSED(l_s);
  //TODO -check error
#endif  // OPENSSL_VERSION_NUMBER >= 0x10002000L \
    // ???
  SSL_CTX_set_mode(l_ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(l_ctx, SSL_MODE_RELEASE_BUFFERS);
  return l_ctx;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t show_tls_info(nconn* a_nconn) {
  if (!a_nconn) {
    TRC_ERROR("a_nconn == NULL");
    return NTRNT_STATUS_ERROR;
  }
  SSL* l_tls = nconn_get_SSL(*(a_nconn));
  if (!l_tls) {
    return NTRNT_STATUS_OK;
  }
  char* l_alpn_result;
  uint32_t l_alpn_result_len = 0;
  a_nconn->get_alpn_result(&l_alpn_result, l_alpn_result_len);
  TRC_OUTPUT("%s", ANSI_COLOR_FG_WHITE);
  TRC_OUTPUT(
      "+-----------------------------------------------------------------------"
      "-------+\n");
  TRC_OUTPUT(
      "|                             T L S   A L P N                           "
      "       |\n");
  TRC_OUTPUT(
      "+-----------------------------------------------------------------------"
      "-------+\n");
  TRC_OUTPUT("%s", ANSI_COLOR_OFF);
  mem_display((const uint8_t*)l_alpn_result, l_alpn_result_len);
  X509* l_cert = NULL;
  l_cert = SSL_get_peer_certificate(l_tls);
  if (l_cert == NULL) {
    TRC_ERROR("SSL_get_peer_certificate error.  tls: %p\n", l_tls);
    return NTRNT_STATUS_ERROR;
  }
  TRC_OUTPUT("%s", ANSI_COLOR_FG_MAGENTA);
  //TRC_OUTPUT("+------------------------------------------------------------------------------+\n");
  //TRC_OUTPUT("| *************** T L S   S E R V E R   C E R T I F I C A T E **************** |\n");
  //TRC_OUTPUT("+------------------------------------------------------------------------------+\n");
  //TRC_OUTPUT("%s", ANSI_COLOR_OFF);
  //X509_print_fp(stdout, l_cert);
  //SSL_SESSION *l_tls_session = SSL_get_session(l_tls);
  //TRC_OUTPUT("%s", ANSI_COLOR_FG_YELLOW);
  //TRC_OUTPUT("+------------------------------------------------------------------------------+\n");
  //TRC_OUTPUT("|                      T L S   S E S S I O N   I N F O                         |\n");
  //TRC_OUTPUT("+------------------------------------------------------------------------------+\n");
  //TRC_OUTPUT("%s", ANSI_COLOR_OFF);
  //SSL_SESSION_print_fp(stdout, l_tls_session);
  //int32_t l_protocol_num = get_tls_info_protocol_num(l_tls);
  //std::string l_cipher = get_tls_info_cipher_str(l_tls);
  //std::string l_protocol = get_tls_info_protocol_str(l_protocol_num);
  //printf(" cipher:     %s\n", l_cipher.c_str());
  //printf(" l_protocol: %s\n", l_protocol.c_str());
  return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nconn_tls::init(void) {
  // -------------------------------------------------
  // check ctx
  // -------------------------------------------------
  if (!m_ssl_ctx) {
    NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS, "LABEL[%s]: ctx == NULL",
                m_label.c_str());
    return NC_STATUS_ERROR;
  }
  // -------------------------------------------------
  // init tls
  // -------------------------------------------------
  if (!m_ssl) {
    m_ssl = ::SSL_new(m_ssl_ctx);
    if (!m_ssl) {
      NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS, "LABEL[%s]: tls_ctx == NULL",
                  m_label.c_str());
      return NC_STATUS_ERROR;
    }
  }
  // -------------------------------------------------
  // set fd
  // -------------------------------------------------
  ::SSL_set_fd(m_ssl, m_fd);
  // TODO check return status
  // -------------------------------------------------
  // options
  // -------------------------------------------------
  const long l_tls_options = m_tls_opt_options;
  if (l_tls_options) {
    // clear all options and set specified options
    ::SSL_clear_options(m_ssl, 0x11111111L);
    long l_result = ::SSL_set_options(m_ssl, l_tls_options);
    if (l_tls_options != l_result) {
      // TODO handle error
    }
  }
  // -------------------------------------------------
  // ciphers
  // -------------------------------------------------
  if (!m_tls_opt_cipher_str.empty()) {
    if (1 != ::SSL_set_cipher_list(m_ssl, m_tls_opt_cipher_str.c_str())) {
      NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS,
                  "LABEL[%s]: Failed to set tls cipher list: %s",
                  m_label.c_str(), m_tls_opt_cipher_str.c_str());
      return NC_STATUS_ERROR;
    }
  }
  // -------------------------------------------------
  // Set tls sni extension
  // -------------------------------------------------
  if (m_tls_opt_sni && !m_tls_opt_hostname.empty()) {
    // const_cast to work around SSL's use of arg -this call does not change buffer argument
    if (1 != ::SSL_set_tlsext_host_name(m_ssl, m_tls_opt_hostname.c_str())) {
      NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS,
                  "LABEL[%s]: Failed to set tls hostname: %s", m_label.c_str(),
                  m_tls_opt_hostname.c_str());
      return NC_STATUS_ERROR;
    }
  }
  // -------------------------------------------------
  // Set tls Cert verify callback ...
  // -------------------------------------------------
  if (m_tls_opt_verify) {
    if (m_tls_opt_verify_allow_self_signed) {
      ::SSL_set_verify(m_ssl, SSL_VERIFY_PEER,
                       tls_cert_verify_callback_allow_self_signed);
    } else {
      ::SSL_set_verify(m_ssl, SSL_VERIFY_PEER, tls_cert_verify_callback);
    }
  }
  return NC_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nconn_tls::tls_connect(void) {
  int l_s;
  m_tls_state = TLS_STATE_TLS_CONNECTING;
  l_s = SSL_connect(m_ssl);
  if (l_s <= 0) {
    int l_te = 0;
    l_te = SSL_get_error(m_ssl, l_s);
    switch (l_te) {
      case SSL_ERROR_SSL: {
        m_last_err = ERR_get_error();
        char* l_buf = gts_last_tls_error;
        l_buf = ERR_error_string(m_last_err, l_buf);
        if (l_buf) {
          NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS,
                      "LABEL[%s]: TLS_ERROR[%ld]: %s.", m_label.c_str(),
                      m_last_err, l_buf);
        } else {
          NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS,
                      "LABEL[%s]: TLS_ERROR[%ld]: OTHER.", m_label.c_str(),
                      m_last_err);
        }
        break;
      }
      case SSL_ERROR_WANT_READ: {
        m_tls_state = TLS_STATE_TLS_CONNECTING_WANT_READ;
        return NC_STATUS_AGAIN;
      }
      case SSL_ERROR_WANT_WRITE: {
        m_tls_state = TLS_STATE_TLS_CONNECTING_WANT_WRITE;
        return NC_STATUS_AGAIN;
      }
      case SSL_ERROR_WANT_X509_LOOKUP: {
        NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS,
                    "LABEL[%s]: SSL_ERROR_WANT_X509_LOOKUP", m_label.c_str());
        m_last_err = ERR_get_error();
        break;
      }
      // look at error stack/return value/errno
      case SSL_ERROR_SYSCALL: {
        m_last_err = ::ERR_get_error();
        if (l_s == 0) {
          NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS,
                      "LABEL[%s]: SSL_ERROR_SYSCALL %ld: %s. An EOF was "
                      "observed that violates the protocol",
                      m_label.c_str(), m_last_err,
                      ERR_error_string(m_last_err, NULL));
        } else if (l_s == -1) {
          NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS,
                      "LABEL[%s]: SSL_ERROR_SYSCALL %ld: %s. %s",
                      m_label.c_str(), m_last_err,
                      ERR_error_string(m_last_err, NULL), strerror(errno));
        }
        break;
      }
      case SSL_ERROR_ZERO_RETURN: {
        NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS,
                    "LABEL[%s]: SSL_ERROR_ZERO_RETURN", m_label.c_str());
        break;
      }
      case SSL_ERROR_WANT_CONNECT: {
        NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS,
                    "LABEL[%s]: SSL_ERROR_WANT_CONNECT", m_label.c_str());
        break;
      }
      case SSL_ERROR_WANT_ACCEPT: {
        NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS,
                    "LABEL[%s]: SSL_ERROR_WANT_ACCEPT", m_label.c_str());
        break;
      }
      default: {
        NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS,
                    "LABEL[%s]: Unknown TLS error", m_label.c_str());
        break;
      }
    }
    //ERR_print_errors_fp(stderr);
    return NC_STATUS_ERROR;
  } else if (l_s == 1) {
    m_tls_state = TLS_STATE_CONNECTED;
  }
  //did_connect = 1;
  return NC_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nconn_tls::tls_accept(void) {
  int l_s;
  m_tls_state = TLS_STATE_TLS_ACCEPTING;
  l_s = SSL_accept(m_ssl);
  if (l_s <= 0) {
    int l_te = ::SSL_get_error(m_ssl, l_s);
    switch (l_te) {
      case SSL_ERROR_SSL: {
        if (gts_last_tls_error[0] != '\0') {
          NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS,
                      "LABEL[%s]: TLS_ERROR %lu: %s. Reason: %s",
                      m_label.c_str(), ::ERR_get_error(),
                      ::ERR_error_string(ERR_get_error(), NULL),
                      gts_last_tls_error);
          // Set back
          gts_last_tls_error[0] = '\0';
        } else {
          NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS,
                      "LABEL[%s]: TLS_ERROR %lu: %s.", m_label.c_str(),
                      ::ERR_get_error(),
                      ::ERR_error_string(::ERR_get_error(), NULL));
        }
        break;
      }
      case SSL_ERROR_WANT_READ: {
        m_tls_state = TLS_STATE_TLS_ACCEPTING_WANT_READ;
        return NC_STATUS_AGAIN;
      }
      case SSL_ERROR_WANT_WRITE: {
        m_tls_state = TLS_STATE_TLS_ACCEPTING_WANT_WRITE;
        return NC_STATUS_AGAIN;
      }
      case SSL_ERROR_WANT_X509_LOOKUP: {
        NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS,
                    "LABEL[%s]: SSL_ERROR_WANT_X509_LOOKUP", m_label.c_str());
        break;
      }
      // look at error stack/return value/errno
      case SSL_ERROR_SYSCALL: {
        if (l_s == 0) {
          NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS,
                      "LABEL[%s]: SSL_ERROR_SYSCALL %lu: %s. An EOF was "
                      "observed that violates the protocol",
                      m_label.c_str(), ::ERR_get_error(),
                      ::ERR_error_string(::ERR_get_error(), NULL));
        } else if (l_s == -1) {
          NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS,
                      "LABEL[%s]: SSL_ERROR_SYSCALL %lu: %s. %s",
                      m_label.c_str(), ::ERR_get_error(),
                      ::ERR_error_string(::ERR_get_error(), NULL),
                      strerror(errno));
        }
        break;
      }
      case SSL_ERROR_ZERO_RETURN: {
        NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS,
                    "LABEL[%s]: SSL_ERROR_ZERO_RETURN", m_label.c_str());
        break;
      }
      case SSL_ERROR_WANT_CONNECT: {
        NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS,
                    "LABEL[%s]: SSL_ERROR_WANT_CONNECT", m_label.c_str());
        break;
      }
      case SSL_ERROR_WANT_ACCEPT: {
        NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS,
                    "LABEL[%s]: SSL_ERROR_WANT_ACCEPT", m_label.c_str());
        break;
      }
    }
    //ERR_print_errors_fp(stderr);
    return NC_STATUS_ERROR;
  } else if (1 == l_s) {
    m_tls_state = TLS_STATE_CONNECTED;
  }
  //did_connect = 1;
  return NC_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nconn_tls::set_opt(uint32_t a_opt, const void* a_buf, uint32_t a_len) {
  int32_t l_s;
  l_s = nconn_tcp::set_opt(a_opt, a_buf, a_len);
  if ((l_s != NC_STATUS_OK) && (l_s != NC_STATUS_UNSUPPORTED)) {
    return NC_STATUS_ERROR;
  }
  if (l_s == NC_STATUS_OK) {
    return NC_STATUS_OK;
  }
  switch (a_opt) {
    case OPT_TLS_CIPHER_STR: {
      m_tls_opt_cipher_str.assign((const char*)a_buf, a_len);
      break;
    }
    case OPT_TLS_OPTIONS: {
      memcpy(&m_tls_opt_options, a_buf, sizeof(long));
      break;
    }
    case OPT_TLS_VERIFY: {
      memcpy(&m_tls_opt_verify, a_buf, sizeof(bool));
      break;
    }
    case OPT_TLS_SNI: {
      memcpy(&m_tls_opt_sni, a_buf, sizeof(bool));
      break;
    }
    case OPT_TLS_HOSTNAME: {
      m_tls_opt_hostname.assign((const char*)a_buf, a_len);
      break;
    }
    case OPT_TLS_VERIFY_ALLOW_SELF_SIGNED: {
      memcpy(&m_tls_opt_verify_allow_self_signed, a_buf, sizeof(bool));
      break;
    }
    case OPT_TLS_VERIFY_NO_HOST_CHECK: {
      memcpy(&m_tls_opt_verify_no_host_check, a_buf, sizeof(bool));
      break;
    }
    case OPT_TLS_CA_FILE: {
      m_tls_opt_ca_file.assign((const char*)a_buf, a_len);
      break;
    }
    case OPT_TLS_CA_PATH: {
      m_tls_opt_ca_path.assign((const char*)a_buf, a_len);
      break;
    }
    case OPT_TLS_TLS_KEY: {
      m_tls_key.assign((const char*)a_buf, a_len);
      break;
    }
    case OPT_TLS_TLS_CRT: {
      m_tls_crt.assign((const char*)a_buf, a_len);
      break;
    }
    case OPT_TLS_CTX: {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
      m_ssl_ctx = (SSL_CTX*)a_buf;
#pragma GCC diagnostic pop
      break;
    }
    default: {
      return NC_STATUS_UNSUPPORTED;
    }
  }
  return NC_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nconn_tls::get_opt(uint32_t a_opt, void** a_buf, uint32_t* a_len) {
  int32_t l_s;
  l_s = nconn_tcp::get_opt(a_opt, a_buf, a_len);
  if ((l_s != NC_STATUS_OK) && (l_s != NC_STATUS_UNSUPPORTED)) {
    return NC_STATUS_ERROR;
  }
  if (l_s == NC_STATUS_OK) {
    return NC_STATUS_OK;
  }
  switch (a_opt) {
    case OPT_TLS_TLS_KEY: {
      // TODO
      break;
    }
    case OPT_TLS_TLS_CRT: {
      // TODO
      break;
    }
    case OPT_TLS_SSL: {
      *a_buf = (void*)m_ssl;
      *a_len = sizeof(m_ssl);
      break;
    }
    case OPT_TLS_SSL_LAST_ERR: {
      *a_buf = (void*)m_last_err;
      *a_len = sizeof(m_last_err);
      break;
    }
    default: {
      return NC_STATUS_ERROR;
    }
  }
  return NC_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nconn_tls::ncset_listening(int32_t a_val) {
  int32_t l_s;
  l_s = nconn_tcp::ncset_listening(a_val);
  if (l_s != NC_STATUS_OK) {
    return NC_STATUS_ERROR;
  }
  m_tls_state = TLS_STATE_LISTENING;
  return NC_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nconn_tls::ncset_listening_nb(int32_t a_val) {
  int32_t l_s;
  l_s = nconn_tcp::ncset_listening_nb(a_val);
  if (l_s != NC_STATUS_OK) {
    return NC_STATUS_ERROR;
  }
  m_tls_state = TLS_STATE_LISTENING;
  return NC_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nconn_tls::ncset_accepting(int a_fd) {
  // -------------------------------------------------
  // set accepting
  // -------------------------------------------------
  int32_t l_s;
  l_s = nconn_tcp::ncset_accepting(a_fd);
  if (l_s != NC_STATUS_OK) {
    return NC_STATUS_ERROR;
  }
  // -------------------------------------------------
  // if accept cb
  // -------------------------------------------------
  if (s_ssl_accept_cb) {
    // -----------------------------------------
    // get sockaddr for accepted socket
    // -----------------------------------------
    sockaddr l_sockaddr;
    socklen_t l_sockaddr_len = sizeof(l_sockaddr);
    l_s = getsockname(a_fd, &l_sockaddr, &l_sockaddr_len);
    if (l_s == -1) {
      TRC_ERROR("performing getsockname: reason: %s", strerror(errno));
      return NC_STATUS_ERROR;
    }
    // -----------------------------------------
    // call cb
    // -----------------------------------------
    SSL* l_ssl = NULL;
    SSL_CTX* l_ctx = NULL;
    l_s = s_ssl_accept_cb(s_ssl_accept_ctx, &l_sockaddr, &l_ssl, &l_ctx);
    if ((l_s == NTRNT_STATUS_OK) && l_ssl && l_ctx) {
      m_ssl = l_ssl;
      m_ssl_ctx = l_ctx;
    }
  }
  // -------------------------------------------------
  // setup tls
  // -------------------------------------------------
  if (!m_ssl) {
    l_s = init();
    if (l_s != NC_STATUS_OK) {
      return NC_STATUS_ERROR;
    }
  }
  // -------------------------------------------------
  // set connection socket to tls state
  // -------------------------------------------------
  ::SSL_set_fd(m_ssl, a_fd);
  // TODO Check return status
  // -------------------------------------------------
  // set ex data
  // -------------------------------------------------
  ::SSL_set_ex_data(m_ssl, _HURL_EX_DATA_IDX, this);
  // TODO Check for Errors
  // -------------------------------------------------
  // set to accepting state
  // -------------------------------------------------
  m_tls_state = TLS_STATE_ACCEPTING;
  // -------------------------------------------------
  // Add to event handler
  // -------------------------------------------------
  if (m_evr_loop) {
    l_s = m_evr_loop->mod_fd(
        m_fd,
        EVR_FILE_ATTR_MASK_READ | EVR_FILE_ATTR_MASK_WRITE |
            EVR_FILE_ATTR_MASK_STATUS_ERROR | EVR_FILE_ATTR_MASK_RD_HUP |
            EVR_FILE_ATTR_MASK_HUP | EVR_FILE_ATTR_MASK_ET,
        &m_evr_fd);
    if (l_s != 0) {
      TRC_ERROR("Couldn't add socket file descriptor");
      return NC_STATUS_ERROR;
    }
  }
  return NC_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nconn_tls::ncset_connected(void) {
  int32_t l_s;
  l_s = nconn_tcp::ncset_connected();
  if (l_s != NC_STATUS_OK) {
    return NC_STATUS_ERROR;
  }
  return NC_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nconn_tls::ncread(char* a_buf, uint32_t a_buf_len) {
  ssize_t l_s;
  int32_t l_bytes_read = 0;
  errno = 0;
  l_s = ::SSL_read(m_ssl, a_buf, a_buf_len);
  TRC_ALL("HOST[%s] tls[%p] READ: %zd bytes. Reason: %s", m_label.c_str(),
          m_ssl, l_s, strerror(errno));
  if (l_s > 0)
    TRC_ALL_MEM((const uint8_t*)a_buf, l_s);
  if (l_s <= 0) {
    int l_te = ::SSL_get_error(m_ssl, l_s);
    if (l_te == SSL_ERROR_WANT_READ) {
      return NC_STATUS_AGAIN;
    } else if (l_te == SSL_ERROR_WANT_WRITE) {
      return NC_STATUS_AGAIN;
    }
  } else {
    l_bytes_read += l_s;
  }
  if (l_s > 0) {
    return l_bytes_read;
  }
  if (l_s == 0) {
    return NC_STATUS_EOF;
  }
  switch (errno) {
    case EAGAIN: {
      return NC_STATUS_AGAIN;
    }
    default: {
      TRC_ERROR("SSL_read failure.");
      return NC_STATUS_ERROR;
    }
  }
  return NC_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nconn_tls::ncwrite(char* a_buf, uint32_t a_buf_len) {
  int l_s;
  errno = 0;
  l_s = ::SSL_write(m_ssl, a_buf, a_buf_len);
  TRC_ALL("HOST[%s] tls[%p] WRITE: %d bytes. Reason: %s", m_label.c_str(),
          m_ssl, l_s, strerror(errno));
  if (l_s > 0) {
    TRC_ALL_MEM((const uint8_t*)a_buf, l_s);
  }
  // -------------------------------------------------
  // write >= 0 bytes successfully
  // -------------------------------------------------
  if (l_s >= 0) {
    return l_s;
  }
  // -------------------------------------------------
  // get error message
  // -------------------------------------------------
  int l_te = ::SSL_get_error(m_ssl, l_s);
  // -------------------------------------------------
  // SSL_ERROR_WANT_READ
  // -------------------------------------------------
  if (l_te == SSL_ERROR_WANT_READ) {
    return NC_STATUS_AGAIN;
  }
  // -------------------------------------------------
  // SSL_ERROR_WANT_WRITE
  // -------------------------------------------------
  else if (l_te == SSL_ERROR_WANT_WRITE) {
    // Add to writeable
    if (m_evr_loop) {
      l_s = m_evr_loop->mod_fd(
          m_fd,
          EVR_FILE_ATTR_MASK_WRITE | EVR_FILE_ATTR_MASK_STATUS_ERROR |
              EVR_FILE_ATTR_MASK_RD_HUP | EVR_FILE_ATTR_MASK_HUP |
              EVR_FILE_ATTR_MASK_ET,
          &m_evr_fd);
      if (l_s != NTRNT_STATUS_OK) {
        NCONN_ERROR(CONN_STATUS_ERROR_INTERNAL,
                    "LABEL[%s]: Error: Couldn't add socket file descriptor",
                    m_label.c_str());
        return NC_STATUS_ERROR;
      }
    }
    return NC_STATUS_AGAIN;
  }
  // -------------------------------------------------
  // unknown error
  // -------------------------------------------------
  NCONN_ERROR(CONN_STATUS_ERROR_SEND, "LABEL[%s]: Error: performing SSL_write.",
              m_label.c_str());
  return NC_STATUS_ERROR;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nconn_tls::ncsetup() {
  int32_t l_s;
  l_s = nconn_tcp::ncsetup();
  if (l_s != NC_STATUS_OK) {
    return NC_STATUS_ERROR;
  }
  l_s = init();
  if (l_s != NC_STATUS_OK) {
    return NC_STATUS_ERROR;
  }
  m_tls_state = TLS_STATE_CONNECTING;
  return NC_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nconn_tls::ncaccept() {
  int l_s;
ncaccept_state_top:
  switch (m_tls_state) {
    // -------------------------------------------------
    // STATE: LISTENING
    // -------------------------------------------------
    case TLS_STATE_LISTENING: {
      l_s = nconn_tcp::ncaccept();
      return l_s;
    }
    // -------------------------------------------------
    // STATE: SSL_ACCEPTING
    // -------------------------------------------------
    case TLS_STATE_ACCEPTING:
    case TLS_STATE_TLS_ACCEPTING:
    case TLS_STATE_TLS_ACCEPTING_WANT_READ:
    case TLS_STATE_TLS_ACCEPTING_WANT_WRITE: {
      int l_s;
      l_s = tls_accept();
      if (l_s == NC_STATUS_AGAIN) {
        if (TLS_STATE_TLS_ACCEPTING_WANT_READ == m_tls_state) {
          if (m_evr_loop) {
            l_s = m_evr_loop->mod_fd(
                m_fd,
                EVR_FILE_ATTR_MASK_READ | EVR_FILE_ATTR_MASK_STATUS_ERROR |
                    EVR_FILE_ATTR_MASK_RD_HUP | EVR_FILE_ATTR_MASK_HUP |
                    EVR_FILE_ATTR_MASK_ET,
                &m_evr_fd);
            if (l_s != NTRNT_STATUS_OK) {
              NCONN_ERROR(
                  CONN_STATUS_ERROR_INTERNAL,
                  "LABEL[%s]: Error: Couldn't add socket file descriptor",
                  m_label.c_str());
              return NC_STATUS_ERROR;
            }
          }
        } else if (TLS_STATE_TLS_ACCEPTING_WANT_WRITE == m_tls_state) {
          if (m_evr_loop) {
            l_s = m_evr_loop->mod_fd(
                m_fd,
                EVR_FILE_ATTR_MASK_WRITE | EVR_FILE_ATTR_MASK_STATUS_ERROR |
                    EVR_FILE_ATTR_MASK_RD_HUP | EVR_FILE_ATTR_MASK_HUP |
                    EVR_FILE_ATTR_MASK_ET,
                &m_evr_fd);
            if (l_s != NTRNT_STATUS_OK) {
              NCONN_ERROR(
                  CONN_STATUS_ERROR_INTERNAL,
                  "LABEL[%s]: Error: Couldn't add socket file descriptor",
                  m_label.c_str());
              return NC_STATUS_ERROR;
            }
          }
        }
        return NC_STATUS_AGAIN;
      } else if (l_s != NC_STATUS_OK) {
        return NC_STATUS_ERROR;
      }
      // Add to event handler
      if (m_evr_loop) {
        l_s = m_evr_loop->mod_fd(
            m_fd,
            EVR_FILE_ATTR_MASK_READ | EVR_FILE_ATTR_MASK_STATUS_ERROR |
                EVR_FILE_ATTR_MASK_RD_HUP | EVR_FILE_ATTR_MASK_HUP |
                EVR_FILE_ATTR_MASK_ET,
            &m_evr_fd);
        if (l_s != NTRNT_STATUS_OK) {
          NCONN_ERROR(CONN_STATUS_ERROR_INTERNAL,
                      "LABEL[%s]: Error: Couldn't add socket file descriptor",
                      m_label.c_str());
          return NC_STATUS_ERROR;
        }
      }
      goto ncaccept_state_top;
    }
    // -------------------------------------------------
    // STATE: CONNECTED
    // -------------------------------------------------
    case TLS_STATE_CONNECTED: {
      //...
      break;
    }
    // -------------------------------------------------
    // STATE: ???
    // -------------------------------------------------
    default: {
      return NC_STATUS_ERROR;
    }
  }
  return NC_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nconn_tls::ncconnect() {
ncconnect_state_top:
  switch (m_tls_state) {
    // -------------------------------------------------
    // STATE: CONNECTING
    // -------------------------------------------------
    case TLS_STATE_CONNECTING: {
      int32_t l_s;
      l_s = nconn_tcp::ncconnect();
      if (l_s == NC_STATUS_ERROR) {
        return NC_STATUS_ERROR;
      }
      if (nconn_tcp::is_connecting()) {
        return NC_STATUS_OK;
      }
      m_tls_state = TLS_STATE_TLS_CONNECTING;
      goto ncconnect_state_top;
    }
    // -------------------------------------------------
    // STATE: tls_connectING
    // -------------------------------------------------
    case TLS_STATE_TLS_CONNECTING:
    case TLS_STATE_TLS_CONNECTING_WANT_READ:
    case TLS_STATE_TLS_CONNECTING_WANT_WRITE: {
      int l_s;
      l_s = tls_connect();
      if (l_s == NC_STATUS_AGAIN) {
        if (TLS_STATE_TLS_CONNECTING_WANT_READ == m_tls_state) {
          // ...
        } else if (TLS_STATE_TLS_CONNECTING_WANT_WRITE == m_tls_state) {
          // ...
        }
        return NC_STATUS_OK;
      } else if (l_s != NC_STATUS_OK) {
        return NC_STATUS_ERROR;
      }
      // ...
      goto ncconnect_state_top;
    }
    // -------------------------------------------------
    // STATE: CONNECTED
    // -------------------------------------------------
    case TLS_STATE_CONNECTED: {
      if (m_tls_opt_verify && !m_tls_opt_verify_no_host_check) {
        int32_t l_s;
        // Do verify
        l_s =
            validate_server_certificate(m_ssl, m_tls_opt_hostname.c_str(),
                                        (!m_tls_opt_verify_allow_self_signed));
        if (l_s != 0) {
          NCONN_ERROR(CONN_STATUS_ERROR_CONNECT_TLS_HOST,
                      "LABEL[%s]: Error: %s", m_label.c_str(),
                      gts_last_tls_error);
          gts_last_tls_error[0] = '\0';
          return NC_STATUS_ERROR;
        }
      }
      // -----------------------------------------
      // get negotiated alpn...
      // -----------------------------------------
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
      const char* l_alpn = NULL;
      uint32_t l_alpn_len;
      SSL_get0_alpn_selected(m_ssl, (const unsigned char**)&l_alpn,
                             &l_alpn_len);
      if ((strncmp("h2", l_alpn, l_alpn_len) == 0) ||
          (strncmp("h2-16", l_alpn, l_alpn_len) == 0) ||
          (strncmp("h2-14", l_alpn, l_alpn_len) == 0)) {
        set_alpn(nconn::ALPN_HTTP_VER_V2);
      } else {
        set_alpn(nconn::ALPN_HTTP_VER_V1_1);
      }
#endif
      break;
    }
    // -------------------------------------------------
    // STATE: ???
    // -------------------------------------------------
    default: {
      TRC_ERROR("State error: %d", m_tls_state);
      return NC_STATUS_ERROR;
    }
  }
  return NC_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nconn_tls::nccleanup() {
  // Shut down connection
  if (m_ssl) {
    SSL_free(m_ssl);
    m_ssl = NULL;
  }
  // -------------------------------------------------
  // Reset all the values
  // TODO Make init function...
  // Set num use back to zero
  // need reset method here?
  // -------------------------------------------------
  m_tls_state = TLS_STATE_NONE;
  // Super
  nconn_tcp::nccleanup();
  return NC_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! nconn_utils
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
SSL* nconn_get_SSL(nconn& a_nconn) {
  SSL* l_ssl;
  uint32_t l_len;
  int l_s;
  l_s = a_nconn.get_opt(nconn_tls::OPT_TLS_SSL, (void**)&l_ssl, &l_len);
  if (l_s != nconn::NC_STATUS_OK) {
    return NULL;
  }
  return l_ssl;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
long nconn_get_last_SSL_err(nconn& a_nconn) {
  long l_err;
  uint32_t l_len;
  int l_s;
  l_s =
      a_nconn.get_opt(nconn_tls::OPT_TLS_SSL_LAST_ERR, (void**)&l_err, &l_len);
  if (l_s != nconn::NC_STATUS_OK) {
    return 0;
  }
  return l_err;
}
}  // namespace ns_ntrnt
