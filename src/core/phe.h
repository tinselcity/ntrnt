#ifndef _NTRNT_PHE_H
#define _NTRNT_PHE_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stddef.h>
#include <stdint.h>
#include <support/nbq.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
// ---------------------------------------------------------
// private key size is preferred to be 160 bits (20 bytes)
// public key size is 768 bits (96 bytes)
// ref: https://wiki.vuze.com/w/Message_Stream_Encryption
// ---------------------------------------------------------
#define PHE_PRIVATE_KEY_SIZE 20
#define PHE_PUBLIC_KEY_SIZE 96
//! ----------------------------------------------------------------------------
//! callbacks
//! ----------------------------------------------------------------------------
typedef int32_t (*phe_select_skey_cb_t)(void* a_ctx, void* a_cb_ctx,
                                        void* a_buf, size_t a_len);
//! ----------------------------------------------------------------------------
//! user defined
//! ----------------------------------------------------------------------------
extern phe_select_skey_cb_t g_phe_select_skey_cb;
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class arc4;
//! ----------------------------------------------------------------------------
//! class phe
//! ----------------------------------------------------------------------------
class phe {
 public:
  // -------------------------------------------------
  // public types
  // -------------------------------------------------
  typedef enum _state {
    PHE_STATE_NONE = 0,
    PHE_STATE_WAITING_FOR_YA,
    PHE_STATE_WAITING_FOR_YB,
    PHE_STATE_WAITING_FOR_AB_NEEDLE,
    PHE_STATE_WAITING_FOR_AB,
    PHE_STATE_WAITING_FOR_AB_PADC,
    PHE_STATE_WAITING_FOR_AB_IA_LEN,
    PHE_STATE_WAITING_FOR_AB_IA,
    PHE_STATE_WAITING_FOR_BA_NEEDLE,
    PHE_STATE_WAITING_FOR_BA_CRYPTO_SELECT,
    PHE_STATE_WAITING_FOR_BA_PAD_D,
    PHE_STATE_CONNECTED
  } state_t;
  // -------------------------------------------------
  // public methods
  // -------------------------------------------------
  phe(void);
  ~phe(void);
  // -------------------------------------------------
  // operations
  // -------------------------------------------------
  int32_t init(void);
  int32_t connect(nbq& a_in_q, nbq& a_out_q);
  int32_t decrypt(uint8_t* a_buf, size_t a_len);
  // like write sans send
  int32_t encrypt(uint8_t* a_buf, uint32_t a_len);
  // -------------------------------------------------
  // set/get
  // -------------------------------------------------
  void set_cb_data(void* a_data) { m_cb_data = a_data; }
  void set_skey(const uint8_t* a_buf, uint16_t a_len);
  void set_ia(const uint8_t* a_buf, uint16_t a_len);
  state_t get_state(void) { return m_state; }
  void get_recvd_ia(const uint8_t** ao_buf, size_t& ao_len);
  void clear_recvd_ia(void);
  void set_state(state_t a_state) { m_state = a_state; }
  // -------------------------------------------------
  // set select key callback
  // -------------------------------------------------
  static phe_select_skey_cb_t s_phe_select_skey_cb;

 private:
  // -------------------------------------------------
  // private methods
  // -------------------------------------------------
  // disallow copy/assign
  phe(const phe&);
  phe& operator=(const phe&);
  int32_t send_ya(nbq& a_out_q);
  int32_t send_yb(nbq& a_out_q);
  int32_t recv_ya(nbq& a_in_q);
  int32_t recv_yb(nbq& a_in_q);
  int32_t recv_ab_needle(nbq& a_in_q);
  int32_t recv_ab(nbq& a_in_q);
  int32_t recv_ab_padc(nbq& a_in_q);
  int32_t recv_ab_ia_len(nbq& a_in_q);
  int32_t recv_ab_ia(nbq& a_in_q);
  int32_t recv_ba_needle(nbq& a_in_q);
  int32_t recv_ba_crypto_select(nbq& a_in_q);
  int32_t recv_ba_pad_d(nbq& a_in_q);
  int32_t send_ab(nbq& a_out_q);
  int32_t send_ba(nbq& a_out_q);
  int32_t padded_send(nbq& a_out_q, uint8_t* a_buf, uint32_t a_len);
  // -------------------------------------------------
  // private members
  // -------------------------------------------------
  state_t m_state;
  uint8_t m_prv_key[PHE_PRIVATE_KEY_SIZE];
  uint8_t m_pub_key[PHE_PUBLIC_KEY_SIZE];
  uint8_t m_secret[PHE_PUBLIC_KEY_SIZE];
  void* m_cb_data;
  uint8_t* m_skey;
  size_t m_skey_len;
  uint32_t m_crypto_provide;
  uint32_t m_crypto_select;
  uint16_t m_padc_len;
  uint16_t m_padd_len;
  uint8_t* m_ia;
  uint16_t m_ia_len;
  uint8_t* m_recvd_ia;
  uint16_t m_recvd_ia_len;
  arc4* m_encrypt;
  arc4* m_decrypt;
};
}  // namespace ns_ntrnt
#endif
