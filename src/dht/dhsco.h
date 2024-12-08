#ifndef _NTRNT_DHSCO_H
#define _NTRNT_DHSCO_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
// ---------------------------------------------------------
// c++ std
// ---------------------------------------------------------
#include <string>
#include <queue>
#include <vector>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#ifndef DHT_MAX_BLACKLISTED
#define DHT_MAX_BLACKLISTED 10
#endif
//! ----------------------------------------------------------------------------
//! enum
//! ----------------------------------------------------------------------------
typedef enum _dht_event {
  DHT_EVENT_NONE = 0,
  DHT_EVENT_VALUES,
  DHT_EVENT_VALUES6,
  DHT_EVENT_SEARCH_DONE,
  DHT_EVENT_SEARCH_DONE6
} dht_event_t;
//! ----------------------------------------------------------------------------
//! callbacks
//! ----------------------------------------------------------------------------
typedef int32_t (*dhsco_sendto_cb_t)(int, const void*, int, int,
                                     const struct sockaddr*, int);
typedef bool (*dhsco_blacklisted_cb_t)(const struct sockaddr*, int);
typedef void (*dhsco_hash_cb_t)(void*, int, const void*, int, const void*, int,
                                const void*, int);
typedef int (*dhsco_random_bytes_cb_t)(void*, size_t);
typedef void dht_callback_t(void*, dht_event_t, const uint8_t*, const void*,
                            size_t);
//! ----------------------------------------------------------------------------
//! user defined
//! ----------------------------------------------------------------------------
extern dhsco_sendto_cb_t g_dhsco_sendto_cb;
extern dhsco_blacklisted_cb_t g_dhsco_blacklisted_cb;
extern dhsco_hash_cb_t g_dhsco_hash_cb;
extern dhsco_random_bytes_cb_t g_dhsco_random_bytes_cb;
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
typedef struct _bucket bucket_t;
typedef struct _storage storage_t;
typedef struct _search_node search_node_t;
typedef struct _search search_t;
typedef struct _node node_t;
typedef struct sockaddr_storage sas_t;
typedef std::queue<sas_t> sas_queue_t;
typedef std::vector<sas_t> sas_vector_t;
//! ----------------------------------------------------------------------------
//! prototypes
//! ----------------------------------------------------------------------------
class dhsco {
 public:
  // -------------------------------------------------
  // public methods
  // -------------------------------------------------
  dhsco(int a_udp_fd, int a_udp6_fd, const uint8_t* a_id, const uint8_t* a_v);
  ~dhsco();
  // -------------------------------------------------
  // running
  // -------------------------------------------------
  int32_t periodic(const void* a_buf, size_t a_buf_len,
                   const struct sockaddr* a_from, int a_from_len,
                   time_t* a_to_sleep, dht_callback_t* a_cb, void* a_ctx);
  // -------------------------------------------------
  // try identify new node by pinging
  // -------------------------------------------------
  int ping_node(const struct sockaddr* a_sa, int a_sa_len);
  // -------------------------------------------------
  // search dht by id
  // -------------------------------------------------
  int search(const uint8_t* a_id, int a_port, int a_af, dht_callback_t* a_cb,
             void* a_ctx);
  // -------------------------------------------------
  // get current health of the dht
  // -------------------------------------------------
  int status(int a_family, int* a_good, int* a_dubious, int* a_cached,
             int* a_incoming);
  size_t bootstrap_size(void);
  // -------------------------------------------------
  // dequeue bootstrap from loaded state
  // -------------------------------------------------
  int32_t bootstrap_dq(void);
  // -------------------------------------------------
  // display dht state
  // -------------------------------------------------
  void display(void);
  // -------------------------------------------------
  // load/save state
  // -------------------------------------------------
  int32_t load(const std::string& a_file);
  int32_t save(const std::string& a_file);

 private:
  // -------------------------------------------------
  // private methods
  // -------------------------------------------------
  void rotate_secrets(void);
  void expire_buckets(bucket_t* a_bucket);
  void expire_storage(void);
  void expire_searches(dht_callback_t* a_cb, void* a_ctx);
  int upkeep_buckets(int a_family);
  int upkeep_neighborhood(int a_family);
  int send_cached_ping(bucket_t* a_bucket);
  int send_buf(const void* a_buf, size_t a_len, int a_flags,
               const struct sockaddr* a_sa, int a_sa_len);
  int send_ping(const struct sockaddr* a_sa, int a_sa_len, const uint8_t* a_tid,
                int a_tid_len);
  int send_pong(const struct sockaddr* a_sa, int a_sa_len, const uint8_t* a_tid,
                int a_tid_len);
  int send_find_node(const struct sockaddr* a_sa, int a_sa_len,
                     const uint8_t* a_tid, int a_tid_len,
                     const uint8_t* a_target, int a_want, int a_confirm);
  int send_nodes_peers(const struct sockaddr* a_sa, int a_sa_len,
                       const uint8_t* a_tid, int a_tid_len,
                       const uint8_t* nodes, int nodes_len,
                       const uint8_t* nodes6, int nodes6_len, int af,
                       storage_t* st, const uint8_t* token, int token_len);
  int send_announce_peer(const struct sockaddr* a_sa, int a_sa_len,
                         uint8_t* a_tid, int a_tid_len, uint8_t* a_infohash,
                         uint16_t a_port, uint8_t* a_token, int a_token_len,
                         int a_confirm);
  int send_peer_announced(const struct sockaddr* a_sa, int a_sa_len,
                          uint8_t* a_tid, int a_tid_len);
  int send_error(const struct sockaddr* a_sa, int a_sa_len, uint8_t* a_tid,
                 int a_tid_len, int a_code, const char* a_msg);
  int send_get_peers(const struct sockaddr* a_sa, int a_sa_len, uint8_t* a_tid,
                     int a_tid_len, uint8_t* a_infohash, int a_want,
                     int a_confirm);
  int search_send_get_peers(search_t* a_sr, search_node_t* a_n);
  bool node_good(node_t* a_n);
  bool node_blacklisted(const struct sockaddr* a_sa, int a_sa_len);
  search_node_t* insert_search_node(const uint8_t* a_id,
                                    const struct sockaddr* a_sa, int a_sa_len,
                                    search_t* a_sr, int replied, uint8_t* token,
                                    int token_len);
  void insert_search_bucket(bucket_t* a_b, search_t* a_sr);
  bool rate_limit(void);
  void pinged(node_t* a_n, bucket_t* a_b);
  void search_step(search_t* a_sr, dht_callback_t* a_cb, void* a_ctx);
  void add_search_node(const uint8_t* a_id, const struct sockaddr* a_sa,
                       int a_sa_len);
  node_t* new_node(const uint8_t* a_id, const struct sockaddr* a_sa,
                   int a_sa_len, int a_confirm);
  int split_bucket(bucket_t* a_b);
  int split_bucket_helper(bucket_t* a_b, node_t** ao_nodes_return);
  int send_closest_nodes(const struct sockaddr* a_sa, int a_sa_len,
                         const uint8_t* a_tid, int a_tid_len, const uint8_t* id,
                         int want, int af, storage_t* st, const uint8_t* token,
                         int token_len);
  int store(const uint8_t* id, const struct sockaddr* a_sa, uint16_t port);
  void blacklist_node(const uint8_t* a_id, const struct sockaddr* a_sa,
                      int a_sa_len);
  // -------------------------------------------------
  // disallow copy/assign
  // -------------------------------------------------
  dhsco(const dhsco&);
  dhsco& operator=(const dhsco&);
  // -------------------------------------------------
  // private members
  // -------------------------------------------------
  uint8_t m_myid[20];
  bool m_have_v;
  uint8_t m_my_v[9];
  int m_dht_socket;
  int m_dht_socket6;
  bucket_t* m_buckets;
  bucket_t* m_buckets6;
  storage_t* m_storage;
  search_t* m_searches;
  uint32_t m_num_storage;
  uint32_t m_num_searches;
  struct timeval m_now;
  time_t m_bucket_grow_time;
  time_t m_bucket6_grow_time;
  time_t m_confirm_nodes_time;
  time_t m_token_bucket_time;
  int m_token_bucket_tokens;
  uint16_t m_search_id;
  time_t m_search_time;
  uint8_t m_secret[8];
  uint8_t m_old_secret[8];
  time_t m_rotate_secrets_time;
  time_t m_expire_data_time;
  sas_vector_t m_blocklist;
  sas_queue_t m_bootstrap_nodes;
};
}  // namespace ns_ntrnt
#endif
