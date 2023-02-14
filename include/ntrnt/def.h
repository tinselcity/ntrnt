#ifndef _NTRNT_DEF_H_
#define _NTRNT_DEF_H_
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#ifndef NTRNT_STATUS_OK
  #define NTRNT_STATUS_OK 0
#endif
#ifndef NTRNT_STATUS_ERROR
  #define NTRNT_STATUS_ERROR -1
#endif
#ifndef NTRNT_STATUS_AGAIN
  #define NTRNT_STATUS_AGAIN -2
#endif
#ifndef NTRNT_STATUS_BUSY
  #define NTRNT_STATUS_BUSY -3
#endif
#ifndef NTRNT_STATUS_DONE
  #define NTRNT_STATUS_DONE -4
#endif
#ifndef NTRNT_ERR_LEN
  #define NTRNT_ERR_LEN 4096
#endif
#ifndef CONFIG_DATE_FORMAT
  #if defined(__APPLE__) || defined(__darwin__)
    #define CONFIG_DATE_FORMAT "%Y-%m-%dT%H:%M:%S"
  #else
    #define CONFIG_DATE_FORMAT "%Y-%m-%dT%H:%M:%S%Z"
  #endif
#endif
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define NTRNT_TORRENT_BLOCK_SIZE            (16*1024)
#define NTRNT_DEFAULT_PORT                     51413
#define NTRNT_METADATA_PIECE_SIZE              16384
#define NTRNT_SESSION_UTP_RECV_BUF_SIZE  (1024*1024)
#define NTRNT_SESSION_MAX_CONNS                   40
#define NTRNT_SESSION_PEER_MAX_INFLIGHT          512
#define NTRNT_SESSION_PEER_INFLIGHT_LOW_WATER     32
#define NTRNT_SESSION_PEER_INFLIGHT_EXPIRES_MS 60000
#define NTRNT_SESSION_PEER_MAX_IDLE_S              5
#define NTRNT_SESSION_NUMWANT                     80
#define NTRNT_SESSION_TRACKER_ANNOUNCE_RETRY_S    30
#define NTRNT_SESSION_TRACKER_ANNOUNCE_S        1200
#define NTRNT_SESSION_TRACKER_SCRAPE_RETRY_S      10
#define NTRNT_SESSION_TRACKER_SCRAPE_S            10
// ---------------------------------------------------------
// periodic tasks
// ---------------------------------------------------------
#define NTRNT_SESSION_T_REQUEST_BLOCKS_MS        100
#define NTRNT_SESSION_T_CONNECT_PEERS_MS        1000
#define NTRNT_SESSION_T_CHECK_TIMEOUTS_MS         50
#define NTRNT_SESSION_T_TRACKERS_MS            30000
//! ----------------------------------------------------------------------------
//! strings
//! ----------------------------------------------------------------------------
#define NTRNT_MAGNET_PREFIX "magnet:?"
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#ifndef NTRNT_PERROR
#define NTRNT_PERROR(...) do { \
    TRC_ERROR(__VA_ARGS__); \
    snprintf(g_ntrnt_err_msg, NTRNT_ERR_LEN, __VA_ARGS__); \
} while(0)
#endif
//! ----------------------------------------------------------------------------
//! global extern
//! ----------------------------------------------------------------------------
extern char g_ntrnt_err_msg[NTRNT_ERR_LEN];
#endif
