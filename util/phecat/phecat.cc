//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
// ---------------------------------------------------------
// external ntrnt includes
// ---------------------------------------------------------
#include "ntrnt/def.h"
#include "ntrnt/ntrnt.h"
// ---------------------------------------------------------
// internal ntrnt includes
// ---------------------------------------------------------
#include "core/peer.h"
#include "core/peer_mgr.h"
#include "core/session.h"
#include "core/tracker.h"
#include "evr/evr.h"
#include "support/ndebug.h"
#include "support/net_util.h"
#include "support/trace.h"
// ---------------------------------------------------------
// utp
// ---------------------------------------------------------
#include "libutp/utp.h"
// ---------------------------------------------------------
// system
// ---------------------------------------------------------
#include <arpa/inet.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <string>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#ifndef STATUS_OK
#define STATUS_OK 0
#endif
#ifndef STATUS_ERROR
#define STATUS_ERROR -1
#endif
//! ----------------------------------------------------------------------------
//! globals
//! ----------------------------------------------------------------------------
bool g_stopped = false;
ns_ntrnt::evr_loop* g_evr_loop = nullptr;
ns_ntrnt::session* g_session = nullptr;
ns_ntrnt::peer_mgr* g_peer_mgr = nullptr;
ns_ntrnt::peer_map_t g_peer_map;
//! ----------------------------------------------------------------------------
//! \details: sighandler
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static void _sig_handler(int signo) {
  g_stopped = true;
  if (g_evr_loop) {
    int32_t l_s;
    l_s = g_evr_loop->signal();
    if (l_s != NTRNT_STATUS_OK) {
      // TODO ???
    }
  }
}
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                        U T P   C A L L B A C K S
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static uint64 _pm_utp_log(utp_callback_arguments* a_args) {
  // -------------------------------------------------
  // get peer manager
  // -------------------------------------------------
  ns_ntrnt::peer_mgr* l_pm = static_cast<ns_ntrnt::peer_mgr*>(
      utp_context_get_userdata(a_args->context));
  if (!l_pm) {
    TRC_ERROR("peer_mgr == null");
    return 0;
  }
  // TODO unused if trace not enabled???
  // TODO cap length with a_args->len
  NDBG_OUTPUT("[UTP_LOG] %s\n", a_args->buf);
  return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static uint64 _pm_utp_on_accept(utp_callback_arguments* a_args) {
  // -------------------------------------------------
  // get peer manager
  // -------------------------------------------------
  ns_ntrnt::peer_mgr* l_pm = static_cast<ns_ntrnt::peer_mgr*>(
      utp_context_get_userdata(a_args->context));
  if (!l_pm) {
    TRC_ERROR("peer_mgr == null");
    return 0;
  }
  // -------------------------------------------------
  // accept
  // -------------------------------------------------
  int32_t l_s;
  l_s = l_pm->pm_utp_on_accept(a_args->socket);
  if (l_s != NTRNT_STATUS_OK) {
    TRC_ERROR("performing pm_utp_on_accept");
    return 0;
  }
  return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static uint64 _pm_utp_on_sendto(utp_callback_arguments* a_args) {
  // -------------------------------------------------
  // get peer manager
  // -------------------------------------------------
  ns_ntrnt::peer_mgr* l_pm = static_cast<ns_ntrnt::peer_mgr*>(
      utp_context_get_userdata(a_args->context));
  if (!l_pm) {
    TRC_ERROR("peer_mgr == null");
    return 0;
  }
  // -------------------------------------------------
  // sendto
  // -------------------------------------------------
  int32_t l_s;
  l_s = l_pm->pm_utp_sendto(a_args->buf, a_args->len, a_args->address,
                            a_args->address_len);
  if (l_s != NTRNT_STATUS_OK) {
    TRC_ERROR("performing pm_utp_sendto");
    return 0;
  }
  return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static uint64 _pm_utp_on_read(utp_callback_arguments* a_args) {
  // -------------------------------------------------
  // get peer
  // -------------------------------------------------
  ns_ntrnt::peer* l_peer = nullptr;
  if (!a_args->socket) {
    return 0;
  }
  l_peer = static_cast<ns_ntrnt::peer*>(utp_get_userdata(a_args->socket));
  if (!l_peer) {
    return 0;
  }
  // -------------------------------------------------
  // on read
  // -------------------------------------------------
  l_peer->pr_utp_on_read(a_args->buf, a_args->len);
  return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static uint64 _pm_utp_get_read_buffer_size(utp_callback_arguments* a_args) {
  // -------------------------------------------------
  // get peer
  // -------------------------------------------------
  ns_ntrnt::peer* l_peer = nullptr;
  if (!a_args->socket) {
    return 0;
  }
  l_peer = static_cast<ns_ntrnt::peer*>(utp_get_userdata(a_args->socket));
  if (!l_peer) {
    return 0;
  }
  // -------------------------------------------------
  // return sizeof in buffer
  // -------------------------------------------------
  return l_peer->pr_utp_get_read_buffer_size();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static uint64 _pm_utp_on_error(utp_callback_arguments* a_args) {
  // -------------------------------------------------
  // get peer
  // -------------------------------------------------
  ns_ntrnt::peer* l_peer = nullptr;
  if (!a_args->socket) {
    return 0;
  }
  l_peer = static_cast<ns_ntrnt::peer*>(utp_get_userdata(a_args->socket));
  if (!l_peer) {
    return 0;
  }
  // -------------------------------------------------
  // on error
  // -------------------------------------------------
  l_peer->pr_utp_on_error(a_args->error_code);
  return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static uint64 _pm_utp_on_overhead_statistics(utp_callback_arguments* a_args) {
  // -------------------------------------------------
  // get peer
  // -------------------------------------------------
  ns_ntrnt::peer* l_peer = nullptr;
  if (!a_args->socket) {
    return 0;
  }
  l_peer = static_cast<ns_ntrnt::peer*>(utp_get_userdata(a_args->socket));
  if (!l_peer) {
    return 0;
  }
  // -------------------------------------------------
  // on overhead stats
  // -------------------------------------------------
  l_peer->pr_utp_on_overhead_statistics(a_args->send, a_args->len);
  return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static uint64 _pm_utp_on_state_change(utp_callback_arguments* a_args) {
  // -------------------------------------------------
  // get peer
  // -------------------------------------------------
  ns_ntrnt::peer* l_peer = nullptr;
  if (!a_args->socket) {
    return 0;
  }
  l_peer = static_cast<ns_ntrnt::peer*>(utp_get_userdata(a_args->socket));
  if (!l_peer) {
    return 0;
  }
  // -------------------------------------------------
  // on state change
  // -------------------------------------------------
  l_peer->pr_utp_on_state_change(a_args->state);
  return 0;
}
//! ----------------------------------------------------------------------------
//! \details: Print the version.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void print_version(FILE* a_stream, int a_exit_code) {
  // print out the version information
  fprintf(a_stream, "ntrnt phecat.\n");
  fprintf(a_stream, "    Version: %s\n", NTRNT_VERSION);
  exit(a_exit_code);
}
//! ----------------------------------------------------------------------------
//! \details: Print the command line help.
//! \return:  NA
//! \param:   a_stream FILE *
//! \param:   a_exit_code exit code
//! ----------------------------------------------------------------------------
static void print_usage(FILE* a_stream, int a_exit_code) {
  fprintf(a_stream, "Usage: phecat [options]\n");
  fprintf(a_stream, "Options:\n");
  fprintf(a_stream, "  -h, --help           display this help and exit.\n");
  fprintf(a_stream,
          "  -v, --version        display the version number and exit.\n");
  fprintf(a_stream,
          "  -i, --info-hash      info hash (20 bytes -hex string).\n");
  fprintf(a_stream,
          "  -c, --connect        peer address+port ie 127.0.0.1:51413\n");
  fprintf(a_stream, "  -l, --listen         listen\n");
  fprintf(a_stream, "  -p, --port           listen port\n");
  fprintf(a_stream, "  \n");
  exit(a_exit_code);
}
//! ----------------------------------------------------------------------------
//! \details main
//! \return  0 on success
//!          -1 on error
//! \param   argc/argv...
//! ----------------------------------------------------------------------------
int main(int argc, char** argv) {
  // -------------------------------------------------
  // vars
  // -------------------------------------------------
  ns_ntrnt::trc_log_level_set(ns_ntrnt::TRC_LOG_LEVEL_DEBUG);
  ns_ntrnt::trc_log_file_open("/dev/stdout");
  int l_s;
  std::string l_info_hash;
  std::string l_host;
  uint16_t l_port = NTRNT_DEFAULT_PORT;
  bool l_listen = false;
  // -------------------------------------------------
  // Get args...
  // -------------------------------------------------
  char l_opt = '\0';
  std::string l_arg;
  int l_opt_index = 0;
  static struct option l_long_opt[] = {{"help", no_argument, 0, 'h'},
                                       {"version", no_argument, 0, 'v'},
                                       {"info-hash", required_argument, 0, 'i'},
                                       {"connect", required_argument, 0, 'c'},
                                       {"listen", no_argument, 0, 'l'},
                                       {"port", required_argument, 0, 'p'},
                                       // Sentinel
                                       {0, 0, 0, 0}};
  char l_short_arg_list[] = "hvi:c:lp:";
  while (((unsigned char)l_opt != 255)) {
    l_opt = getopt_long_only(argc, argv, l_short_arg_list, l_long_opt,
                             &l_opt_index);
    if (optarg) {
      l_arg = std::string(optarg);
    } else {
      l_arg.clear();
    }
    switch (l_opt) {
      // -----------------------------------------
      // *****************************************
      // options
      // *****************************************
      // -----------------------------------------
      // -----------------------------------------
      // Help
      // -----------------------------------------
      case 'h': {
        print_usage(stdout, 0);
        break;
      }
      // -----------------------------------------
      // version
      // -----------------------------------------
      case 'v': {
        print_version(stdout, 0);
        break;
      }
      // -----------------------------------------
      // info hash
      // -----------------------------------------
      case 'i': {
        l_info_hash = optarg;
        break;
      }
      // -----------------------------------------
      // peer
      // -----------------------------------------
      case 'c': {
        l_host = optarg;
        break;
      }
      // -----------------------------------------
      // listen
      // -----------------------------------------
      case 'l': {
        l_listen = true;
        break;
      }
      // -----------------------------------------
      // port
      // -----------------------------------------
      case 'p': {
        int l_port_val;
        l_port_val = atoi(optarg);
        if ((l_port_val < 1) || (l_port_val > 65535)) {
          NDBG_OUTPUT("Error bad port value: %d.\n", l_port_val);
          print_usage(stdout, STATUS_ERROR);
        }
        l_port = (uint16_t)l_port_val;
        break;
      }
      // -----------------------------------------
      // ?
      // -----------------------------------------
      case '?': {
        // ---------------------------------
        // Required argument was missing
        // '?' is provided when the 3rd arg
        // to getopt_long does not begin with
        //':', and preceeded by an automatic
        // error message.
        // ---------------------------------
        NDBG_ERROR_AT("unrecognized argument.  Exiting.\n");
        return STATUS_ERROR;
      }
      // -----------------------------------------
      // default
      // -----------------------------------------
      default: {
        // ---------------------------------
        // get the host...
        // ---------------------------------
        if (argv[optind]) {
          l_host = argv[optind];
        }
        break;
      }
    }
  }
  // -------------------------------------------------
  // Sigint handler
  // -------------------------------------------------
  if (signal(SIGINT, _sig_handler) == SIG_ERR) {
    NDBG_ERROR_AT("error: can't catch SIGINT\n");
    return STATUS_ERROR;
  }
  // -------------------------------------------------
  // check for info hash
  // -------------------------------------------------
  if (l_info_hash.empty()) {
    NDBG_ERROR_AT("Error info hash must be specified.\n");
    return STATUS_ERROR;
  }
  // -------------------------------------------------
  // check for tracker
  // -------------------------------------------------
  if (!l_listen && l_host.empty()) {
    NDBG_ERROR_AT("Error peer address+port must be specified.\n");
    return STATUS_ERROR;
  }
  // -------------------------------------------------
  // session
  // -------------------------------------------------
  ns_ntrnt::session l_ses;
  g_session = &l_ses;
  l_ses.set_dht(false);
  l_ses.set_ext_port(l_port);
  l_s = l_ses.init_w_hash(l_info_hash);
  if (l_s != NTRNT_STATUS_OK) {
    NDBG_ERROR_AT("error performing session init.\n");
    return STATUS_ERROR;
  }
  // -------------------------------------------------
  // TODO HACK UTP CB
  // -------------------------------------------------
  // -------------------------------------------------
  // utp initialization
  // -------------------------------------------------
  g_peer_mgr = &(l_ses.get_peer_mgr());
  utp_context* l_utp_ctx = g_peer_mgr->get_utp_ctx();
  // set callbacks
  utp_set_callback(l_utp_ctx, UTP_ON_ACCEPT, _pm_utp_on_accept);
  utp_set_callback(l_utp_ctx, UTP_SENDTO, _pm_utp_on_sendto);
  utp_set_callback(l_utp_ctx, UTP_ON_READ, _pm_utp_on_read);
  utp_set_callback(l_utp_ctx, UTP_GET_READ_BUFFER_SIZE,
                   _pm_utp_get_read_buffer_size);
  utp_set_callback(l_utp_ctx, UTP_ON_ERROR, _pm_utp_on_error);
  utp_set_callback(l_utp_ctx, UTP_ON_OVERHEAD_STATISTICS,
                   _pm_utp_on_overhead_statistics);
  utp_set_callback(l_utp_ctx, UTP_ON_STATE_CHANGE, _pm_utp_on_state_change);
  // tracing
//#ifdef UTP_DEBUG_LOGGING
#if 0
        utp_set_callback(m_utp_ctx, UTP_LOG, &_pm_utp_log);
        utp_context_set_option(m_utp_ctx, UTP_LOG_NORMAL, 1);
        utp_context_set_option(m_utp_ctx, UTP_LOG_MTU, 1);
        utp_context_set_option(m_utp_ctx, UTP_LOG_DEBUG, 1);
#else
  UNUSED(_pm_utp_log);
#endif
  // set recv buffer size?
  l_s = utp_context_set_option(l_utp_ctx, UTP_RCVBUF,
                               NTRNT_SESSION_UTP_RECV_BUF_SIZE);
  if (l_s != 0) {
    TRC_ERROR("performing utp_context_set_option");
    return NTRNT_STATUS_ERROR;
  }
  // -------------------------------------------------
  // peer
  // -------------------------------------------------
  ns_ntrnt::peer* l_peer = nullptr;
  if (!l_listen) {
    sockaddr_storage l_sas;
    l_s = ns_ntrnt::str_to_sas(l_host, l_sas);
    if (l_s != NTRNT_STATUS_OK) {
      NDBG_ERROR_AT("error performing str_to_sas.\n");
      return STATUS_ERROR;
    }
    l_peer = new ns_ntrnt::peer(ns_ntrnt::NTRNT_PEER_FROM_SELF, l_ses,
                                l_ses.get_peer_mgr(), l_sas);
    l_s = l_peer->connect();
    if (l_s != NTRNT_STATUS_OK) {
      NDBG_ERROR_AT("error performing connect.\n");
      if (l_peer) {
        delete l_peer;
        l_peer = nullptr;
      }
      return STATUS_ERROR;
    }
  }
  // -------------------------------------------------
  // run
  // -------------------------------------------------
  g_evr_loop = l_ses.get_evr_loop();
  while (!g_stopped) {
    // -----------------------------------------
    // run event loop
    // -----------------------------------------
    l_s = g_evr_loop->run();
    if (l_s != NTRNT_STATUS_OK) {
      // TODO log error
    }
  }
  NDBG_PRINT("done...\n");
  // -------------------------------------------------
  // cleanup
  // -------------------------------------------------
  return NTRNT_STATUS_OK;
}
