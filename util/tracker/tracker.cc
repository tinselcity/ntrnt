//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <string>
// ---------------------------------------------------------
// externa ntrnt includes
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
ns_ntrnt::session* g_session = NULL;
bool g_stopped = false;
//! ----------------------------------------------------------------------------
//! \details: sighandler
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static void _sig_handler(int signo) {
  // Kill program
  if (g_session) {
    g_session->stop();
  }
  g_stopped = true;
}
//! ----------------------------------------------------------------------------
//! \details: Print the version.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void print_version(FILE* a_stream, int a_exit_code) {
  // print out the version information
  fprintf(a_stream, "ntrnt tracker.\n");
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
  fprintf(a_stream, "Usage: announce [options]\n");
  fprintf(a_stream, "Options:\n");
  fprintf(a_stream, "  -h, --help       display this help and exit.\n");
  fprintf(a_stream,
          "  -v, --version    display the version number and exit.\n");
  fprintf(a_stream, "  -i, --info-hash  info hash (20 bytes -hex string).\n");
  fprintf(a_stream, "  -t, --tracker    tracker to send request to.\n");
  fprintf(a_stream, "  -s, --scrape     send scrape (default to announce).\n");
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
  ns_ntrnt::trc_log_level_set(ns_ntrnt::TRC_LOG_LEVEL_ERROR);
  ns_ntrnt::trc_log_file_open("/dev/stdout");
  int l_s;
  std::string l_info_hash;
  std::string l_url;
  bool l_scrape = false;
  // -------------------------------------------------
  // Get args...
  // -------------------------------------------------
  char l_opt = '\0';
  std::string l_arg;
  int l_opt_index = 0;
  static struct option l_long_opt[] = {{"help", no_argument, 0, 'h'},
                                       {"version", no_argument, 0, 'v'},
                                       {"info-hash", required_argument, 0, 'i'},
                                       {"tracker", required_argument, 0, 't'},
                                       {"scrape", no_argument, 0, 's'},
                                       // Sentinel
                                       {0, 0, 0, 0}};
  // -------------------------------------------------
  // args...
  // -------------------------------------------------
  char l_short_arg_list[] = "hvi:t:";
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
      // tracker
      // -----------------------------------------
      case 't': {
        l_url = optarg;
        break;
      }
      // -----------------------------------------
      // scrape
      // -----------------------------------------
      case 's': {
        l_scrape = true;
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
          l_url = argv[optind];
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
  if (l_url.empty()) {
    NDBG_ERROR_AT("Error tracker must be specified.\n");
    return STATUS_ERROR;
  }
  // -------------------------------------------------
  // session
  // -------------------------------------------------
  ns_ntrnt::session l_ses;
  g_session = &l_ses;
  l_s = l_ses.init_w_hash(l_info_hash);
  if (l_s != NTRNT_STATUS_OK) {
    NDBG_ERROR_AT("error performing session init.\n");
    return STATUS_ERROR;
  }
  l_ses.set_stopped(false);
  // -------------------------------------------------
  // init tracker
  // -------------------------------------------------
  ns_ntrnt::tracker* l_t = nullptr;
  l_s =
      ns_ntrnt::init_tracker_w_url(&l_t, l_ses, l_url.c_str(), l_url.length());
  if (l_s != NTRNT_STATUS_OK) {
    NDBG_ERROR_AT("error initializing tracker with announce: %s\n",
                  l_url.c_str());
    return STATUS_ERROR;
  }
  // -------------------------------------------------
  // announce
  // -------------------------------------------------
  //NDBG_PRINT(": announce: %s\n", l_t->str().c_str());
  if (l_scrape) {
    l_s = l_t->scrape();
    if (l_s != NTRNT_STATUS_OK) {
      NDBG_ERROR_AT("performing send announce for: %s\n", l_t->str().c_str());
      return STATUS_ERROR;
    }
  } else {
    l_s = l_t->announce();
    if (l_s != NTRNT_STATUS_OK) {
      NDBG_ERROR_AT("performing send announce for: %s\n", l_t->str().c_str());
      return STATUS_ERROR;
    }
  }
  // -------------------------------------------------
  // run
  // -------------------------------------------------
  while (!g_stopped && (!l_t->m_stat_announce_num && !l_t->m_stat_scrape_num)) {
    // -----------------------------------------
    // run event loop
    // -----------------------------------------
    l_s = l_ses.get_evr_loop()->run();
    if (l_s != NTRNT_STATUS_OK) {
      // TODO log error
    }
  }
  // -------------------------------------------------
  // display output (scrape)
  // -------------------------------------------------
  if (l_scrape) {
    if (!l_t->m_stat_scrape_num) {
      if (l_t) {
        delete l_t;
        l_t = nullptr;
      }
      return NTRNT_STATUS_OK;
    }
    NDBG_OUTPUT("seeders:   %lu\n", l_t->m_stat_last_scrape_num_complete);
    NDBG_OUTPUT("completed: %lu\n", l_t->m_stat_last_scrape_num_downloaded);
    NDBG_OUTPUT("leechers:  %lu\n", l_t->m_stat_last_scrape_num_incomplete);
  }
  // -------------------------------------------------
  // display output (announce)
  // -------------------------------------------------
  else {
    if (!l_t->m_stat_announce_num) {
      if (l_t) {
        delete l_t;
        l_t = nullptr;
      }
      return NTRNT_STATUS_OK;
    }
    ns_ntrnt::peer_mgr& l_pmgr = l_ses.get_peer_mgr();
    std::string l_str;
    l_s = l_pmgr.get_peers_str(l_str);
    if (l_s != NTRNT_STATUS_OK) {
      NDBG_ERROR_AT("performing get_peers_api\n");
      return STATUS_ERROR;
    }
    NDBG_OUTPUT("%s", l_str.c_str());
  }
  // -------------------------------------------------
  // done...
  // -------------------------------------------------
  if (l_t) {
    delete l_t;
    l_t = nullptr;
  }
  return NTRNT_STATUS_OK;
}
