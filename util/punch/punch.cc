//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <string>
//  --------------------------------------------------------
// stl
//  --------------------------------------------------------
#include <vector>
// ---------------------------------------------------------
// externa ntrnt includes
// ---------------------------------------------------------
#include "ntrnt/def.h"
#include "ntrnt/ntrnt.h"
// ---------------------------------------------------------
// internal ntrnt includes
// ---------------------------------------------------------
#include "lan/upnp.h"
#include "support/ndebug.h"
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
//! \details: Print the version.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void print_version(FILE* a_stream, int a_exit_code) {
  // print out the version information
  fprintf(a_stream, "punch: open port on NAT with libminiupnpc.\n");
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
  fprintf(a_stream, "Usage: punch [options]\n");
  fprintf(a_stream, "Options:\n");
  fprintf(a_stream, "  -h, --help     display this help and exit.\n");
  fprintf(a_stream, "  -V, --version  display the version number and exit.\n");
  fprintf(a_stream, "  -p, --port     port to open (default: 51413).\n");
  fprintf(a_stream, "  -o, --open     open port (default).\n");
  fprintf(a_stream, "  -c, --close    close port (default).\n");
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
  int l_s;
  uint16_t l_port = NTRNT_DEFAULT_PORT;
  bool l_open = true;
  // -------------------------------------------------
  // Get args...
  // -------------------------------------------------
  char l_opt = '\0';
  std::string l_arg;
  int l_opt_index = 0;
  static struct option l_long_opt[] = {{"help", no_argument, 0, 'h'},
                                       {"version", no_argument, 0, 'V'},
                                       {"port", required_argument, 0, 'p'},
                                       {"open", no_argument, 0, 'o'},
                                       {"close", no_argument, 0, 'c'},
                                       // Sentinel
                                       {0, 0, 0, 0}};
  // -------------------------------------------------
  // args...
  // -------------------------------------------------
  char l_short_arg_list[] = "hVp:oc";
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
      case 'V': {
        print_version(stdout, 0);
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
      // open
      // -----------------------------------------
      case 'o': {
        l_open = true;
        break;
      }
      // -----------------------------------------
      // close
      // -----------------------------------------
      case 'c': {
        l_open = false;
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
        fprintf(stderr, "  Exiting.\n");
        return STATUS_ERROR;
      }
      // -----------------------------------------
      // default
      // -----------------------------------------
      default: {
        break;
      }
    }
  }
  // -------------------------------------------------
  // port forwarding setup
  // -------------------------------------------------
  ns_ntrnt::upnp l_upnp;
  l_s = l_upnp.init();
  if (l_s != NTRNT_STATUS_OK) {
    NDBG_ERROR_AT("error performing upnp::init\n");
    return STATUS_ERROR;
  }
  // -------------------------------------------------
  // open
  // -------------------------------------------------
  if (l_open) {
    l_s = l_upnp.add_port_mapping(l_port);
    if (l_s != NTRNT_STATUS_OK) {
      NDBG_ERROR_AT("error performing upnp::add_port_mapping (port: %u)\n",
                    l_port);
      return STATUS_ERROR;
    }
  }
  // -------------------------------------------------
  // close
  // -------------------------------------------------
  else {
    l_s = l_upnp.delete_port_mapping(l_port);
    if (l_s != NTRNT_STATUS_OK) {
      NDBG_ERROR_AT("error performing upnp::delete_port_mapping (port: %u)\n",
                    l_port);
      return STATUS_ERROR;
    }
  }
  // -------------------------------------------------
  // donezo...
  // -------------------------------------------------
  return STATUS_OK;
}
