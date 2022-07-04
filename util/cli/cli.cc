//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <string>
#include <stdio.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
// ---------------------------------------------------------
// externa ntrnt includes
// ---------------------------------------------------------
#include "ntrnt/def.h"
#include "ntrnt/ntrnt.h"
// ---------------------------------------------------------
// internal ntrnt includes
// ---------------------------------------------------------
#include "core/torrent.h"
#include "core/session.h"
#include "support/trace.h"
#include "support/ndebug.h"
#include "support/util.h"
#include "lan/upnp.h"
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
ns_ntrnt::session *g_session = NULL;
//! ----------------------------------------------------------------------------
//! \details: sighandler
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static void _sig_handler(int signo)
{
        if(!g_session)
        {
                return;
        }
        if(signo == SIGINT)
        {
                // Kill program
                g_session->stop();
        }
}
//! ----------------------------------------------------------------------------
//! \details: Print the version.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void print_version(FILE* a_stream, int a_exit_code)
{
        // print out the version information
        fprintf(a_stream, "ntrnt BitTorrent client.\n");
        fprintf(a_stream, "    Version: %s\n", NTRNT_VERSION);
        exit(a_exit_code);
}
//! ----------------------------------------------------------------------------
//! \details: Print the command line help.
//! \return:  NA
//! \param:   a_stream FILE *
//! \param:   a_exit_code exit code
//! ----------------------------------------------------------------------------
static void print_usage(FILE* a_stream, int a_exit_code)
{
        fprintf(a_stream, "Usage: ntrnt [options]\n");
        fprintf(a_stream, "Options:\n");
        fprintf(a_stream, "  -h, --help           display this help and exit.\n");
        fprintf(a_stream, "  -v, --version        display the version number and exit.\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Run Options:\n");
        fprintf(a_stream, "  -t, --torrent        torrent file.\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Debug Options:\n");
        fprintf(a_stream, "  -T, --trace         tracing (error/rule/match/all)\n");
        fprintf(a_stream, "  \n");
#ifdef ENABLE_PROFILER
        fprintf(a_stream, "  -G, --gprofile       Google cpu profiler output file\n");
        fprintf(a_stream, "  -H, --hprofile       Google heap profiler output file\n");
        fprintf(a_stream, "\n");
#endif
        exit(a_exit_code);
}
//! ----------------------------------------------------------------------------
//! \details main
//! \return  0 on success
//!          -1 on error
//! \param   argc/argv...
//! ----------------------------------------------------------------------------
int main(int argc, char** argv)
{
        // -------------------------------------------------
        // vars
        // -------------------------------------------------
        ns_ntrnt::trc_log_level_set(ns_ntrnt::TRC_LOG_LEVEL_ALL);
#ifdef ENABLE_PROFILER
        std::string l_gprof_file;
        std::string l_hprof_file;
#endif
        int l_s;
        bool l_input_flag = false;
        std::string l_torrent;
        // -------------------------------------------------
        // Get args...
        // -------------------------------------------------
        char l_opt = '\0';
        std::string l_arg;
        int l_opt_index = 0;
        static struct option l_long_opt[] = {
                { "help",     no_argument,       0, 'h' },
                { "version",  no_argument,       0, 'v' },
                { "torrent",  required_argument, 0, 't' },
                { "trace",    no_argument,       0, 'T' },
#ifdef ENABLE_PROFILER
                { "gprofile", required_argument, 0, 'G' },
                { "hprofile", required_argument, 0, 'H' },
#endif
                // Sentinel
                { 0,          0,                 0,  0  }
        };
        // -------------------------------------------------
        // args...
        // -------------------------------------------------
#ifdef ENABLE_PROFILER
        char l_short_arg_list[] = "hvt:TG:H:";
#else
        char l_short_arg_list[] = "hvt:T";
#endif
        while(((unsigned char)l_opt != 255))
        {
                l_opt = getopt_long_only(argc, argv, l_short_arg_list, l_long_opt, &l_opt_index);
                if (optarg)
                {
                        l_arg = std::string(optarg);
                }
                else
                {
                        l_arg.clear();
                }
                switch (l_opt)
                {
                // -----------------------------------------
                // *****************************************
                // options
                // *****************************************
                // -----------------------------------------
                // -----------------------------------------
                // Help
                // -----------------------------------------
                case 'h':
                {
                        print_usage(stdout, 0);
                        break;
                }
                // -----------------------------------------
                // version
                // -----------------------------------------
                case 'v':
                {
                        print_version(stdout, 0);
                        break;
                }
                // -----------------------------------------
                // torrent file
                // -----------------------------------------
                case 't':
                {
                        l_torrent = optarg;
                        break;
                }
                // -----------------------------------------
                // trace
                // -----------------------------------------
#define ELIF_TRACE_STR(_level) else if (strncasecmp(_level, l_arg.c_str(), sizeof(_level)) == 0)
                case 'T':
                {
                        bool l_trace = false;
                        if (0) {}
                        ELIF_TRACE_STR("error") { ns_ntrnt::trc_log_level_set(ns_ntrnt::TRC_LOG_LEVEL_ERROR); l_trace = true; }
                        ELIF_TRACE_STR("warn") { ns_ntrnt::trc_log_level_set(ns_ntrnt::TRC_LOG_LEVEL_WARN); l_trace = true; }
                        ELIF_TRACE_STR("debug") { ns_ntrnt::trc_log_level_set(ns_ntrnt::TRC_LOG_LEVEL_DEBUG); l_trace = true; }
                        ELIF_TRACE_STR("verbose") { ns_ntrnt::trc_log_level_set(ns_ntrnt::TRC_LOG_LEVEL_VERBOSE); l_trace = true; }
                        ELIF_TRACE_STR("all") { ns_ntrnt::trc_log_level_set(ns_ntrnt::TRC_LOG_LEVEL_ALL); l_trace = true; }
                        else
                        {
                                ns_ntrnt::trc_log_level_set(ns_ntrnt::TRC_LOG_LEVEL_NONE);
                        }
                        if (l_trace)
                        {
                                ns_ntrnt::trc_log_file_open("/dev/stdout");
                        }
                        break;
                }
#ifdef ENABLE_PROFILER
                // -----------------------------------------
                // google cpu profiler output file
                // -----------------------------------------
                case 'G':
                {
                        l_gprof_file = optarg;
                        break;
                }
                // -----------------------------------------
                // google heap profiler output file
                // -----------------------------------------
                case 'H':
                {
                        l_hprof_file = optarg;
                        break;
                }
#endif
                // -----------------------------------------
                // ?
                // -----------------------------------------
                case '?':
                {
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
                default:
                {
                        // ---------------------------------
                        // get the host...
                        // ---------------------------------
                        if (argv[optind])
                        {
                                l_torrent = argv[optind];
                        }
                        if (!l_torrent.empty())
                        {
                                l_input_flag = true;
                        }
                        break;
                }
                }
        }
        // -------------------------------------------------
        // check for file
        // -------------------------------------------------
        if (l_torrent.empty())
        {
                NDBG_ERROR_AT("Error torrent file must be specified.\n");
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // read in file
        // -------------------------------------------------
        ns_ntrnt::torrent l_trnt;
        l_s = l_trnt.init(l_torrent.c_str());
        if (l_s != NTRNT_STATUS_OK)
        {
                NDBG_ERROR_AT("error performing read_file(%s).  Reason: %s.\n",
                                l_torrent.c_str(),
                                ns_ntrnt::get_err_msg());
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // Sigint handler
        // -------------------------------------------------
        if (signal(SIGINT, _sig_handler) == SIG_ERR)
        {
                NDBG_ERROR_AT("error: can't catch SIGINT\n");
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // display
        // -------------------------------------------------
        l_trnt.display();
        // -------------------------------------------------
        // get peer id
        // -------------------------------------------------
        std::string l_peer_id;
        l_peer_id = ns_ntrnt::get_peer_id();
        NDBG_PRINT("peer_id: %s\n", l_peer_id.c_str());
        // -------------------------------------------------
        // session
        // -------------------------------------------------
        ns_ntrnt::session l_ses(l_peer_id, l_trnt);
        g_session = &l_ses;
        // -------------------------------------------------
        // port forwarding setup
        // -------------------------------------------------
        int32_t l_ret = STATUS_OK;
        uint16_t l_port = 51413;
        ns_ntrnt::upnp l_upnp;
        l_s = l_upnp.init();
        if (l_s != NTRNT_STATUS_OK)
        {
                NDBG_ERROR_AT("error performing upnp::init\n");
                l_ret = STATUS_ERROR;
                goto cleanup;
        }
        l_s = l_upnp.add_port_mapping(l_port);
        if (l_s != NTRNT_STATUS_OK)
        {
                NDBG_ERROR_AT("error performing upnp::add_port_mapping (port: %u)\n", l_port);
                l_ret = STATUS_ERROR;
                goto cleanup;
        }
        // -------------------------------------------------
        // run...
        // -------------------------------------------------
        l_s = l_ses.run();
        if (l_s != NTRNT_STATUS_OK)
        {
                NDBG_ERROR_AT("error performing session::run\n");
                l_ret = STATUS_ERROR;
                goto cleanup;
        }
        // -------------------------------------------------
        // cleanup...
        // -------------------------------------------------
cleanup:
        NDBG_PRINT("shutting down\n");
        l_s = l_upnp.delete_port_mapping(l_port);
        if (l_s != NTRNT_STATUS_OK)
        {
                NDBG_ERROR_AT("error performing upnp::delete_port_mapping (port: %u)\n", l_port);
                l_ret = STATUS_ERROR;
                goto cleanup;
        }
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        return l_ret;
}
