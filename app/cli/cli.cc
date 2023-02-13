//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdio.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <string>
// ---------------------------------------------------------
// externa ntrnt includes
// ---------------------------------------------------------
#include "ntrnt/def.h"
#include "ntrnt/ntrnt.h"
// ---------------------------------------------------------
// internal ntrnt includes
// ---------------------------------------------------------
#include "core/session.h"
#include "support/trace.h"
#include "support/ndebug.h"
#include "support/util.h"
#include "lan/upnp.h"
// ---------------------------------------------------------
// is2
// ---------------------------------------------------------
#ifdef ENABLE_IS2
#include <is2/srvr/srvr.h>
#include <is2/srvr/lsnr.h>
#include <is2/srvr/default_rqst_h.h>
#include <is2/srvr/api_resp.h>
#include <is2/srvr/rqst.h>
#include <is2/srvr/session.h>
#endif
// ---------------------------------------------------------
// google perf
// ---------------------------------------------------------
#ifdef ENABLE_PROFILER
#include <gperftools/profiler.h>
#include <gperftools/heap-profiler.h>
#endif
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
#ifdef ENABLE_IS2
ns_is2::srvr *g_srvr = NULL;
#endif
//! ----------------------------------------------------------------------------
//! \details: display_status
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
#define _T_DISPLAY_STATUS_MS 200
static int32_t _t_display_status(void *a_data)
{
        // -------------------------------------------------
        // have info???
        // -------------------------------------------------
        static bool s_show_info_progress_heading = false;
        static bool s_show_progress_heading = false;
        ns_ntrnt::peer_mgr& l_peer_mgr = g_session->get_peer_mgr();
        ns_ntrnt::info_pickr& l_info_pickr = g_session->get_info_pickr();
        ns_ntrnt::pickr& l_pickr = g_session->get_pickr();
        if (!g_session->get_info_num_pieces())
        {
                if (!s_show_info_progress_heading)
                {
                NDBG_OUTPUT("%sRequesting Metadata Pieces%s\n",
                                ANSI_COLOR_FG_MAGENTA, ANSI_COLOR_OFF);
                NDBG_OUTPUT("+-------------------------+--------------------------------+\n");
                NDBG_OUTPUT("| %sPeers%s (connected/total) | %sPieces%s (requested/recvd/total) |\n",
                                ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF,
                                ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF);
                NDBG_OUTPUT("+-------------------------+--------------------------------+\n");
                s_show_info_progress_heading = true;
                }
                NDBG_OUTPUT("|           %s%6lu%s/%6lu |                    %3lu/%s%3lu%s/%3lu |\r",
                            ANSI_COLOR_FG_YELLOW,
                            l_peer_mgr.get_peer_connected_vec().size(),
                            ANSI_COLOR_OFF,
                            l_peer_mgr.get_peer_vec().size(),
                            l_info_pickr.get_stat_num_pieces_rqstd(),
                            ANSI_COLOR_FG_BLUE,
                            l_info_pickr.get_stat_num_pieces_recvd(),
                            ANSI_COLOR_OFF,
                            l_info_pickr.get_info_buf_pieces_size());
        }
        else
        {
                if (!s_show_progress_heading)
                {
                if (s_show_info_progress_heading)
                {
                NDBG_OUTPUT("|           %s%6lu%s/%6lu |                    %3lu/%s%3lu%s/%3lu |\n",
                            ANSI_COLOR_FG_YELLOW,
                            l_peer_mgr.get_peer_connected_vec().size(),
                            ANSI_COLOR_OFF,
                            l_peer_mgr.get_peer_vec().size(),
                            l_info_pickr.get_stat_num_pieces_rqstd(),
                            ANSI_COLOR_FG_BLUE,
                            l_info_pickr.get_stat_num_pieces_recvd(),
                            ANSI_COLOR_OFF,
                            l_info_pickr.get_info_buf_pieces_size());
                NDBG_OUTPUT("+-------------------------+--------------------------------+\n");
                NDBG_OUTPUT("Received metadata for torrent:\n");
                NDBG_OUTPUT("  %s%s%s\n",
                                ANSI_COLOR_FG_WHITE,
                                l_info_pickr.get_info_name().c_str(),
                                ANSI_COLOR_OFF);
                }
                NDBG_OUTPUT("%sRequesting Pieces%s\n",
                             ANSI_COLOR_FG_CYAN, ANSI_COLOR_OFF);
                NDBG_OUTPUT("+-------------------------+--------------------------+----------------------+\n");
                NDBG_OUTPUT("| %sPeers%s (connected/total) | %sBlocks%s (requested/recvd) | %sPieces%s (recvd/total) |\n",
                            ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF,
                            ANSI_COLOR_FG_MAGENTA, ANSI_COLOR_OFF,
                            ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF);
                NDBG_OUTPUT("+-------------------------+--------------------------+----------------------+\n");
                s_show_progress_heading = true;
                }
                const char* l_recv_chr = ANSI_COLOR_FG_GREEN;
                if (l_pickr.get_pieces().get_count() == l_pickr.get_pieces().get_size())
                {
                        l_recv_chr = ANSI_COLOR_BG_GREEN;
                }
                NDBG_OUTPUT("|           %s%6lu%s/%6lu |        %8lu/%s%8lu%s |    %s%8lu%s/%8lu |\r",
                            ANSI_COLOR_FG_YELLOW,
                            l_peer_mgr.get_peer_connected_vec().size(),
                            ANSI_COLOR_OFF,
                            l_peer_mgr.get_peer_vec().size(),
                            l_pickr.get_stat_num_blocks_rqstd(),
                            ANSI_COLOR_FG_MAGENTA,
                            l_pickr.get_stat_num_blocks_recvd(),
                            ANSI_COLOR_OFF,
                            l_recv_chr,
                            l_pickr.get_pieces().get_count(),
                            ANSI_COLOR_OFF,
                            l_pickr.get_pieces().get_size());
        }
        // -------------------------------------------------
        // fire status
        // -------------------------------------------------
        int32_t l_s;
        void *l_timer = NULL;
        l_s = g_session->add_timer((uint32_t)(_T_DISPLAY_STATUS_MS),
                                   _t_display_status,
                                   (void *)nullptr,
                                   &l_timer);
        UNUSED(l_s);
        UNUSED(l_timer);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! define handler for get
//! ----------------------------------------------------------------------------
#ifdef ENABLE_IS2
class ntrnt_api_handler: public ns_is2::default_rqst_h
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        ntrnt_api_handler(ns_ntrnt::session& a_session):
                default_rqst_h(),
                m_route(),
                m_session(a_session)
        {}
        ns_is2::h_resp_t do_get(ns_is2::session &a_session,
                                ns_is2::rqst &a_rqst,
                                const ns_is2::url_pmap_t &a_url_pmap);
        void set_route(const std::string &a_route) { m_route = a_route;}
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        ns_is2::h_resp_t get_info(ns_is2::session &a_session, ns_is2::rqst &a_rqst);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        std::string m_route;
        ns_ntrnt::session& m_session;

};
//! ----------------------------------------------------------------------------
//! \details: do_get
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
ns_is2::h_resp_t ntrnt_api_handler::do_get(ns_is2::session &a_session,
                                           ns_is2::rqst &a_rqst,
                                           const ns_is2::url_pmap_t &a_url_pmap)
{
        // -------------------------------------------------
        // get path
        // -------------------------------------------------
        std::string l_route = m_route;
        if(m_route[m_route.length() - 1] == '*')
        {
                l_route = m_route.substr(0, m_route.length() - 2);
        }
        std::string l_path;
        l_path.assign(a_rqst.get_url_path().m_data, a_rqst.get_url_path().m_len);
        std::string l_url_path;
        if(!l_route.empty() &&
           (l_path.find(l_route, 0) != std::string::npos))
        {
                size_t l_idx = l_route.length();
                if(l_path[l_idx] == '/')
                {
                        ++l_idx;
                }
                l_url_path = l_path.substr(l_idx, l_path.length() - l_route.length());
        }
        int32_t l_s;
        std::string l_body;
        if (0) {}
#define _ELIF_API(_str) else if(l_url_path == _str)
        // -------------------------------------------------
        // info
        // -------------------------------------------------
        _ELIF_API("info.json")
        {
                l_s = m_session.api_get_info(l_body);
                if (l_s != NTRNT_STATUS_OK)
                {
                        return send_internal_server_error(a_session, a_rqst.m_supports_keep_alives);
                }
        }
        // -------------------------------------------------
        // trackers
        // -------------------------------------------------
        _ELIF_API("trackers.json")
        {
                l_s = m_session.api_get_trackers(l_body);
                if (l_s != NTRNT_STATUS_OK)
                {
                        return send_internal_server_error(a_session, a_rqst.m_supports_keep_alives);
                }
        }
        // -------------------------------------------------
        // trackers
        // -------------------------------------------------
        _ELIF_API("peers.json")
        {
                l_s = m_session.api_get_peers(l_body);
                if (l_s != NTRNT_STATUS_OK)
                {
                        return send_internal_server_error(a_session, a_rqst.m_supports_keep_alives);
                }
        }
        // -------------------------------------------------
        // not found
        // -------------------------------------------------
        else
        {
                return send_not_found(a_session, a_rqst.m_supports_keep_alives);
        }
        // -------------------------------------------------
        // write out
        // -------------------------------------------------
        ns_is2::api_resp &l_api_resp = create_api_resp(a_session);
        l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                   "application/json",
                                   l_body.length(),
                                   a_rqst.m_supports_keep_alives,
                                   a_session.get_server_name());
        l_api_resp.set_header("Access-Control-Allow-Origin", "*");
        l_api_resp.set_body_data(l_body.c_str(), l_body.length());
        queue_api_resp(a_session, l_api_resp);
        return ns_is2::H_RESP_DONE;
}
#endif
//! ----------------------------------------------------------------------------
//! \details: sighandler
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static void _sig_handler(int signo)
{
        if (signo == SIGINT)
        {
#ifdef ENABLE_IS2
                if (g_srvr)
                {
                        g_srvr->stop();
                }
#endif
                // Kill program
                if (g_session)
                {
                        g_session->stop();
                }
                // for display
                NDBG_OUTPUT("\n");
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
        fprintf(a_stream, "  -t, --torrent        torrent file.\n");
        fprintf(a_stream, "  -i, --info-hash      info hash (hex).\n");
        fprintf(a_stream, "  -e, --ext-port       ext-port (default: 51413)\n");
        fprintf(a_stream, "  -d, --no-dht         disable dht.\n");
        fprintf(a_stream, "  -r, --no-trackers    disable tracker announce/scrape\n");
        fprintf(a_stream, "  -g, --geoip-db       geoip-db\n");
#ifdef ENABLE_IS2
        fprintf(a_stream, "  -p, --port           listen on api port\n");
#endif
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Debug Options:\n");
        fprintf(a_stream, "  -D, --display        display torrent+meta-info and exit\n");
        fprintf(a_stream, "  -M, --no-port-map    disable portmapping\n");
        fprintf(a_stream, "  -A, --no-accept      disable accepting inbound connections\n");
        fprintf(a_stream, "  -P, --peer           connect to single peer (disable tracker announce)\n");
        fprintf(a_stream, "  -T, --trace          tracing (none/error/warn/debug/verbose/all) (default: none)\n");
        fprintf(a_stream, "  -E, --error-log      log errors to file <file>\n");
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
        bool l_no_accept = false;
        bool l_display = false;
        bool l_portmap = true;
        bool l_dht = true;
        bool l_trackers = true;
        bool l_trace = false;
        ns_ntrnt::trc_log_level_set(ns_ntrnt::TRC_LOG_LEVEL_NONE);
        uint16_t l_ext_port = NTRNT_DEFAULT_PORT;
#ifdef ENABLE_IS2
        uint16_t l_port = 0;
#endif
#ifdef ENABLE_PROFILER
        std::string l_gprof_file;
        std::string l_hprof_file;
#endif
        int l_s;
        std::string l_geoip_db;
        std::string l_path;
        std::string l_info_hash;
        std::string l_peer;
        std::string l_error_log;
        // -------------------------------------------------
        // Get args...
        // -------------------------------------------------
        char l_opt = '\0';
        std::string l_arg;
        int l_opt_index = 0;
        static struct option l_long_opt[] = {
                { "help",        no_argument,       0, 'h' },
                { "version",     no_argument,       0, 'v' },
                { "torrent",     required_argument, 0, 't' },
                { "info-hash",   required_argument, 0, 'i' },
                { "ext-port",    required_argument, 0, 'e' },
                { "no-dht",      no_argument,       0, 'd' },
                { "no-trackers", no_argument,       0, 'r' },
                { "geoip-db",    required_argument, 0, 'g' },
#ifdef ENABLE_IS2
                { "port",        required_argument, 0, 'p' },
#endif
                { "display",     no_argument,       0, 'D' },
                { "no-port-map", no_argument,       0, 'M' },
                { "no-accept",   no_argument,       0, 'A' },
                { "peer",        required_argument, 0, 'P' },
                { "trace",       required_argument, 0, 'T' },
                { "error-log",   required_argument, 0, 'E' },
#ifdef ENABLE_PROFILER
                { "gprofile",    required_argument, 0, 'G' },
                { "hprofile",    required_argument, 0, 'H' },
#endif
                // Sentinel
                { 0,             0,                 0,  0  }
        };
        // -------------------------------------------------
        // args...
        // -------------------------------------------------
        std::string l_short_arg_list;
        l_short_arg_list += "hvt:i:e:drg:";
#ifdef ENABLE_IS2
        l_short_arg_list += "p:";
#endif
        l_short_arg_list += "DMAP:T:E:";
#ifdef ENABLE_PROFILER
        l_short_arg_list += "G:H:";
#endif
        while(((unsigned char)l_opt != 255))
        {
                l_opt = getopt_long_only(argc, argv, l_short_arg_list.c_str(), l_long_opt, &l_opt_index);
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
                        l_path = optarg;
                        break;
                }
                // -----------------------------------------
                // info hash
                // -----------------------------------------
                case 'i':
                {
                        l_info_hash = optarg;
                        break;
                }
                // -----------------------------------------
                // external port
                // -----------------------------------------
                case 'e':
                {
                        int l_port_val;
                        l_port_val = atoi(optarg);
                        if((l_port_val < 1) ||
                           (l_port_val > 65535))
                        {
                                NDBG_OUTPUT("Error bad port value: %d.\n", l_port_val);
                                print_usage(stdout, STATUS_ERROR);
                        }
                        l_ext_port = (uint16_t)l_port_val;
                        break;
                }
                // -----------------------------------------
                // disable dht
                // -----------------------------------------
                case 'd':
                {
                        l_dht = false;
                        break;
                }
                // -----------------------------------------
                // disable trackers
                // -----------------------------------------
                case 'r':
                {
                        l_trackers = false;
                        break;
                }
                // -----------------------------------------
                // geoip db
                // -----------------------------------------
                case 'g':
                {
                        l_geoip_db = optarg;
                        break;
                }
                // -----------------------------------------
                // display torrent+meta and exit
                // -----------------------------------------
                case 'D':
                {
                        l_display = true;
                        break;
                }
                // -----------------------------------------
                // disable port mapping
                // -----------------------------------------
                case 'M':
                {
                        l_portmap = false;
                        break;
                }
                // -----------------------------------------
                // disable accept
                // -----------------------------------------
                case 'A':
                {
                        l_no_accept = true;
                        break;
                }
                // -----------------------------------------
                // peer
                // -----------------------------------------
                case 'P':
                {
                        l_peer = optarg;
                        break;
                }
                // -----------------------------------------
                // trace
                // -----------------------------------------
#define ELIF_TRACE_STR(_level) else if (strncasecmp(_level, l_arg.c_str(), sizeof(_level)) == 0)
                case 'T':
                {
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
                        break;
                }
                // -----------------------------------------
                // error-log
                // -----------------------------------------
                case 'E':
                {
                        l_error_log = optarg;
                        break;
                }
#ifdef ENABLE_IS2
                // -----------------------------------------
                // port
                // -----------------------------------------
                case 'p':
                {
                        int l_port_val;
                        l_port_val = atoi(optarg);
                        if((l_port_val < 1) ||
                           (l_port_val > 65535))
                        {
                                NDBG_OUTPUT("Error bad port value: %d.\n", l_port_val);
                                print_usage(stdout, STATUS_ERROR);
                        }
                        l_port = (uint16_t)l_port_val;
                        break;
                }
#endif
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
                                l_path = argv[optind];
                        }
                        break;
                }
                }
        }
        // -------------------------------------------------
        // error logging
        // -------------------------------------------------
        if (!l_error_log.empty())
        {
                ns_ntrnt::trc_log_file_open(l_error_log);
        }
        else if (l_trace)
        {
                ns_ntrnt::trc_log_file_open("/dev/stdout");
        }
        // -------------------------------------------------
        // check for file
        // -------------------------------------------------
        if (l_path.empty() &&
            l_info_hash.empty())
        {
                NDBG_ERROR_AT("Error torrent metadata / magnet / info-hash must be specified.\n");
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
        // session
        // -------------------------------------------------
        void *l_timer = NULL;
        ns_ntrnt::upnp l_upnp;
        int32_t l_ret = STATUS_OK;
        ns_ntrnt::session l_ses;
        g_session = &l_ses;
        // -------------------------------------------------
        // port forwarding setup
        // -------------------------------------------------
        if (l_portmap)
        {
                l_s = l_upnp.init();
                if (l_s != NTRNT_STATUS_OK)
                {
                        NDBG_ERROR_AT("error performing upnp::init\n");
                        l_ret = STATUS_ERROR;
                        goto cleanup;
                }
                l_s = l_upnp.add_port_mapping(l_ext_port);
                if (l_s != NTRNT_STATUS_OK)
                {
                        NDBG_ERROR_AT("error performing upnp::add_port_mapping (port: %u)\n", l_ext_port);
                        l_ret = STATUS_ERROR;
                        goto cleanup;
                }
                // -----------------------------------------
                // set ip address if discovered
                // -----------------------------------------
                l_ses.set_ext_ip(l_upnp.get_stat_ext_ip());
                // -----------------------------------------
                // set self address
                // -----------------------------------------
                char l_port_str[16];
                snprintf(l_port_str, 16, "%u", l_ext_port);
                std::string l_address = l_ses.get_ext_ip();
                if (l_address.find(':') != std::string::npos)
                {
                        std::string l_ipv6_address;
                        l_ipv6_address += "[";
                        l_ipv6_address += l_address;
                        l_ipv6_address += "]";
                        l_ipv6_address += ":";
                        l_ipv6_address += l_port_str;
                        l_ses.set_ext_address_v6(l_ipv6_address);
                }
                else
                {
                        l_address += ":";
                        l_address += l_port_str;
                        l_ses.set_ext_address_v4(l_address);
                }
        }
        // -------------------------------------------------
        // settings
        // -------------------------------------------------
        l_ses.set_dht(l_dht);
        l_ses.set_trackers(l_trackers);
        l_ses.set_ext_port(l_ext_port);
        l_ses.set_no_accept(l_no_accept);
        // -------------------------------------------------
        // set dht
        // -------------------------------------------------
        if (!l_geoip_db.empty())
        {
                l_s = l_ses.set_geoip_db(l_geoip_db);
                if (l_s != NTRNT_STATUS_OK)
                {
                        NDBG_ERROR_AT("error performing session::set_geoip_db\n");
                        l_ret = STATUS_ERROR;
                        goto cleanup;
                }
        }
        // -------------------------------------------------
        // peer
        // -------------------------------------------------
        if (!l_peer.empty())
        {
                l_ses.set_peer(l_peer);
        }
        // -------------------------------------------------
        // detect if magnet link
        // -------------------------------------------------
        if (!l_info_hash.empty())
        {
                l_s = l_ses.init_w_hash(l_info_hash);
                if (l_s != NTRNT_STATUS_OK)
                {
                        NDBG_ERROR_AT("error performing session::init_w_hash\n");
                        return STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // detect if magnet link
        // -------------------------------------------------
        else if (l_path.rfind(NTRNT_MAGNET_PREFIX, 0) == 0)
        {
                l_s = l_ses.init_w_magnet(l_path);
                if (l_s != NTRNT_STATUS_OK)
                {
                        NDBG_ERROR_AT("error performing session::init_w_magnet\n");
                        return STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // init as meta info file
        // -------------------------------------------------
        else
        {
                l_s = l_ses.init_w_metainfo(l_path);
                if (l_s != NTRNT_STATUS_OK)
                {
                        NDBG_ERROR_AT("error performing session::init_w_metainfo\n");
                        return STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // display
        // -------------------------------------------------
        if (l_display)
        {
                l_ses.display_info();
                return STATUS_OK;
        }
#ifdef ENABLE_IS2
#define _API_ROUTE "/api/v0.1/*"
        ns_is2::srvr *l_srvr = nullptr;
        ns_is2::lsnr *l_lsnr = nullptr;
        ntrnt_api_handler *l_api_h = nullptr;
        if (l_port)
        {
                l_srvr = new ns_is2::srvr();
                g_srvr = l_srvr;
                l_lsnr = new ns_is2::lsnr(l_port, ns_is2::SCHEME_TCP);
                l_api_h = new ntrnt_api_handler(l_ses);
                l_api_h->set_route(_API_ROUTE);
                l_lsnr->add_route("/api/v0.1/*", l_api_h);
                l_srvr->register_lsnr(l_lsnr);
                // Run in bg w/ threads == 1
                l_srvr->set_num_threads(1);
                l_srvr->run();
        }
#endif
#ifdef ENABLE_PROFILER
        // -------------------------------------------------
        // start profiler(s)
        // -------------------------------------------------
        if(!l_hprof_file.empty())
        {
                HeapProfilerStart(l_hprof_file.c_str());
        }
        if(!l_gprof_file.empty())
        {
                ProfilerStart(l_gprof_file.c_str());
        }
#endif
        // -------------------------------------------------
        // fire status
        // -------------------------------------------------
        l_s = g_session->add_timer((uint32_t)(_T_DISPLAY_STATUS_MS),
                                   _t_display_status,
                                   (void *)nullptr,
                                   &l_timer);
        UNUSED(l_timer);
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
#ifdef ENABLE_PROFILER
        // -------------------------------------------------
        // stop profiler(s)
        // -------------------------------------------------
        if (!l_hprof_file.empty())
        {
                HeapProfilerStop();
        }
        if (!l_gprof_file.empty())
        {
                ProfilerStop();
        }
#endif
        // -------------------------------------------------
        // cleanup...
        // -------------------------------------------------
cleanup:
        if (l_portmap)
        {
                l_s = l_upnp.delete_port_mapping(l_ext_port);
                if (l_s != NTRNT_STATUS_OK)
                {
                        NDBG_ERROR_AT("error performing upnp::delete_port_mapping (port: %u)\n", l_ext_port);
                        l_ret = STATUS_ERROR;
                }
        }
#ifdef ENABLE_IS2
        if (l_port &&
            l_srvr)
        {
                l_srvr->wait_till_stopped();
        }
        if(l_srvr) {delete l_srvr; l_srvr = NULL;}
        if(l_api_h) {delete l_api_h; l_api_h = NULL;}
#endif
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        return l_ret;
}
