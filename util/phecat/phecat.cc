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
#include "support/ndebug.h"
#include "support/trace.h"
#include "support/net_util.h"
#include "evr/evr.h"
#include "core/session.h"
#include "core/tracker.h"
#include "core/peer_mgr.h"
#include "core/peer.h"
// ---------------------------------------------------------
// utp
// ---------------------------------------------------------
#include "libutp/utp.h"
// ---------------------------------------------------------
// system
// ---------------------------------------------------------
#include <string>
#include <stdio.h>
#include <getopt.h>
#include <signal.h>
#include <arpa/inet.h>
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
static void _sig_handler(int signo)
{
        g_stopped = true;
        if (g_evr_loop)
        {
                int32_t l_s;
                l_s = g_evr_loop->signal();
                if (l_s != NTRNT_STATUS_OK)
                {
                        // TODO ???
                }
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static uint64 _utp_cb(utp_callback_arguments* a_args)
{
        int32_t l_s;
        NDBG_PRINT("[%sUTP%s]: cb type: %d ctx: %p conn: %p\n",
                   ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF,
                   a_args->callback_type,
                   a_args->context,
                   a_args->socket);
        // -------------------------------------------------
        // get session
        // -------------------------------------------------
        ns_ntrnt::session* l_ses = static_cast<ns_ntrnt::session*>(utp_context_get_userdata(a_args->context));
        if (!l_ses)
        {
                TRC_ERROR("session == null");
                return 0;
        }
        // -------------------------------------------------
        // get peer
        // -------------------------------------------------
        ns_ntrnt::peer* l_peer = nullptr;
        if (a_args->socket)
        {
                l_peer = static_cast<ns_ntrnt::peer*>(utp_get_userdata(a_args->socket));
        }
        if (l_peer)
        {
                ns_ntrnt::peer::state_t l_ls = l_peer->get_state();
                // TODO FIX!!!
#if 0
                l_s = l_peer->utp_cb(a_args->socket,
                                     a_args->callback_type,
                                     a_args->state,
                                     a_args->buf,
                                     a_args->len);
#endif
                // EOF
                if (l_s == NTRNT_STATUS_DONE)
                {
                        //shutdown_peer(*l_peer);
                }
                // error
                else if (l_s == NTRNT_STATUS_ERROR)
                {
                        //shutdown_peer(*l_peer);
                }
                // -----------------------------------------
                // check is new active
                // -----------------------------------------
                if (l_ls != ns_ntrnt::peer::STATE_CONNECTED)
                {
                        ns_ntrnt::peer::state_t l_ns = l_peer->get_state();
                        if (l_ns == ns_ntrnt::peer::STATE_CONNECTED)
                        {
                                //set_peer_active(*l_peer);
                        }
                }
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // for msg type...
        // -------------------------------------------------
        switch(a_args->callback_type)
        {
        // -------------------------------------------------
        // UTP_ON_ACCEPT
        // -------------------------------------------------
        case UTP_ON_ACCEPT:
        {
                if (!a_args->socket)
                {
                        TRC_ERROR("a_args->socket == null");
                        return 0;
                }
                sockaddr_storage l_sas;
                socklen_t l_sas_len;
                int32_t l_s;
                l_s = utp_getpeername(a_args->socket, (struct sockaddr*)&l_sas, &l_sas_len);
                if (l_s != 0)
                {
                        TRC_ERROR("performing utp_getpeername");
                        return 0;
                }
                std::string l_host;
                l_host = ns_ntrnt::sas_to_str(l_sas);
                NDBG_PRINT("[%sUTP%s]: [HOST: %s] %sON_ACCEPT%s\n",
                           ANSI_COLOR_FG_MAGENTA, ANSI_COLOR_OFF,
                           l_host.c_str(),
                           ANSI_COLOR_BG_RED, ANSI_COLOR_OFF);
                // -------------------------------------------------
                // find
                // -------------------------------------------------
                auto i_p = g_peer_map.find(l_sas);
                if (i_p != g_peer_map.end())
                {
                        return NTRNT_STATUS_OK;
                }
                // -------------------------------------------------
                // make new
                // -------------------------------------------------
                ns_ntrnt::peer* l_peer = new ns_ntrnt::peer(ns_ntrnt::NTRNT_PEER_FROM_SELF, *g_session, *g_peer_mgr, l_sas);
                l_s = l_peer->accept_utp(a_args->socket);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing accept_utp");
                        if (l_peer) { delete l_peer; l_peer = nullptr; }
                        return NTRNT_STATUS_ERROR;
                }
                l_peer->set_state(ns_ntrnt::peer::STATE_PHE_SETUP);
                // -------------------------------------------------
                // add to map
                // -------------------------------------------------
                g_peer_map[l_sas] = l_peer;
                break;
        }
        // -------------------------------------------------
        // UTP_ON_ACCEPT
        // -------------------------------------------------
        case UTP_ON_ERROR:
        {
                // TODO
                break;
        }
        // -------------------------------------------------
        // UTP_ON_ACCEPT
        // -------------------------------------------------
        case UTP_ON_READ:
        {
                // TODO
                break;
        }
        // -------------------------------------------------
        // UTP_ON_OVERHEAD_STATISTICS
        // -------------------------------------------------
        case UTP_ON_OVERHEAD_STATISTICS:
        {
                // TODO
                break;
        }
        // -------------------------------------------------
        // UTP_GET_READ_BUFFER_SIZE
        // -------------------------------------------------
        case UTP_GET_READ_BUFFER_SIZE:
        {
                // TODO
                // FIX!!!
                return (64*1024);
        }
        // -------------------------------------------------
        // UTP_LOG
        // -------------------------------------------------
        case UTP_LOG:
        {
                // TODO
                break;
        }
        // -------------------------------------------------
        // UTP_ON_STATE_CHANGE
        // -------------------------------------------------
        case UTP_ON_STATE_CHANGE:
        {
                // TODO ???
                break;
        }
        // -------------------------------------------------
        // UTP_SENDTO
        // -------------------------------------------------
        case UTP_SENDTO:
        {
                int l_fd = g_session->get_udp_fd();
                const struct sockaddr* l_sa = a_args->address;
                if(l_sa->sa_family == AF_INET6)
                {
                        l_fd = g_session->get_udp6_fd();
                }
                int l_s;
                errno = 0;
                l_s = sendto(l_fd, a_args->buf, a_args->len, 0, l_sa, a_args->address_len);
                if (l_s < 0)
                {
                        // -----------------------------------------
                        // EAGAIN
                        // -----------------------------------------
                        if (errno == EAGAIN)
                        {
                                NDBG_PRINT("unexpected EAGAIN from sendto\n");
                                return NTRNT_STATUS_AGAIN;
                        }
                        TRC_ERROR("error performing sendto. Reason: %s\n", strerror(errno));
                        TRC_ERROR("fd:                  %d", l_fd);
                        TRC_ERROR("a_args->buf:         %p", a_args->buf);
                        TRC_ERROR("a_args->len:         %lu", a_args->len);
                        TRC_ERROR("a_args->address:     %p", l_sa);
                        TRC_ERROR("a_args->address_len: %u", a_args->address_len);
                        return 0;
                }
                break;
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        default:
        {
                TRC_ERROR("unhandled utp msg type: %d", a_args->callback_type);
                break;
        }
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Print the version.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void print_version(FILE* a_stream, int a_exit_code)
{
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
static void print_usage(FILE* a_stream, int a_exit_code)
{
        fprintf(a_stream, "Usage: phecat [options]\n");
        fprintf(a_stream, "Options:\n");
        fprintf(a_stream, "  -h, --help           display this help and exit.\n");
        fprintf(a_stream, "  -v, --version        display the version number and exit.\n");
        fprintf(a_stream, "  -i, --info-hash      info hash (20 bytes -hex string).\n");
        fprintf(a_stream, "  -c, --connect        peer address+port ie 127.0.0.1:51413\n");
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
int main(int argc, char** argv)
{
        // -------------------------------------------------
        // vars
        // -------------------------------------------------
        ns_ntrnt::trc_log_level_set(ns_ntrnt::TRC_LOG_LEVEL_ERROR);
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
        static struct option l_long_opt[] = {
                { "help",      no_argument,       0, 'h' },
                { "version",   no_argument,       0, 'v' },
                { "info-hash", required_argument, 0, 'i' },
                { "connect",   required_argument, 0, 'c' },
                { "listen",    no_argument,       0, 'l' },
                { "port",      required_argument, 0, 'p' },
                // Sentinel
                { 0,           0,                 0,  0  }
        };
        char l_short_arg_list[] = "hvi:c:lp:";
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
                // info hash
                // -----------------------------------------
                case 'i':
                {
                        l_info_hash = optarg;
                        break;
                }
                // -----------------------------------------
                // peer
                // -----------------------------------------
                case 'c':
                {
                        l_host = optarg;
                        break;
                }
                // -----------------------------------------
                // listen
                // -----------------------------------------
                case 'l':
                {
                        l_listen = true;
                        break;
                }
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
                                l_host = argv[optind];
                        }
                        break;
                }
                }
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
        // check for info hash
        // -------------------------------------------------
        if (l_info_hash.empty())
        {
                NDBG_ERROR_AT("Error info hash must be specified.\n");
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // check for tracker
        // -------------------------------------------------
        if (!l_listen &&
            l_host.empty())
        {
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
        if (l_s != NTRNT_STATUS_OK)
        {
                NDBG_ERROR_AT("error performing session init.\n");
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // TODO HACK UTP CB
        // -------------------------------------------------
        utp_context* l_utp_ctx = l_ses.get_peer_mgr().get_utp_ctx();
        // set callbacks
        utp_set_callback(l_utp_ctx, UTP_ON_ACCEPT, _utp_cb);
        utp_set_callback(l_utp_ctx, UTP_SENDTO, _utp_cb);
        utp_set_callback(l_utp_ctx, UTP_ON_READ, _utp_cb);
        // TODO -don't implement for now...
#if 0
        utp_set_callback(m_utp_ctx, UTP_GET_READ_BUFFER_SIZE, _utp_cb);
#endif
        utp_set_callback(l_utp_ctx, UTP_ON_ERROR, _utp_cb);
        utp_set_callback(l_utp_ctx, UTP_ON_OVERHEAD_STATISTICS, _utp_cb);
        utp_set_callback(l_utp_ctx, UTP_ON_STATE_CHANGE, _utp_cb);
        // tracing
#if 0
        utp_set_callback(m_utp_ctx, UTP_LOG, &_utp_cb);
        utp_context_set_option(m_utp_ctx, UTP_LOG_NORMAL, 1);
        utp_context_set_option(m_utp_ctx, UTP_LOG_MTU, 1);
        utp_context_set_option(m_utp_ctx, UTP_LOG_DEBUG, 1);
#endif
        // -------------------------------------------------
        // peer
        // -------------------------------------------------
        g_peer_mgr = &(l_ses.get_peer_mgr());
        ns_ntrnt::peer* l_peer  = nullptr;
        if (!l_listen)
        {
                sockaddr_storage l_sas;
                l_s = ns_ntrnt::str_to_sas(l_host, l_sas);
                if (l_s != NTRNT_STATUS_OK)
                {
                        NDBG_ERROR_AT("error performing str_to_sas.\n");
                        return STATUS_ERROR;
                }
                l_peer = new ns_ntrnt::peer(ns_ntrnt::NTRNT_PEER_FROM_SELF, l_ses,l_ses.get_peer_mgr(), l_sas);
                l_s = l_peer->connect();
                if (l_s != NTRNT_STATUS_OK)
                {
                        NDBG_ERROR_AT("error performing connect.\n");
                        if (l_peer) { delete l_peer; l_peer = nullptr; }
                        return STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // run
        // -------------------------------------------------
        g_evr_loop = l_ses.get_evr_loop();
        while(!g_stopped)
        {
                // -----------------------------------------
                // run event loop
                // -----------------------------------------
                l_s = g_evr_loop->run();
                if (l_s != NTRNT_STATUS_OK)
                {
                        // TODO log error
                }
        }
        NDBG_PRINT("done...\n");
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        return NTRNT_STATUS_OK;
}
