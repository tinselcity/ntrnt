//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
// ---------------------------------------------------------
// external includes
// ---------------------------------------------------------
#include "ntrnt/def.h"
// ---------------------------------------------------------
// this app
// ---------------------------------------------------------
#include "upnp.h"
// ---------------------------------------------------------
// upnp
// ---------------------------------------------------------
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
// ---------------------------------------------------------
// std includes
// ---------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
// ---------------------------------------------------------
// c++ std library
// ---------------------------------------------------------
#include <string>
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#ifndef UNUSED
#define UNUSED(x) ( (void)(x) )
#endif
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef enum _upnp_igd_status
{
    UPNP_IGD_NONE = 0,
    UPNP_IGD_VALID_CONNECTED = 1,
    UPNP_IGD_VALID_NOT_CONNECTED = 2,
    UPNP_IGD_INVALID = 3
} _upnp_igd_status_t;
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
upnp::upnp(void):
        m_urls(),
        m_datas(),
        m_lan_addr(),
        m_stat_status(),
        m_stat_uptime(0),
        m_stat_last_conn_err(),
        m_stat_conn_type(),
        m_stat_ext_ip(),
        m_stat_br_down(0),
        m_stat_br_up(0)
{
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
upnp::~upnp(void)
{
        FreeUPNPUrls(&m_urls);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t upnp::init(void)
{
        NDBG_OUTPUT(": MINIUPNPC_API_VERSION: %d\n", MINIUPNPC_API_VERSION);
        // -------------------------------------------------
        // discover
        // -------------------------------------------------
        struct UPNPDev* l_dev = nullptr;
#if (MINIUPNPC_API_VERSION >= 8)
        int l_err = UPNPDISCOVER_SUCCESS;
        errno = 0;
        NDBG_OUTPUT(": upnpDiscover: ...\n");
#if (MINIUPNPC_API_VERSION >= 14)
        l_dev = upnpDiscover(2000, // delay ms
                             nullptr,
                             nullptr,
                             0,
                             0,
                             2,
                             &l_err);
#else
        l_dev = upnpDiscover(2000, // delay ms
                             nullptr,
                             nullptr,
                             0,
                             0,
                             &l_err);
#endif
#else
        l_dev = upnpDiscover(2000, // delay ms
                             nullptr,
                             nullptr,
                             0);
#endif
        NDBG_OUTPUT(": upnpDiscover: dev: %p\n", l_dev);
        NDBG_OUTPUT(": upnpDiscover: err: %d\n", l_err);
        if (l_dev == nullptr)
        {
                NDBG_PRINT("error performing upnpDiscover. Reason[%d]: %s\n", errno, strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        NDBG_OUTPUT(": upnpDiscover: done...\n");
        // -------------------------------------------------
        // find internet gateway device
        // -------------------------------------------------
        int32_t l_s;
        NDBG_OUTPUT(": UPNP_GetValidIGD: ...\n");
        l_s = UPNP_GetValidIGD(l_dev, &m_urls, &m_datas, m_lan_addr, sizeof(m_lan_addr));
        if (l_s != UPNP_IGD_VALID_CONNECTED)
        {
                NDBG_PRINT("error performing UPNP_GetValidIGD. Reason[%d]: %s\n", errno, strerror(errno));
                NDBG_PRINT("If your router supports UPnP, please make sure UPnP is enabled.\n");
                freeUPNPDevlist(l_dev);
        }
        NDBG_OUTPUT(": UPNP_GetValidIGD: done...\n");
        NDBG_OUTPUT(": Found Internet Gateway Device: %s\n", m_urls.controlURL);
        NDBG_OUTPUT(": Local Address:                 %s\n", m_lan_addr);
        freeUPNPDevlist(l_dev);
        // -------------------------------------------------
        // status info
        // -------------------------------------------------
        l_s = UPNP_GetStatusInfo(m_urls.controlURL,
                                 m_datas.first.servicetype,
                                 m_stat_status,
                                 &m_stat_uptime,
                                 m_stat_last_conn_err);
        if (l_s != UPNPCOMMAND_SUCCESS)
        {

        }
        else
        {
        NDBG_OUTPUT(": UPNP_STAT: status:             %s\n", m_stat_status);
        NDBG_OUTPUT(": UPNP_STAT: uptime:             %u\n", m_stat_uptime);
        NDBG_OUTPUT(": UPNP_STAT: last_conn_err:      %s\n", m_stat_last_conn_err);
        }
        // -------------------------------------------------
        // connection type
        // -------------------------------------------------
        char l_upnp_stat_conn_type[64];
        l_s = UPNP_GetConnectionTypeInfo(m_urls.controlURL,
                                         m_datas.first.servicetype,
                                         l_upnp_stat_conn_type);
        if (l_s != UPNPCOMMAND_SUCCESS)
        {

        }
        else
        {
        NDBG_OUTPUT(": UPNP_STAT: conn_type_info:     %s\n", m_stat_status);
        }
        // -------------------------------------------------
        // external IP address
        // -------------------------------------------------
        l_s = UPNP_GetExternalIPAddress(m_urls.controlURL,
                                        m_datas.first.servicetype,
                                        m_stat_ext_ip);
        if (l_s != UPNPCOMMAND_SUCCESS)
        {

        }
        else
        {
        NDBG_OUTPUT(": UPNP_STAT: ext_ip_address:     %s\n", m_stat_ext_ip);
        }
        // -------------------------------------------------
        // link layer max bitrates
        // -------------------------------------------------
        l_s = UPNP_GetLinkLayerMaxBitRates(m_urls.controlURL,
                                           m_datas.first.servicetype,
                                           &m_stat_br_down,
                                           &m_stat_br_up);
        if (l_s != UPNPCOMMAND_SUCCESS)
        {

        }
        else
        {
        NDBG_OUTPUT(": UPNP_STAT: bitrate_down:       %u\n", m_stat_br_down);
        NDBG_OUTPUT(": UPNP_STAT: bitrate_up:         %u\n", m_stat_br_up);
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t upnp::teardown(void)
{
        // ??? do nothing???
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t upnp::add_port_mapping(uint16_t a_port)
{
        int32_t l_s;
        // -------------------------------------------------
        // create port string
        // -------------------------------------------------
        char l_port_str[16];
        snprintf(l_port_str, sizeof(l_port_str), "%u", a_port);
        // -------------------------------------------------
        // create desc string
        // -------------------------------------------------
        char l_desc[64];
        snprintf(l_desc, sizeof(l_desc), "%s at %d", "ntrnt", a_port);
        // -------------------------------------------------
        // add port mapping (TCP)
        // -------------------------------------------------
        errno = 0;
        NDBG_OUTPUT(": UPNP_AddPortMapping(TCP): port[%u]\n", a_port);
        l_s = UPNP_AddPortMapping(m_urls.controlURL,
                                  m_datas.first.servicetype,
                                  l_port_str,
                                  l_port_str,
                                  m_lan_addr,
                                  l_desc,
                                  "TCP",
                                  nullptr,
                                  nullptr);
        if (l_s != 0)
        {
                NDBG_PRINT("error performing UPNP_AddPortMapping (TCP). Reason[%d]: %s\n", errno, strerror(errno));
        }
        NDBG_OUTPUT(": UPNP_AddPortMapping(TCP): port[%u]: done...\n", a_port);
        // -------------------------------------------------
        // add port mapping (UDP)
        // -------------------------------------------------
        errno = 0;
        NDBG_OUTPUT(": UPNP_AddPortMapping(UDP): port[%u]\n", a_port);
        l_s = UPNP_AddPortMapping(m_urls.controlURL,
                                  m_datas.first.servicetype,
                                  l_port_str,
                                  l_port_str,
                                  m_lan_addr,
                                  l_desc,
                                  "UDP",
                                  nullptr,
                                  nullptr);
        if (l_s != 0)
        {
                NDBG_PRINT("error performing UPNP_AddPortMapping (UDP). Reason[%d]: %s\n", errno, strerror(errno));
        }
        NDBG_OUTPUT(": UPNP_AddPortMapping(UDP): port[%u]: done...\n", a_port);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t upnp::delete_port_mapping(uint16_t a_port)
{
        int32_t l_s;
        // -------------------------------------------------
        // create port string
        // -------------------------------------------------
        char l_port_str[16];
        snprintf(l_port_str, sizeof(l_port_str), "%u", a_port);
        // -------------------------------------------------
        // create desc string
        // -------------------------------------------------
        char l_desc[64];
        snprintf(l_desc, sizeof(l_desc), "%s at %d", "ntrnt", a_port);
        // -----------------------------------------
        // remove port mapping (TCP)
        // -----------------------------------------
        NDBG_OUTPUT(": UPNP_DeletePortMapping(TCP): port[%u]\n", a_port);
        errno = 0;
        l_s = UPNP_DeletePortMapping(m_urls.controlURL,
                                     m_datas.first.servicetype,
                                     l_port_str,
                                     "TCP",
                                     nullptr);
        if (l_s != 0)
        {
                NDBG_PRINT("error performing UPNP_DeletePortMapping (TCP). Reason[%d]: %s\n", errno, strerror(errno));
        }
        NDBG_OUTPUT(": UPNP_DeletePortMapping(TCP): port[%u]: done...\n", a_port);
        // -----------------------------------------
        // remove port mapping (UDP)
        // -----------------------------------------
        NDBG_OUTPUT(": UPNP_DeletePortMapping(UDP): port[%u]\n", a_port);
        errno = 0;
        l_s = UPNP_DeletePortMapping(m_urls.controlURL,
                                     m_datas.first.servicetype,
                                     l_port_str,
                                     "UDP",
                                     nullptr);
        if (l_s != 0)
        {
                NDBG_PRINT("error performing UPNP_DeletePortMapping (UDP). Reason[%d]: %s\n", errno, strerror(errno));
        }
        NDBG_OUTPUT(": UPNP_DeletePortMapping(UDP): port[%u]: done...\n", a_port);
        return NTRNT_STATUS_OK;
}
}
#ifdef STANDALONE_UPNP
//! ----------------------------------------------------------------------------
//! \details: print the command line help.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void print_usage(const char *a_prog, FILE* a_stream, int a_exit_code)
{
        fprintf(a_stream, "Usage: %s [options]\n", a_prog);
        fprintf(a_stream, "Options are:\n");
        fprintf(a_stream, "  -h, --help     Display this help and exit.\n");
        fprintf(a_stream, "  -p, --port     port (default 51413 -BitTorrent)\n");
        fprintf(a_stream, "  -s, --set      set up port forwarding\n");
        fprintf(a_stream, "  -u, --unset    unset port forwaring\n");
        fprintf(a_stream, "  -e, --echo     run echo server\n");
        exit(a_exit_code);
}
//! ----------------------------------------------------------------------------
//! \details: index certificates
//! \return:  0 on success -1 on error.
//! \param:   TODO
//! ----------------------------------------------------------------------------
int main(int argc, char** argv)
{
        // -------------------------------------------------
        // defaults
        // -------------------------------------------------
        uint16_t l_port = 51413;
        bool l_flag_set = false;
        bool l_flag_unset = false;
        bool l_flag_echo = false;
        // -------------------------------------------------
        // cmd line args
        // -------------------------------------------------
        char l_opt = '\0';
        std::string l_arg;
        int l_opt_index = 0;
        struct option l_long_options[] =
                {
                { "help",  no_argument,       0, 'h' },
                { "port",  required_argument, 0, 'p' },
                { "set",   no_argument,       0, 's' },
                { "unset", no_argument,       0, 'u' },
                { "echo",  no_argument,       0, 'e' },
                // list sentinel
                { 0, 0, 0, 0 }
        };
        // -------------------------------------------------
        // parse args...
        // -------------------------------------------------
        char l_short_arg_list[] = "hp:sue";
        while ((l_opt = getopt_long_only(argc, argv, l_short_arg_list, l_long_options, &l_opt_index)) != -1)
        {
                if (optarg)
                {
                        l_arg = std::string(optarg);
                }
                else
                {
                        l_arg.clear();
                }
                //printf("arg[%c=%d]: %s\n", l_opt, l_option_index, l_argument.c_str());
                switch (l_opt)
                {
                // -----------------------------------------
                // help
                // -----------------------------------------
                case 'h':
                {
                        print_usage(argv[0], stdout, 0);
                        break;
                }
                // -----------------------------------------
                // port
                // -----------------------------------------
                case 'p':
                {
                        int l_port_val;
                        l_port_val = atoi(l_arg.c_str());
                        if ((l_port_val < 1) ||
                           (l_port_val > 65535))
                        {
                                NDBG_OUTPUT("Error bad port value: %d.\n", l_port_val);
                                print_usage(argv[0], stdout, 0);
                        }
                        l_port = (uint16_t)l_port_val;
                        break;
                }
                // -----------------------------------------
                // set
                // -----------------------------------------
                case 's':
                {
                        l_flag_set = true;
                        break;
                }
                // -----------------------------------------
                // unset
                // -----------------------------------------
                case 'u':
                {
                        l_flag_unset = true;
                        break;
                }
                // -----------------------------------------
                // echo
                // -----------------------------------------
                case 'e':
                {
                        l_flag_echo = true;
                        break;
                }
                // -----------------------------------------
                // what???
                // -----------------------------------------
                case '?':
                {
                        NDBG_OUTPUT("exiting.\n");
                        print_usage(argv[0], stdout, NTRNT_STATUS_ERROR);
                        break;
                }
                // -----------------------------------------
                // huh???
                // -----------------------------------------
                default:
                {
                        NDBG_OUTPUT("unrecognized option.\n");
                        print_usage(argv[0], stdout,  NTRNT_STATUS_ERROR);
                        break;
                }
                }
        }
        int32_t l_s;
        ns_ntrnt::upnp l_upnp;
        // -------------------------------------------------
        // setup port forwarding
        // -------------------------------------------------
        if (l_flag_set)
        {
                l_s = l_upnp.init();
                // TODO check for error
                UNUSED(l_s);
                l_s = l_upnp.add_port_mapping(l_port);
                // TODO check for error
                UNUSED(l_s);
        }
        // -------------------------------------------------
        // unset port forwarding
        // -------------------------------------------------
        else if (l_flag_unset)
        {
                l_s = l_upnp.init();
                // TODO check for error
                UNUSED(l_s);
                l_s = l_upnp.add_port_mapping(l_port);
                // TODO check for error
                UNUSED(l_s);
        }
        // -------------------------------------------------
        // run echo server
        // -------------------------------------------------
        else if (l_flag_echo)
        {
                l_s = echo_server(l_port);
                if (l_s != NTRNT_STATUS_OK)
                {
                        return NTRNT_STATUS_ERROR;
                }
        }
        else
        {
                l_s = l_upnp.init();
                // TODO check for error
                UNUSED(l_s);
        }
        // -------------------------------------------------
        // done
        // -------------------------------------------------
        return 0;
}
#endif
