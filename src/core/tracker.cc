//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
// ---------------------------------------------------------
// external includes
// ---------------------------------------------------------
#include "ntrnt/def.h"
// ---------------------------------------------------------
// internal includes
// ---------------------------------------------------------
#include "core/tracker.h"
#include "core/tracker_tcp.h"
#include "core/tracker_udp.h"
#include "conn/scheme.h"
#include "support/trace.h"
#include "support/ndebug.h"
#include "support/data.h"
#include "support/util.h"
// ---------------------------------------------------------
// ext
// ---------------------------------------------------------
#include "http_parser/http_parser.h"
// ---------------------------------------------------------
// std
// ---------------------------------------------------------
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
// ---------------------------------------------------------
// stl
// ---------------------------------------------------------
#include <sstream>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _REQUEST_SIZE 16384
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
template <typename T>
std::string to_string(const T& a_num)
{
        std::stringstream l_s;
        l_s << a_num;
        return l_s.str();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
tracker::tracker(session& a_session):
        m_session(a_session),
        m_announce(),
        m_scheme(SCHEME_NONE),
        m_host(),
        m_port(0),
        m_root(),
        m_stat_announce_num(0),
        m_stat_scrape_num(0),
        m_next_announce_s(0),
        m_next_scrape_s(0),
        m_stat_last_announce_time_s(0),
        m_stat_last_announce_num_peers(0),
        m_stat_last_announce_num_peers6(0),
        m_stat_last_scrape_time_s(0),
        m_stat_last_scrape_num_complete(0),
        m_stat_last_scrape_num_downloaded(0),
        m_stat_last_scrape_num_incomplete(0)
{
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
tracker::~tracker(void)
{
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void tracker::display(void)
{
        NDBG_OUTPUT("+-----------------------------------------------------------\n");
        NDBG_OUTPUT("|                       T R A C K E R\n");
        NDBG_OUTPUT("+-----------------------------------------------------------\n");
        NDBG_OUTPUT("| announce: %s\n", m_announce.c_str());
        NDBG_OUTPUT("| host:     %s\n", m_host.c_str());
        NDBG_OUTPUT("| root:     %s\n", m_root.c_str());
        NDBG_OUTPUT("+-----------------------------------------------------------\n");
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
std::string tracker::str(void)
{
        std::string l_str;
        l_str += get_scheme_str(m_scheme);
        l_str += "://";
        l_str += m_host;
        l_str += ":";
        l_str += to_string(m_port);
        l_str += m_root;
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t init_tracker_w_url(tracker** ao_tracker,
                           session& a_session,
                           const char* a_url,
                           size_t a_url_len)
{
        if ((!a_url) ||
            (a_url_len <= 0) ||
            (!ao_tracker))
        {
                NTRNT_PERROR("arg error");
                return NTRNT_STATUS_ERROR;
        }
        *ao_tracker = nullptr;
        // -------------------------------------------------
        // properties
        // -------------------------------------------------
        scheme_t l_scheme = SCHEME_NONE;
        std::string l_host;
        uint16_t l_port = 0;
        std::string l_root;
        // -------------------------------------------------
        // copy in url for parsing...
        // -------------------------------------------------
        char *l_str = nullptr;
        size_t l_str_len = 0;
        l_str_len = a_url_len;
        l_str = (char *)malloc(sizeof(char)*(a_url_len+1));
        memcpy((void *)l_str, (const void *)a_url, a_url_len);
        // silence bleating memory sanitizers...
        //memset(&l_url, 0, sizeof(l_url));
        // -------------------------------------------------
        // parse
        // -------------------------------------------------
        http_parser_url l_url;
        http_parser_url_init(&l_url);
        int l_s;
        l_s = http_parser_parse_url(l_str, l_str_len, 0, &l_url);
        if (l_s != 0)
        {
                NTRNT_PERROR("parsing url: %.*s", (int)l_str_len, l_str);
                // TODO get error msg from http_parser
                if (l_str) { free(l_str); l_str = nullptr; }
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // set bits...
        // -------------------------------------------------
        for(uint32_t i_part = 0; i_part < UF_MAX; ++i_part)
        {
                if (l_url.field_data[i_part].len &&
                  // TODO Some bug with parser -parsing urls like "http://127.0.0.1" sans paths
                   ((l_url.field_data[i_part].len + l_url.field_data[i_part].off) <= l_str_len))
                {
                        char *l_part = l_str + l_url.field_data[i_part].off;
                        size_t l_part_len = l_url.field_data[i_part].len;
                        switch(i_part)
                        {
                        // ---------------------------------
                        // scheme
                        // ---------------------------------
                        case UF_SCHEMA:
                        {
                                std::string l_scheme_str;
                                l_scheme_str.assign(l_part, l_part_len);
                                l_scheme = get_scheme(l_scheme_str);
                                if (l_scheme == SCHEME_NONE)
                                {
                                        NTRNT_PERROR("unrecognized scheme: %s", l_scheme_str.c_str());
                                        // TODO get error msg from http_parser
                                        if (l_str) { free(l_str); l_str = nullptr; }
                                        return NTRNT_STATUS_ERROR;
                                }
                                break;
                        }
                        // ---------------------------------
                        // host
                        // ---------------------------------
                        case UF_HOST:
                        {
                                l_host.assign(l_part, l_part_len);
                                break;
                        }
                        // ---------------------------------
                        // port
                        // ---------------------------------
                        case UF_PORT:
                        {
                                std::string l_port_str;
                                l_port_str.assign(l_part, l_part_len);
                                int l_port_val;
                                l_port_val = atoi(l_port_str.c_str());
                                if ((l_port_val < 1) ||
                                   (l_port_val > 65535))
                                {
                                        NTRNT_PERROR("bad port value: %d", l_port_val);
                                        // TODO get error msg from http_parser
                                        if (l_str) { free(l_str); l_str = nullptr; }
                                        return NTRNT_STATUS_ERROR;
                                }
                                l_port = (uint16_t)l_port_val;
                                break;
                        }
                        // ---------------------------------
                        // path
                        // ---------------------------------
                        case UF_PATH:
                        {
                                l_root.assign(l_part, l_part_len);
                                break;
                        }
                        // ---------------------------------
                        // other
                        // ---------------------------------
                        default:
                        {
                                break;
                        }
                        }
                }
        }
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        // -------------------------------------------------
        // for scheme...
        // -------------------------------------------------
        switch(l_scheme)
        {
        // -------------------------------------------------
        // SCHEME_HTTP
        // -------------------------------------------------
        case SCHEME_TCP:
        {
                *ao_tracker = new tracker_tcp(a_session);
                break;
        }
        // -------------------------------------------------
        // SCHEME_HTTPS
        // -------------------------------------------------
        case SCHEME_TLS:
        {
                *ao_tracker = new tracker_tcp(a_session);
                break;
        }
        // -------------------------------------------------
        // SCHEME_UDP
        // -------------------------------------------------
        case SCHEME_UDP:
        {
                *ao_tracker = new tracker_udp(a_session);
                break;
        }
        // -------------------------------------------------
        // SCHEME_WSS
        // -------------------------------------------------
        case SCHEME_WSS:
        {
                NTRNT_PERROR("not supported.");
                if (l_str) { free(l_str); l_str = nullptr; }
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                NTRNT_PERROR("not supported.");
                if (l_str) { free(l_str); l_str = nullptr; }
                return NTRNT_STATUS_ERROR;
        }
        }
        // -------------------------------------------------
        // set properties
        // -------------------------------------------------
        (*ao_tracker)->m_announce.assign(a_url, a_url_len);
        (*ao_tracker)->m_scheme = l_scheme;
        (*ao_tracker)->m_host = l_host;
        (*ao_tracker)->m_port = l_port;
        (*ao_tracker)->m_root = l_root;
        // -------------------------------------------------
        // done
        // -------------------------------------------------
        if (l_str) { free(l_str); l_str = nullptr; }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void http_escape(std::string& ao_out, std::string a_in, bool a_escp_rsvd)
{
        static const std::string s_rsvd_chars = "!*'();:@&=+$,/?%#[]";
        static const std::string s_unescpd_chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_.~";
        for (auto& ch : a_in)
        {
                if ((s_unescpd_chars.find(ch) != s_unescpd_chars.npos) ||
                    (!a_escp_rsvd &&
                    (s_rsvd_chars.find(ch) != s_rsvd_chars.npos)))
                {
                        ao_out += ch;
                }
                else
                {
                        char buf[16];
                        snprintf(buf, sizeof(buf), "%%%02X", (unsigned)(ch & 0xFF));
                        ao_out += buf;
                }
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void encode_digest(char* a_out, const uint8_t* a_digest, size_t a_digest_len)
{
        for (size_t i_c = 0; i_c < a_digest_len; ++i_c)
        {
                // -----------------------------------------
                // see: rfc2396
                //      unreserved  = alphanum | mark
                // -----------------------------------------
                uint8_t l_c = a_digest[i_c];
                if (('0' <= l_c && l_c <= '9') ||
                    ('A' <= l_c && l_c <= 'Z') ||
                    ('a' <= l_c && l_c <= 'z') ||
                    l_c == '.' ||
                    l_c == '-' ||
                    l_c == '_' ||
                    l_c == '~')
                {
                        *a_out++ = (char)l_c;
                }
                else
                {
                        a_out += snprintf(a_out, 4, "%%%02x", (unsigned int)l_c);
                }
        }
        *a_out = '\0';
}
}
