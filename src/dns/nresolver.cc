//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "dns/ai_cache.h"
#include "dns/nresolver.h"
#include "dns/nlookup.h"
#include "evr/evr.h"
#include "support/time_util.h"
#include "support/time_util.h"
#include "conn/host_info.h"
#include "ntrnt/def.h"
#include "support/trace.h"
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
// for inet_pton
#include <arpa/inet.h>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
std::string get_cache_key(const std::string &a_host, uint16_t a_port)
{
        char l_port_str[8];
        snprintf(l_port_str, 8, "%d", a_port);
        std::string l_cache_key;
        l_cache_key = a_host + ":" + l_port_str;
        return l_cache_key;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
nresolver::nresolver():
        m_is_initd(false),
        m_resolver_host_list(),
        m_port(53),
        m_use_cache(true),
        m_cache_mutex(),
        m_ai_cache(NULL)
{
        pthread_mutex_init(&m_cache_mutex, NULL);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
nresolver::~nresolver()
{
        // Sync back to disk
        if (m_use_cache && m_ai_cache)
        {
                delete m_ai_cache;
                m_ai_cache = NULL;
        }
        pthread_mutex_destroy(&m_cache_mutex);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nresolver::init(bool a_use_cache,
                        const std::string &a_ai_cache_file)
{
        if (m_is_initd)
        {
                return NTRNT_STATUS_OK;
        }
        m_use_cache = a_use_cache;
        if (m_use_cache)
        {
                m_ai_cache = new ai_cache(a_ai_cache_file);
        }
        else
        {
                m_ai_cache = NULL;
        }
        m_is_initd = true;
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void nresolver::add_resolver_host(const std::string a_server)
{
        m_resolver_host_list.push_back(a_server);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static bool is_valid_ip_address(const char *a_str)
{
    struct sockaddr_in l_sa;
    return (inet_pton(AF_INET, a_str, &(l_sa.sin_addr)) != 0);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nresolver::lookup_tryfast(const std::string &a_host,
                                  uint16_t a_port,
                                  host_info &ao_host_info)
{
        //NDBG_PRINT("%sRESOLVE%s: a_host: %s a_port: %d\n",
        //           ANSI_COLOR_BG_RED, ANSI_COLOR_OFF,
        //           a_host.c_str(), a_port);
        int32_t l_s;
        if (!m_is_initd)
        {
                l_s = init();
                if (l_s != NTRNT_STATUS_OK)
                {
                        return NTRNT_STATUS_ERROR;
                }
        }
        // ---------------------------------------
        // cache lookup
        // ---------------------------------------
        host_info *l_host_info = NULL;
        // Create a cache key
        char l_port_str[8];
        snprintf(l_port_str, 8, "%d", a_port);
        std::string l_cache_key;
        l_cache_key = a_host + ":" + l_port_str;
        // Lookup in map
        if (m_use_cache && m_ai_cache)
        {
                pthread_mutex_lock(&m_cache_mutex);
                l_host_info = m_ai_cache->lookup(l_cache_key);
                pthread_mutex_unlock(&m_cache_mutex);
        }
        if (l_host_info)
        {
                ao_host_info = *l_host_info;
                return NTRNT_STATUS_OK;
        }
        // Lookup inline
        if (is_valid_ip_address(a_host.c_str()))
        {
                return lookup_inline(a_host, a_port, ao_host_info);
        }
        return NTRNT_STATUS_ERROR;
}
//! ----------------------------------------------------------------------------
//! \details: slow resolution
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nresolver::lookup_inline(const std::string &a_host, uint16_t a_port, host_info &ao_host_info)
{
        int32_t l_s;
        host_info *l_host_info = new host_info();
        l_s = nlookup(a_host, a_port, *l_host_info);
        if (l_s != NTRNT_STATUS_OK)
        {
                delete l_host_info;
                return NTRNT_STATUS_ERROR;
        }
        //show_host_info();
        if (m_use_cache &&
           m_ai_cache)
        {
                l_host_info = m_ai_cache->lookup(get_cache_key(a_host, a_port), l_host_info);
        }
        int32_t l_retval = NTRNT_STATUS_OK;
        if (l_host_info)
        {
                ao_host_info = *l_host_info;
                l_retval = NTRNT_STATUS_OK;
        }
        else
        {
                l_retval = NTRNT_STATUS_ERROR;
        }
        if (l_host_info &&
           (!m_use_cache || !m_ai_cache))
        {
                delete l_host_info;
                l_host_info = NULL;
        }
        return l_retval;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nresolver::lookup_sync(const std::string &a_host,
                               uint16_t a_port,
                               host_info &ao_host_info)
{
        //NDBG_PRINT("%sRESOLVE%s: a_host: %s a_port: %d\n",
        //           ANSI_COLOR_FG_RED, ANSI_COLOR_OFF,
        //           a_host.c_str(), a_port);
        int32_t l_s;
        if (!m_is_initd)
        {
                l_s = init();
                if (l_s != NTRNT_STATUS_OK)
                {
                        return NTRNT_STATUS_ERROR;
                }
        }
        // tryfast lookup
        l_s = lookup_tryfast(a_host, a_port, ao_host_info);
        if (l_s == NTRNT_STATUS_OK)
        {
                return NTRNT_STATUS_OK;
        }
        return lookup_inline(a_host, a_port, ao_host_info);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
const char *s_bytes_2_ip_str(const unsigned char *c)
{
        static char b[sizeof("255.255.255.255")];
        sprintf(b, "%u.%u.%u.%u", c[0], c[1], c[2], c[3]);
        return b;
}
}
