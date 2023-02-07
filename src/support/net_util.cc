//! ----------------------------------------------------------------------------
//! include
//! ----------------------------------------------------------------------------
// ---------------------------------------------------------
// internal
// ---------------------------------------------------------
#include "support/net_util.h"
// ---------------------------------------------------------
// std includes
// ---------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#ifndef _TRUE
#define _TRUE 1
#endif
#ifndef _FALSE
#define _FALSE 0
#endif
#ifndef NTRNT_STATUS_OK
#define NTRNT_STATUS_OK 0
#endif
#ifndef NTRNT_STATUS_ERROR
#define NTRNT_STATUS_ERROR -1
#endif
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! typedefs
//! ----------------------------------------------------------------------------
typedef unsigned char uchar_t;
//! ----------------------------------------------------------------------------
//! \details:  Get source address used for a given destination address.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int _get_source_address(struct sockaddr const *a_dst,
                               socklen_t a_dst_len,
                               struct sockaddr *a_src,
                               socklen_t *a_src_len)
{
        // -------------------------------------------------
        // make socket
        // -------------------------------------------------
        int l_fd;
        l_fd = socket(a_dst->sa_family, SOCK_DGRAM, 0);
        if (l_fd == -1)
        {
                printf("error performing socket. Reason: %s\n", strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // connect
        // UDP socket doesn't send packets to connect
        // -------------------------------------------------
        int l_s;
        l_s = connect(l_fd, a_dst, a_dst_len);
        if (l_s != 0)
        {
                printf("error performing connect. Reason: %s\n", strerror(errno));
                if (l_fd) { close(l_fd); l_fd = -1; }
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get sockname
        // -------------------------------------------------
        l_s = getsockname(l_fd, a_src, a_src_len);
        if (l_s != 0)
        {
                printf("error performing getsockname. Reason: %s\n", strerror(errno));
                if (l_fd) { close(l_fd); l_fd = -1; }
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // done
        // -------------------------------------------------
        close(l_fd);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int _get_public_address_v4(uint32_t *a_addr)
{
        static uint32_t l_addr = 0;
        if (l_addr)
        {
                *a_addr = l_addr;
        }
        int l_s;
        struct sockaddr_storage l_sas;
        socklen_t l_sslen = sizeof(l_sas);
        struct sockaddr const *l_sa = NULL;
        socklen_t l_salen = 0;
        // -------------------------------------------------
        // make sockaddr_in
        // -------------------------------------------------
        struct sockaddr_in l_sin;
        memset(&l_sin, 0, sizeof(l_sin));
        l_sin.sin_family = AF_INET;
        // -------------------------------------------------
        // any real ipv4 address (not private)
        // -------------------------------------------------
        l_s = inet_pton(AF_INET, "8.8.8.8", &l_sin.sin_addr);
        if (l_s != 1)
        {
                printf("error performing inet_pton. Reason: %s\n", strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        l_sin.sin_port = htons(53);
        l_sa = (struct sockaddr const*) &l_sin;
        l_salen = sizeof(l_sin);
        // -------------------------------------------------
        // get source address
        // -------------------------------------------------
        l_s = _get_source_address(l_sa, l_salen, (struct sockaddr*) &l_sas, &l_sslen);
        if (l_s < 0)
        {
                printf("error performing get_source_address\n");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // check for is private
        // see: RFC1918
        // -------------------------------------------------
        uchar_t* l_c = NULL;
        l_c = (uchar_t*) &(((struct sockaddr_in*) &l_sas)->sin_addr);
        uchar_t l_c_0 = l_c[0];
        uchar_t l_c_1 = l_c[1];
        if (
            (l_c_0 == 0)   ||
            (l_c_0 == 127) ||
            (l_c_0 >= 224) ||
            (l_c_0 == 10)  ||
            ((l_c_0 == 172) &&
             (l_c_1 >= 16)  &&
             (l_c_1 <= 31)) ||
            ((l_c_0 == 192) &&
             (l_c_1 == 168))
            )
        {
                printf("error ipv4 appears to be private address (RFC4193)\n");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // copy in
        // -------------------------------------------------
        memcpy(&l_addr, &((struct sockaddr_in*) &l_sas)->sin_addr, 4);
        *a_addr = l_addr;
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int _get_public_address_v6(void *a_addr)
{
        int l_s;
        struct sockaddr_storage l_sas;
        socklen_t l_sslen = sizeof(l_sas);
        struct sockaddr const *l_sa = NULL;
        socklen_t l_salen = 0;
        // -------------------------------------------------
        // make sockaddr_in6
        // -------------------------------------------------
        struct sockaddr_in6 l_sin6;
        memset(&l_sin6, 0, sizeof(l_sin6));
        l_sin6.sin6_family = AF_INET6;
        // -------------------------------------------------
        // any real ipv6 address (not private)
        // -------------------------------------------------
        l_s = inet_pton(AF_INET6, "2607:f8b0:4007:810::200e", &l_sin6.sin6_addr);
        if (l_s != 1)
        {
                printf("error performing inet_pton. Reason: %s\n", strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        l_sin6.sin6_port = htons(6969);
        l_sa = (struct sockaddr const*) &l_sin6;
        l_salen = sizeof(l_sin6);
        // -------------------------------------------------
        // get source address
        // -------------------------------------------------
        l_s = _get_source_address(l_sa, l_salen, (struct sockaddr*) &l_sas, &l_sslen);
        if (l_s < 0)
        {
                printf("error performing get_source_address\n");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // check for is private
        // see: RFC4193
        // -------------------------------------------------
        uchar_t* l_c = NULL;
        l_c = (uchar_t*) &((struct sockaddr_in6*) &l_sas)->sin6_addr;
        uchar_t l_c_0 = l_c[0];
        if ((l_c_0 & 0xE0) != 0x20)
        {
                printf("error ipv6 appears to be private address (RFC4193)\n");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // copy in
        // -------------------------------------------------
        memcpy(a_addr, &((struct sockaddr_in6*) &l_sas)->sin6_addr, 16);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: display public address(es)
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
const char* get_public_address_v6_str(void)
{
        static char s_ipv6_str[INET6_ADDRSTRLEN] = "\0";
        if (strlen(s_ipv6_str) != 0)
        {
                return s_ipv6_str;
        }
        // -------------------------------------------------
        // ipv6
        // -------------------------------------------------
        int l_s;
        uchar_t l_ipv6_addr_str[INET_ADDRSTRLEN];
        l_s = _get_public_address_v6(l_ipv6_addr_str);
        if (l_s != NTRNT_STATUS_OK)
        {
                printf("error performing get_public_address\n");
                return NULL;
        }
        // -------------------------------------------------
        // convert to string
        // -------------------------------------------------
        const char* l_rs;
        errno = 0;
        l_rs = inet_ntop(AF_INET6, l_ipv6_addr_str, s_ipv6_str, INET6_ADDRSTRLEN);
        if (l_rs == NULL)
        {
                printf("error performing inet_ntop:  Reason: %s\n", strerror(errno));
                return NULL;
        }
        printf(": ipv6: %s\n", s_ipv6_str);
        return s_ipv6_str;
}
//! ----------------------------------------------------------------------------
//! \details: display public address(es)
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t display_public_address(void)
{
        printf(": getting public ip address(es)\n");
        // -------------------------------------------------
        // ipv4
        // -------------------------------------------------
        int l_s;
        uint32_t l_ipv4_addr;
        l_s = _get_public_address_v4(&l_ipv4_addr);
        if (l_s != NTRNT_STATUS_OK)
        {
                printf("error performing get_public_address\n");
                goto get_ipv6;
        }
        // -------------------------------------------------
        // convert to string
        // -------------------------------------------------
        char l_ipv4_str[INET_ADDRSTRLEN];
        errno = 0;
        const char* l_rs;
        l_rs = inet_ntop(AF_INET, &l_ipv4_addr, l_ipv4_str, INET_ADDRSTRLEN);
        if (l_rs == NULL)
        {
                printf("error performing inet_ntop:  Reason: %s\n", strerror(errno));
                goto get_ipv6;
        }
        printf(": ipv4: %s\n", l_ipv4_str);
get_ipv6:
        // -------------------------------------------------
        // ipv6
        // -------------------------------------------------
        uchar_t l_ipv6_addr_str[INET_ADDRSTRLEN];
        l_s = _get_public_address_v6(l_ipv6_addr_str);
        if (l_s != NTRNT_STATUS_OK)
        {
                printf("error performing get_public_address\n");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // convert to string
        // -------------------------------------------------
        char l_ipv6_str[INET6_ADDRSTRLEN];
        errno = 0;
        l_rs = inet_ntop(AF_INET6, l_ipv6_addr_str, l_ipv6_str, INET6_ADDRSTRLEN);
        if (l_rs == NULL)
        {
                printf("error performing inet_ntop:  Reason: %s\n", strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        printf(": ipv6: %s\n", l_ipv6_str);
        // -------------------------------------------------
        // done
        // -------------------------------------------------
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
std::string sas_to_str(const struct sockaddr_storage& a_ss)
{
        char l_addr_tmp[40];
        char l_addr_str[64];
        uint16_t l_port = 0;
        std::string l_ip;
        if (a_ss.ss_family == AF_INET)
        {
                struct sockaddr_in* l_sin = (struct sockaddr_in*) &(a_ss);
                inet_ntop(AF_INET, &l_sin->sin_addr, l_addr_tmp, sizeof(l_addr_tmp));
                l_port = ntohs(l_sin->sin_port);
                snprintf(l_addr_str, 64, "%s:%u", l_addr_tmp, l_port);
                l_ip = l_addr_str;
        }
        else if(a_ss.ss_family == AF_INET6)
        {
                struct sockaddr_in6* l_sin6 = (struct sockaddr_in6*) &(a_ss);
                inet_ntop(AF_INET6, &l_sin6->sin6_addr, l_addr_tmp, sizeof(l_addr_tmp));
                l_port = ntohs(l_sin6->sin6_port);
                snprintf(l_addr_str, 64, "[%s]:%u", l_addr_tmp, l_port);
                l_ip = l_addr_str;
        }
        return l_ip;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
std::string sas_to_ip_str(const struct sockaddr_storage& a_ss)
{
        char l_addr_tmp[40];
        char l_addr_str[64];
        std::string l_ip;
        if (a_ss.ss_family == AF_INET)
        {
                struct sockaddr_in* l_sin = (struct sockaddr_in*) &(a_ss);
                inet_ntop(AF_INET, &l_sin->sin_addr, l_addr_tmp, sizeof(l_addr_tmp));
                snprintf(l_addr_str, 64, "%s", l_addr_tmp);
                l_ip = l_addr_str;
        }
        else if(a_ss.ss_family == AF_INET6)
        {
                struct sockaddr_in6* l_sin6 = (struct sockaddr_in6*) &(a_ss);
                inet_ntop(AF_INET6, &l_sin6->sin6_addr, l_addr_tmp, sizeof(l_addr_tmp));
                snprintf(l_addr_str, 64, "%s", l_addr_tmp);
                l_ip = l_addr_str;
        }
        return l_ip;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
#if defined(__APPLE__) || defined(__darwin__)
static void * memrchr(const void *s, int c, size_t n)
{
    const unsigned char *cp;
    if (n != 0)
    {
            cp = (unsigned char *)s + n;
            do
            {
                    if (*(--cp) == (unsigned char)c)
                    {
                            return (void *)cp;
                    }
            } while (--n != 0);
    }
    return (void *)0;
}
#endif
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t str_to_sas(const std::string& a_str, struct sockaddr_storage& a_sas)
{
        // -------------------------------------------------
        // clear
        // -------------------------------------------------
        memset(&a_sas, 0, sizeof(struct sockaddr_storage));
        // -------------------------------------------------
        // family
        // -------------------------------------------------
        int l_family = AF_INET;
        const void* l_ptr = nullptr;
        l_ptr = memchr(a_str.c_str(), '[', (int)a_str.length());
        if (l_ptr)
        {
                l_family = AF_INET6;
        }
        // -------------------------------------------------
        // find port part
        // -------------------------------------------------
        l_ptr = memrchr(a_str.c_str(), ':', (int)a_str.length());
        if (!l_ptr)
        {
                return NTRNT_STATUS_ERROR;
        }
        int l_val;
        l_val = atoi(((char*)l_ptr)+1);
        if((l_val < 1) ||
           (l_val > 65535))
        {
                return NTRNT_STATUS_ERROR;
        }
        uint16_t l_port = 0;
        l_port = (uint16_t)l_val;
        // -------------------------------------------------
        // ipv4
        // -------------------------------------------------
        if (l_family == AF_INET)
        {
                a_sas.ss_family = AF_INET;
                size_t l_len = (char*)l_ptr - a_str.data();
                std::string l_str;
                l_str.assign(a_str.c_str(), l_len);
                struct sockaddr_in* l_sa = (struct sockaddr_in*)(&a_sas);
                int l_s;
                l_s = inet_pton(AF_INET, l_str.c_str(), &(l_sa->sin_addr));
                if (l_s != 1)
                {
                        return NTRNT_STATUS_ERROR;
                }
                l_sa->sin_port = htons(l_port);
        }
        // -------------------------------------------------
        // ipv6
        // -------------------------------------------------
        else
        {
                a_sas.ss_family = AF_INET6;
                // -----------------------------------------
                // skip [ ... ] chars
                // -----------------------------------------
                size_t l_len = (char*)l_ptr - a_str.data() - 2;
                std::string l_str;
                l_str.assign(a_str.c_str()+1, l_len);
                struct sockaddr_in6* l_sa = (struct sockaddr_in6*)(&a_sas);
                int l_s;
                l_s = inet_pton(AF_INET6, l_str.c_str(), &(l_sa->sin6_addr));
                if (l_s != 1)
                {
                        return NTRNT_STATUS_ERROR;
                }
                l_sa->sin6_port = htons(l_port);
        }
        return NTRNT_STATUS_OK;
}
}
//! ----------------------------------------------------------------------------
//! main
//! ----------------------------------------------------------------------------
#ifdef NET_UTIL_MAIN
int main(void)
{
        int l_s;
        l_s = ns_ntrnt::display_public_address();
        if (l_s != NTRNT_STATUS_OK)
        {
                printf("error performing display_public_address\n");
                return NTRNT_STATUS_ERROR;
        }
        return 0;
}
#endif
