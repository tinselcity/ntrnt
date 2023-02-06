#ifndef _NTRNT_HOST_INFO_H
#define _NTRNT_HOST_INFO_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <sys/socket.h>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: Host info
//! ----------------------------------------------------------------------------
struct host_info {
        struct sockaddr_storage m_sa;
        int m_sa_len;
        int m_sock_family;
        int m_sock_type;
        int m_sock_protocol;
        unsigned int m_expires_s;
        host_info();
        void show(void);
};
}
#endif
