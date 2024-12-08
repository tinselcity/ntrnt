//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "conn/host_info.h"
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
host_info::host_info()
    : m_sa(),
      m_sa_len(16),
      m_sock_family(AF_INET),
      m_sock_type(SOCK_STREAM),
      m_sock_protocol(IPPROTO_TCP),
      m_expires_s(0) {
  ((struct sockaddr_in*)(&m_sa))->sin_family = AF_INET;
};
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void host_info::show(void) {
  char l_hoststr[NI_MAXHOST] = "";
  char l_portstr[NI_MAXSERV] = "";
  int32_t l_s;
  l_s = getnameinfo((struct sockaddr*)&m_sa, sizeof(struct sockaddr_storage),
                    l_hoststr, sizeof(l_hoststr), l_portstr, sizeof(l_portstr),
                    NI_NUMERICHOST | NI_NUMERICSERV);
  if (l_s != 0) {
    // TODO???
  }
  printf("+-----------+\n");
  printf("| Host Info |\n");
  printf("+-----------+-------------------------\n");
  printf(": address:         %s:%s\n", l_hoststr, l_portstr);
  printf(": m_sock_family:   %d\n", m_sock_family);
  printf(": m_sock_type:     %d\n", m_sock_type);
  printf(": m_sock_protocol: %d\n", m_sock_protocol);
  printf(": m_sa_len:        %d\n", m_sa_len);
  printf(": m_expires:       %u\n", m_expires_s);
  printf("+-------------------------------------\n");
}
}  // namespace ns_ntrnt
