//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
// ---------------------------------------------------------
// this app
// ---------------------------------------------------------
#include "upnp.h"
// ---------------------------------------------------------
// std includes
// ---------------------------------------------------------
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define BUFSIZE 1024
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t echo_server(uint16_t a_port) {
  NDBG_PRINT(": echoserver starting on port: %u\n", a_port);
  int listenfd;
  int connfd;
  uint32_t clientlen;
  struct sockaddr_in serveraddr;
  struct sockaddr_in clientaddr;
  struct hostent* hostp;
  char buf[BUFSIZE];
  char* hostaddrp;
  int optval;
  int n;
  listenfd = socket(AF_INET, SOCK_STREAM, 0);
  if (listenfd < 0) {
    NDBG_PRINT("ERROR opening socket");
    return NTRNT_STATUS_ERROR;
  }
  optval = 1;
  setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void*)&optval,
             sizeof(int));
  bzero((char*)&serveraddr, sizeof(serveraddr));
  serveraddr.sin_family = AF_INET;
  serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
  serveraddr.sin_port = htons((unsigned short)a_port);
  if (bind(listenfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0) {
    NDBG_PRINT("ERROR on binding");
    return NTRNT_STATUS_ERROR;
  }
  if (listen(listenfd, 5) < 0) {
    NDBG_PRINT("ERROR on listen");
    return NTRNT_STATUS_ERROR;
  }
  clientlen = sizeof(clientaddr);
  while (1) {
    connfd = accept(listenfd, (struct sockaddr*)&clientaddr, &clientlen);
    if (connfd < 0) {
      NDBG_PRINT("ERROR on accept");
      return NTRNT_STATUS_ERROR;
    }
    hostp = gethostbyaddr((const char*)&clientaddr.sin_addr.s_addr,
                          sizeof(clientaddr.sin_addr.s_addr), AF_INET);
    if (hostp == NULL) {
      NDBG_PRINT("ERROR on gethostbyaddr");
      return NTRNT_STATUS_ERROR;
    }
    hostaddrp = inet_ntoa(clientaddr.sin_addr);
    if (hostaddrp == NULL) {
      NDBG_PRINT("ERROR on inet_ntoa\n");
      return NTRNT_STATUS_ERROR;
    }
    NDBG_OUTPUT(": server established connection with %s (%s)\n", hostp->h_name,
                hostaddrp);
    bzero(buf, BUFSIZE);
    n = read(connfd, buf, BUFSIZE);
    if (n < 0) {
      NDBG_PRINT("ERROR reading from socket");
      return NTRNT_STATUS_ERROR;
    }
    NDBG_OUTPUT(": server received %d bytes: %s\n", n, buf);
    n = write(connfd, buf, strlen(buf));
    if (n < 0) {
      NDBG_PRINT("ERROR writing to socket");
      return NTRNT_STATUS_ERROR;
    }
    close(connfd);
  }
  return NTRNT_STATUS_OK;
}
