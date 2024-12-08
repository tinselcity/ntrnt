//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "evr/evr_epoll.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include "ntrnt/def.h"
#include "support/ndebug.h"
#include "support/trace.h"
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
evr_epoll::evr_epoll(void) : m_fd(-1), m_ctrl_fd(-1) {
  m_fd = epoll_create1(0);
  if (m_fd == -1) {
    TRC_ERROR("epoll_create() failed: %s\n", strerror(errno));
    exit(-1);
  }
  // Create ctrl fd
  m_ctrl_fd = eventfd(0, EFD_NONBLOCK);
  if (m_ctrl_fd == -1) {
    TRC_ERROR("eventfd() failed: %s\n", strerror(errno));
    exit(-1);
  }

  int32_t l_status = 0;
  l_status =
      add(m_ctrl_fd, EVR_FILE_ATTR_MASK_READ | EVR_FILE_ATTR_MASK_ET, NULL);
  if (l_status != 0) {
    TRC_ERROR("failed to add ctrl fd.\n");
    exit(-1);
  }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int evr_epoll::wait(evr_events_t* a_ev, int a_max_events, int a_timeout_msec) {
  int l_s = 0;
  // -------------------------------------------------
  // loop over EINTR
  // -------------------------------------------------
  do {
    errno = 0;
    l_s = epoll_wait(m_fd, (epoll_event*)a_ev, a_max_events, a_timeout_msec);
  } while ((l_s < 0) && (errno == EINTR));
  if (l_s < 0) {
    TRC_ERROR("reason[%d] EINTR: %d: %s\n", errno, EINTR, strerror(errno));
  }
  return l_s;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static inline uint32_t get_epoll_attr(uint32_t a_attr_mask) {
  uint32_t l_attr = 0;
  if (a_attr_mask & EVR_FILE_ATTR_MASK_READ)
    l_attr |= EPOLLIN;
  if (a_attr_mask & EVR_FILE_ATTR_MASK_WRITE)
    l_attr |= EPOLLOUT;
  if (a_attr_mask & EVR_FILE_ATTR_MASK_STATUS_ERROR)
    l_attr |= EPOLLERR;
  if (a_attr_mask & EVR_FILE_ATTR_MASK_RD_HUP)
    l_attr |= EPOLLRDHUP;
  if (a_attr_mask & EVR_FILE_ATTR_MASK_HUP)
    l_attr |= EPOLLRDHUP;
  if (a_attr_mask & EVR_FILE_ATTR_MASK_ET)
    l_attr |= EPOLLET;
  return l_attr;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int evr_epoll::add(int a_fd, uint32_t a_attr_mask, evr_fd_t* a_evr_fd_event) {
  struct epoll_event ev;
  ev.events = get_epoll_attr(a_attr_mask);
  ev.data.ptr = a_evr_fd_event;
  if (0 != epoll_ctl(m_fd, EPOLL_CTL_ADD, a_fd, &ev)) {
    //TRC_ERROR("epoll_fd[%d] EPOLL_CTL_ADD fd[%d] failed (%s)\n",
    //           m_fd, a_fd, strerror(errno));
    return NTRNT_STATUS_ERROR;
  }
  return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int evr_epoll::mod(int a_fd, uint32_t a_attr_mask, evr_fd_t* a_evr_fd_event) {
  struct epoll_event l_ev;
  l_ev.events = get_epoll_attr(a_attr_mask);
  l_ev.data.ptr = a_evr_fd_event;
  if (0 != epoll_ctl(m_fd, EPOLL_CTL_MOD, a_fd, &l_ev)) {
    TRC_ERROR("epoll_fd[%d] EPOLL_CTL_MOD fd[%d] failed (%s)\n", m_fd, a_fd,
              strerror(errno));
    return NTRNT_STATUS_ERROR;
  }
  return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int evr_epoll::del(int a_fd) {
  // TODO Can skip del for close(fd) -since is removed automagically
  struct epoll_event ev;
  if ((m_fd > 0) && (a_fd > 0)) {
    if (0 != epoll_ctl(m_fd, EPOLL_CTL_DEL, a_fd, &ev)) {
      TRC_ERROR("epoll_fd[%d] EPOLL_CTL_DEL fd[%d] failed (%s)\n", m_fd, a_fd,
                strerror(errno));
      return NTRNT_STATUS_ERROR;
    }
  }
  return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t evr_epoll::signal(void) {
  // Wake up epoll_wait by writing to control fd
  uint64_t l_value = 1;
  ssize_t l_write_status = 0;
  l_write_status = write(m_ctrl_fd, &l_value, sizeof(l_value));
  if (l_write_status == -1) {
    //TRC_ERROR("performing write\n");
    return NTRNT_STATUS_ERROR;
  }
  return NTRNT_STATUS_OK;
}
}  // namespace ns_ntrnt
