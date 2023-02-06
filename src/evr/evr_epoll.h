#ifndef _NTRNT_EVR_EPOLL_H
#define _NTRNT_EVR_EPOLL_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "evr/evr.h"
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! fwd Decl's
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
class evr_epoll: public evr
{
public:
        evr_epoll(void);
        int wait(evr_events_t* a_ev, int a_max_events, int a_timeout_msec);
        int add(int a_fd, uint32_t a_attr_mask, evr_fd_t *a_evr_fd_event);
        int mod(int a_fd, uint32_t a_attr_mask, evr_fd_t *a_evr_fd_event);
        int del(int a_fd);
        int signal(void);
private:
        // Disallow copy/assign
        evr_epoll& operator=(const evr_epoll &);
        evr_epoll(const evr_epoll &);
        int m_fd;
        int m_ctrl_fd;
};
} //namespace ns_ntrnt {
#endif
