#ifndef _TRACKER_UDP_H
#define _TRACKER_UDP_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include <string>
#include "ntrnt/types.h"
#include "tracker/tracker.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \class: tracker_udp
//! ----------------------------------------------------------------------------
class tracker_udp: public tracker {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        tracker_udp(void);
        ~tracker_udp(void);
        int32_t init(const char* a_str, size_t a_str_len);
        virtual int32_t announce(session& a_session, torrent& a_torrent);
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // disallow copy/assign
        tracker_udp(const tracker_udp&);
        tracker_udp& operator=(const tracker_udp&);
};
}
#endif
