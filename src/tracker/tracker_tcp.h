#ifndef _TRACKER_TCP_H
#define _TRACKER_TCP_H
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
//! \class: tracker_tcp
//! ----------------------------------------------------------------------------
class tracker_tcp: public tracker {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        tracker_tcp(void);
        ~tracker_tcp(void);
        int32_t init(const char* a_str, size_t a_str_len);
        virtual int32_t announce(session& a_session, torrent& a_torrent);
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // disallow copy/assign
        tracker_tcp(const tracker_tcp&);
        tracker_tcp& operator=(const tracker_tcp&);
};
}
#endif
