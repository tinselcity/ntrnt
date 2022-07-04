#ifndef _TRACKER_H
#define _TRACKER_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include <string>
#include "ntrnt/types.h"
#include "conn/scheme.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class torrent;
class session;
//! ----------------------------------------------------------------------------
//! \class: tracker
//! ----------------------------------------------------------------------------
class tracker {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        tracker(void);
        ~tracker(void);
        virtual int32_t announce(session& a_session, torrent& a_torrent) = 0;
        void display(void);
        std::string str(void);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        std::string m_announce;
        scheme_t m_scheme;
        std::string m_host;
        uint16_t m_port;
        std::string m_root;
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // -------------------------------------------------
        // disallow copy/assign
        // -------------------------------------------------
        tracker(const tracker&);
        tracker& operator=(const tracker&);
};
//! ----------------------------------------------------------------------------
//! prototypes
//! ----------------------------------------------------------------------------
int32_t init_tracker_w_url(tracker** ao_tracker, const char* a_url, size_t a_url_len);
void http_escape(std::string& ao_out, std::string a_in, bool a_escp_rsvd);
void encode_digest(char* a_out, const uint8_t* a_digest, size_t a_digest_len);
}
#endif
