#ifndef _NTRNT_SCHEME_H
#define _NTRNT_SCHEME_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <string>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! enums
//! ----------------------------------------------------------------------------
// Schemes
typedef enum scheme_enum {
        SCHEME_NONE = 0,
        SCHEME_TCP,
        SCHEME_TLS,
        SCHEME_UDP,
        SCHEME_WSS
} scheme_t;
//! ----------------------------------------------------------------------------
//! prototypes
//! ----------------------------------------------------------------------------
scheme_t get_scheme(const std::string &a_str);
std::string get_scheme_str(scheme_t a_scheme);
}
#endif
