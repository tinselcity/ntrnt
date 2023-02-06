#ifndef _NTRNT_HTTP_RESP_STRS_H
#define _NTRNT_HTTP_RESP_STRS_H
//! ----------------------------------------------------------------------------
//! Includes
//! ----------------------------------------------------------------------------
#include <string>
#include <map>
//! ----------------------------------------------------------------------------
//! Macros
//! ----------------------------------------------------------------------------
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! http_resp strings
//! ----------------------------------------------------------------------------
class http_resp_strs
{
public:
        // -------------------------------------------------
        // Types
        // -------------------------------------------------
        typedef std::map<uint16_t, std::string> code_resp_map_t;
        // -------------------------------------------------
        // ext->type pair
        // -------------------------------------------------
        struct T
        {
                uint16_t m_http_status_code;
                const char* m_resp_str;
                operator code_resp_map_t::value_type() const
                {
                        return std::pair<uint16_t, std::string>(m_http_status_code, m_resp_str);
                }
        };
        // -------------------------------------------------
        // Private class members
        // -------------------------------------------------
        static const T S_CODE_RESP_PAIRS[];
        static const code_resp_map_t S_CODE_RESP_MAP;
};
//! ----------------------------------------------------------------------------
//! Generated file extensions -> mime types associations
//! ----------------------------------------------------------------------------
const http_resp_strs::T http_resp_strs::S_CODE_RESP_PAIRS[] =
{
#include "_http_resp_strs.h"
};
//! ----------------------------------------------------------------------------
//! Map
//! ----------------------------------------------------------------------------
const http_resp_strs::code_resp_map_t http_resp_strs::S_CODE_RESP_MAP(S_CODE_RESP_PAIRS,
                                                                      S_CODE_RESP_PAIRS +
                                                                      ARRAY_SIZE(http_resp_strs::S_CODE_RESP_PAIRS));
} 
#endif
