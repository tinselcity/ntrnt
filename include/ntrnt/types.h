#ifndef _NTRNT_TYPES_H
#define _NTRNT_TYPES_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <string>
#include <list>
#include <vector>
#include <cstdint>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::list<std::string> str_list_t;
typedef struct { uint8_t m_data[20]; } id_t;
typedef struct { uint8_t m_data[20]; } peer_id_t;
typedef std::vector<id_t> id_vector_t;
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef struct _files {
        std::list<std::string> m_path;
        size_t m_len;
        _files():
                m_path(),
                m_len(0)
        {}
} files_t;
typedef std::list<files_t> files_list_t;
}
#endif
