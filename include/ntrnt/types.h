#ifndef _NTRNT_TYPES_H
#define _NTRNT_TYPES_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <string>
#include <list>
#include <vector>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::list<std::string> str_list_t;
typedef struct { uint8_t m_data[20]; } id_t;
typedef struct { uint8_t m_data[20]; } peer_id_t;
typedef std::vector<id_t> id_vector_t;
}
#endif
