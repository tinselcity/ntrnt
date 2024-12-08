#ifndef _NTRNT_CR_H
#define _NTRNT_CR_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
// For fixed size types
#include <stdint.h>
#include <list>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! Raw buffer
//! ----------------------------------------------------------------------------
typedef struct cr_struct {
  uint64_t m_off;
  uint64_t m_len;
  cr_struct() : m_off(0), m_len(0) {}
  void clear(void) {
    m_off = 0;
    m_len = 0;
  }
} cr_t;
typedef std::list<cr_t> cr_list_t;
}  // namespace ns_ntrnt
#endif
