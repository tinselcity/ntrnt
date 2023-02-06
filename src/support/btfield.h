#ifndef _NTRNT_BTFIELD_H
#define _NTRNT_BTFIELD_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "ntrnt/types.h"
#include <stdint.h>
#include <string>
#include <vector>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \class: torrent
//! ----------------------------------------------------------------------------
class btfield {
public:
        // -------------------------------------------------
        // public types
        // -------------------------------------------------
        typedef std::vector<bool> flag_vector_t;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        btfield(uint32_t a_size=0);
        ~btfield(void);
        int32_t set(size_t a_bit, bool a_flag);
        bool test(size_t a_bit) const;
        size_t get_count(void);
        bool has_all(void);
        bool has_none(void);
        size_t get_size(void) const { return m_bits.size(); }
        void set_size(size_t a_len);
        void clear_all(void);
        int32_t import_raw(const uint8_t* a_buf, size_t a_len, size_t a_bit_len);
        int32_t export_raw(uint8_t** ao_buf, size_t& ao_len);
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // disallow copy/assign
        btfield(const btfield&);
        btfield& operator=(const btfield&);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        flag_vector_t m_bits;
        uint8_t* m_raw;
        size_t m_raw_len;
        bool m_dirty;
};
}
#endif
