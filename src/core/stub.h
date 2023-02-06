#ifndef _NTRNT_STUB_H
#define _NTRNT_STUB_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include "ntrnt/types.h"
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \class: tracker
//! ----------------------------------------------------------------------------
class stub {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        stub(void);
        ~stub(void);
        int32_t init(const std::string& a_file, size_t a_len);
        // -------------------------------------------------
        // writing/reading/validating
        // -------------------------------------------------
        int32_t write(const uint8_t* a_buf, size_t a_off, size_t a_len);
        int32_t read(uint8_t* ao_buf, size_t a_off, size_t a_len);
        int32_t calc_sha1(id_t& ao_sha1, size_t a_off, size_t a_len);
        // TODO fix for multifile
        void* get_buf(void) { return m_buf; }
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // disallow copy/assign
        stub(const stub&);
        stub& operator=(const stub&);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        std::string m_file;
        size_t m_len;
        int m_fd;
        void* m_buf;
};
}
#endif
