#ifndef _NTRNT_NBQ_H
#define _NTRNT_NBQ_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stddef.h>
#include <sys/types.h>
#include <list>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! internal fwd decl's
//! ----------------------------------------------------------------------------
struct nb_struct;
typedef struct nb_struct nb_t;
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::list <nb_t*> nb_list_t;
//! ----------------------------------------------------------------------------
//! callbacks
//! ----------------------------------------------------------------------------
typedef int32_t (*nbq_filter_cb_t)(void*, char*, size_t);
//! ----------------------------------------------------------------------------
//! \details: nbq
//! ----------------------------------------------------------------------------
class nbq
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        nbq(size_t a_bsize);
        ~nbq();
        // -------------------------------------------------
        // writing...
        // -------------------------------------------------
        off_t write(const char* a_buf, size_t a_len);
        off_t write_fd(int a_fd, size_t a_len, ssize_t& a_status);
        off_t write_q(nbq& a_q);
        // -------------------------------------------------
        // network ordered writes
        // -------------------------------------------------
        off_t write_n32(uint32_t a_val);
        off_t write_n16(uint16_t a_val);
        off_t write_n8(uint8_t a_val);
        // -------------------------------------------------
        // reading
        // -------------------------------------------------
        off_t read(char* a_buf, size_t a_len);
        size_t read_seek(size_t a_off);
        size_t read_from(size_t a_off, char* a_buf, size_t a_len);
        size_t read_avail(void) const {return m_total_read_avail;}
        char peek(void) const;
        bool starts_with(const char* a_buf, size_t a_len) const;
        off_t discard(size_t a_len);
        // -------------------------------------------------
        // resetting...
        // -------------------------------------------------
        void reset_read(void);
        void reset_write(void);
        void reset(void);
        // -------------------------------------------------
        // shrink -free all read blocks
        // -------------------------------------------------
        void shrink(void);
        // -------------------------------------------------
        // split and create separate nbq with tail at offset
        // -------------------------------------------------
        int32_t split(nbq** ao_nbq_tail, size_t a_offset);
        // -------------------------------------------------
        // join nbq with reference nbq
        // -------------------------------------------------
        int32_t join_ref(const nbq& ao_nbq_tail);
        // -------------------------------------------------
        // block writing...
        // -------------------------------------------------
        char*  b_write_ptr(void);
        char*  b_write_data_ptr(void);
        size_t b_write_avail(void);
        int32_t b_write_add_avail();
        void b_write_incr(size_t a_len);
        // -------------------------------------------------
        // block reading...
        // -------------------------------------------------
        char* b_read_ptr(void) const;
        int32_t b_read_avail(void) const;
        void b_read_incr(size_t a_len);
        // -------------------------------------------------
        // debugging/display
        // -------------------------------------------------
        void b_display_all(void);
        void b_display_written(void);
        // -------------------------------------------------
        // for use with obj pool
        // -------------------------------------------------
        size_t get_idx(void) {return m_idx;}
        void set_idx(size_t a_idx) {m_idx = a_idx;}
        // -------------------------------------------------
        // inline
        // -------------------------------------------------
        size_t get_cur_write_offset(void) { return m_cur_write_offset;}
        bool read_avail_is_max_limit(void)
        {
                if((m_max_read_queue > 0) &&
                   (m_total_read_avail >= (size_t)m_max_read_queue))
                {
                        return true;
                }
                return false;
        }
        // set max read size
        off_t get_max_read_queue(void) { return m_max_read_queue; }
        void set_max_read_queue(off_t a_val) {m_max_read_queue = a_val; }
        void set_filter_cb(nbq_filter_cb_t a_cb, void* a_ctx) { m_filter_cb = a_cb; m_filter_ctx = a_ctx;}
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // Disallow copy/assign
        nbq& operator=(const nbq& );
        nbq(const nbq& );
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        // Block list
        nb_list_t m_q;
        // Block size
        size_t m_bsize;
        // cur write/read blocks
        nb_list_t::iterator m_cur_write_block;
        nb_list_t::iterator m_cur_read_block;
        // For use with obj pool
        size_t m_idx;
        // internal acct'ing
        size_t m_cur_write_offset;
        size_t m_total_read_avail;
        off_t m_max_read_queue;
        nbq_filter_cb_t m_filter_cb;
        void* m_filter_ctx;
};
//! ----------------------------------------------------------------------------
//! util
//! ----------------------------------------------------------------------------
char* copy_part(nbq& a_nbq, size_t a_off, size_t a_len);
void print_part(nbq& a_nbq, size_t a_off, size_t a_len);
} // ns_ntrnt
#endif
