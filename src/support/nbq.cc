//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "ntrnt/def.h"
#include "support/ndebug.h"
#include "support/nbq.h"
#include "support/trace.h"
// ---------------------------------------------------------
// system includes
// ---------------------------------------------------------
#include <string.h>
#include <unistd.h>
// for ntohl and friends
#include <arpa/inet.h>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! Macros
//! ----------------------------------------------------------------------------
#define CHECK_FOR_NULL_AND_LEN(_buf, _len) do{ \
                if (!_buf) { return -1; } \
                if (!_len) { return 0; } \
        } while(0)
//! ----------------------------------------------------------------------------
//! \details: nbq
//! ----------------------------------------------------------------------------
typedef struct nb_struct {
        // -------------------------------------------------
        // std constructor
        // -------------------------------------------------
        nb_struct(size_t a_len):
                m_data(nullptr),
                m_len(a_len),
                m_written(0),
                m_read(0),
                m_ref(false)
        {
        }
        // -------------------------------------------------
        // std constructor
        // -------------------------------------------------
        nb_struct(char* a_buf, size_t a_len):
                m_data(a_buf),
                m_len(a_len),
                m_written(a_len),
                m_read(0),
                m_ref(true)
        {}
        // -------------------------------------------------
        // destructor
        // -------------------------------------------------
        ~nb_struct(void)
        {
                if (m_data &&
                    !m_ref)
                {
                        free(m_data);
                }
                m_data = nullptr;
                m_len = 0;
        }
        void init(void)
        {
                if (!m_data)
                {
                        m_data = (char* )malloc(m_len);
                }
        }
        size_t write_avail(void) { return m_len - m_written;}
        size_t read_avail(void) { return m_written - m_read;}
        char* data(void) { return m_data; }
        bool ref(void) const { return m_ref; }
        size_t size(void) { return m_len; }
        size_t written(void) { return m_written; }
        char* write_ptr(void) { return m_data + m_written; }
        void write_inc(size_t a_inc) { m_written += a_inc; }
        void write_reset(void) { m_written = 0; m_read = 0;}
        char* read_ptr(void) { return m_data + m_read; }
        void read_inc(size_t a_inc) { m_read += a_inc; }
        void read_reset(void) { m_read = 0; }
private:
        // Disallow copy/assign
        nb_struct& operator=(const nb_struct &);
        nb_struct(const nb_struct &);
        char* m_data;
        size_t m_len;
        size_t m_written;
        size_t m_read;
        bool m_ref;
} nb_t;
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
nbq::nbq(size_t a_bsize):
        m_q(),
        m_bsize(a_bsize),
        m_cur_write_block(),
        m_cur_read_block(),
        m_idx(0),
        m_cur_write_offset(0),
        m_total_read_avail(0),
        m_max_read_queue(-1),
        m_filter_cb(),
        m_filter_ctx(nullptr)
{
        m_cur_write_block = m_q.end();
        m_cur_read_block = m_q.end();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
nbq::~nbq(void)
{
        for(nb_list_t::iterator i_b = m_q.begin(); i_b != m_q.end(); ++i_b)
        {
                if (*i_b)
                {
                        delete *i_b;
                }
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
off_t nbq::write(const char* a_buf, size_t a_len)
{
        CHECK_FOR_NULL_AND_LEN(a_buf, a_len);
        size_t l_left = a_len;
        size_t l_written = 0;
        const char* l_buf = a_buf;
        // -------------------------------------------------
        // while left...
        // -------------------------------------------------
        while(l_left)
        {
                // -----------------------------------------
                // check write available
                // -----------------------------------------
                if (b_write_avail() <= 0)
                {
                        int32_t l_s = b_write_add_avail();
                        if (l_s <= 0)
                        {
                                TRC_ERROR("error performing b_write_add_avail\n");
                                return -1;
                        }
                }
                size_t l_write_avail = b_write_avail();
                size_t l_write = (l_left > l_write_avail)?l_write_avail:l_left;
                // -----------------------------------------
                // copy in
                // -----------------------------------------
                memcpy(b_write_ptr(), l_buf, l_write);
                // -----------------------------------------
                // apply filter if exist
                // -----------------------------------------
                if (m_filter_cb)
                {
                        int32_t l_fs;
                        l_fs = m_filter_cb(m_filter_ctx, b_write_ptr(), l_write);
                        UNUSED(l_fs);
                }
                // -----------------------------------------
                // update counts
                // -----------------------------------------
                b_write_incr(l_write);
                l_left -= l_write;
                l_buf += l_write;
                l_written += l_write;
        }
        return l_written;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
off_t nbq::write_fd(int a_fd, size_t a_len, ssize_t &a_status)
{
        if (!a_len)
        {
                return 0;
        }
        size_t l_left = a_len;
        size_t l_written = 0;
        // -------------------------------------------------
        // while left...
        // -------------------------------------------------
        while(l_left)
        {
                // -----------------------------------------
                // check write available
                // -----------------------------------------
                if (b_write_avail() <= 0)
                {
                        int32_t l_s = b_write_add_avail();
                        if (l_s <= 0)
                        {
                                // TODO error...
                                return -1;
                        }
                }
                size_t l_write_avail = b_write_avail();
                size_t l_write = (l_left > l_write_avail)?l_write_avail:l_left;
                errno = 0;
                // -----------------------------------------
                // read from fd
                // -----------------------------------------
                a_status = ::read(a_fd, b_write_ptr(), l_write);
                if (a_status > 0)
                {
                        // ---------------------------------
                        // apply filter if exist
                        // ---------------------------------
                        if (m_filter_cb)
                        {
                                int32_t l_fs;
                                l_fs = m_filter_cb(m_filter_ctx, b_write_ptr(), (size_t)a_status);
                                UNUSED(l_fs);
                        }
                        // ---------------------------------
                        // update ptrs
                        // ---------------------------------
                        b_write_incr(a_status);
                        b_read_incr(0);
                        l_left -= a_status;
                        l_written += a_status;
                }
                else if ((a_status == 0) ||
                         ((a_status < 0) &&
                          (errno == EAGAIN)))
                {
                        break;
                }
                else if (a_status < 0)
                {
                        return NTRNT_STATUS_ERROR;
                }
        }
        return l_written;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
off_t nbq::write_q(nbq& a_q)
{
        size_t l_left = a_q.read_avail();
        size_t l_written = 0;
        // -------------------------------------------------
        // while left...
        // -------------------------------------------------
        while(l_left)
        {
                // -----------------------------------------
                // check write available
                // -----------------------------------------
                if (b_write_avail() <= 0)
                {
                        int32_t l_s = b_write_add_avail();
                        if (l_s <= 0)
                        {
                                TRC_ERROR("b_write_add_avail()\n");
                                return NTRNT_STATUS_ERROR;
                        }
                }
                size_t l_write_avail = b_write_avail();
                size_t l_write = (l_left > l_write_avail)?l_write_avail:l_left;
                // -----------------------------------------
                // read from q
                // -----------------------------------------
                ssize_t l_s = a_q.read(b_write_ptr(), l_write);
                if (l_s < 0)
                {
                        TRC_ERROR("a_q.read()\n");
                        return NTRNT_STATUS_ERROR;
                }
                if (l_s == 0)
                {
                        break;
                }
                // -----------------------------------------
                // apply filter if exist
                // -----------------------------------------
                if (m_filter_cb)
                {
                        int32_t l_fs;
                        l_fs = m_filter_cb(m_filter_ctx, b_write_ptr(), (size_t)l_s);
                        UNUSED(l_fs);
                }
                b_write_incr(l_s);
                l_left -= l_s;
                l_written += l_s;
        }
        return l_written;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
off_t nbq::write_n32(uint32_t a_val)
{
        uint32_t l_val;
        l_val = htonl(a_val);
        return write((const char*)(&l_val), sizeof(l_val));
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
off_t nbq::write_n16(uint16_t a_val)
{
        uint16_t l_val;
        l_val = htons(a_val);
        return write((const char*)(&l_val), sizeof(l_val));
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
off_t nbq::write_n8(uint8_t a_val)
{
        return write((const char*)(&a_val), sizeof(a_val));
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
char nbq::peek(void) const
{
        if (read_avail())
        {
                return *b_read_ptr();
        }
        return '\0';
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
bool nbq::starts_with(const char* a_buf, size_t a_len) const
{
        if (b_read_avail() < 0)
        {
                return false;
        }
        if ((size_t)b_read_avail() < a_len)
        {
                return false;
        }
        if (memcmp(b_read_ptr(), a_buf, a_len) == 0)
        {
                return true;
        }
        return false;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
off_t nbq::read(char* a_buf, size_t a_len)
{
        if (!a_len)
        {
                return 0;
        }
        size_t l_read = 0;
        char* l_buf = a_buf;
        size_t l_total_read_avail = read_avail();
        size_t l_left = (a_len > l_total_read_avail)?l_total_read_avail:a_len;
        while(l_left)
        {
                size_t l_read_avail = b_read_avail();
                size_t l_read_size = (l_left > l_read_avail)?l_read_avail:l_left;
                if (l_buf)
                {
                        memcpy(l_buf, b_read_ptr(), l_read_size);
                        l_buf += l_read_size;
                }
                b_read_incr(l_read_size);
                l_left -= l_read_size;
                l_read += l_read_size;
        }
        return l_read;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
off_t nbq::discard(size_t a_len)
{
        if (!a_len)
        {
                return 0;
        }
        size_t l_read = 0;
        size_t l_total_read_avail = read_avail();
        size_t l_left = (a_len > l_total_read_avail)?l_total_read_avail:a_len;
        while(l_left)
        {
                size_t l_read_avail = b_read_avail();
                size_t l_read_size = (l_left > l_read_avail)?l_read_avail:l_left;
                b_read_incr(l_read_size);
                l_left -= l_read_size;
                l_read += l_read_size;
        }
        return l_read;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
size_t nbq::read_seek(size_t a_off)
{
        reset_read();
        return read(nullptr, a_off);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
size_t nbq::read_from(size_t a_off, char* a_buf, size_t a_len)
{
        read_seek(a_off);
        return read(a_buf, a_len);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void nbq::reset_read(void)
{
        // reset read ptrs and recalc read available
        m_total_read_avail = 0;
        for(nb_list_t::const_iterator i_b = m_q.begin();
            i_b != m_q.end();
            ++i_b)
        {
                (*i_b)->read_reset();
                m_total_read_avail += (*i_b)->read_avail();
        }
        m_cur_read_block = m_q.begin();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void nbq::reset_write(void)
{
        for(nb_list_t::iterator i_b = m_q.begin();
            i_b != m_q.end();
            )
        {
                if (!(*i_b))
                {
                        ++i_b;
                        continue;
                }
                // erase references
                if ((*i_b)->ref())
                {
                        delete (*i_b);
                        (*i_b) = nullptr;
                        m_q.erase(i_b++);
                }
                else
                {
                        (*i_b)->write_reset();
                        ++i_b;
                }
        }
        m_cur_write_block = m_q.begin();
        m_cur_read_block = m_q.begin();
        m_total_read_avail = 0;
        m_cur_write_offset = 0;
        m_filter_cb = nullptr;
        m_filter_ctx = nullptr;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void nbq::reset(void)
{
        for(nb_list_t::iterator i_b = m_q.begin();
            i_b != m_q.end();
            ++i_b)
        {
                if (*i_b)
                {
                        delete *i_b;
                        *i_b = nullptr;
                }
        }
        m_q.clear();
        m_cur_write_block = m_q.end();
        m_cur_read_block = m_q.end();
        m_cur_write_offset = 0;
        m_total_read_avail = 0;
        m_filter_cb = nullptr;
        m_filter_ctx = nullptr;
}
//! ----------------------------------------------------------------------------
//! \details: Free all read
//! \return:  NA
//! \param:   NA
//! ----------------------------------------------------------------------------
void nbq::shrink(void)
{
        while(m_q.begin() != m_cur_read_block)
        {
                nb_t *l_nb = m_q.front();
                if (!l_nb)
                {
                        TRC_ERROR("l_nb == nullptr\n");
                        return;
                }
                m_q.pop_front();
                m_cur_write_offset -= l_nb->size();
                delete l_nb;
                l_nb = nullptr;
        }
        if ((m_cur_read_block != m_q.end()) &&
           (m_cur_write_block != m_q.end()) &&
           (*m_cur_read_block == *m_cur_write_block))
        {
                nb_t *l_nb = (*m_cur_read_block);
                if ((l_nb->read_avail() == 0) &&
                   (l_nb->write_avail() == 0))
                {
                        delete l_nb;
                        l_nb = nullptr;
                        m_q.clear();
                        m_cur_write_block = m_q.end();
                        m_cur_read_block = m_q.end();
                        m_cur_write_offset = 0;
                        m_total_read_avail = 0;
                }
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nbq::split(nbq **ao_nbq_tail, size_t a_offset)
{
        *ao_nbq_tail = nullptr;
        if (!a_offset)
        {
                return NTRNT_STATUS_OK;
        }
        if (a_offset >= m_cur_write_offset)
        {
                TRC_ERROR("requested split at offset: %lu > write_offset: %lu\n", a_offset, m_cur_write_offset);
                return NTRNT_STATUS_ERROR;
        }
        // ---------------------------------------
        // find block at offset
        // ---------------------------------------
        size_t i_offset = a_offset;
        nb_list_t::iterator i_b;
        for(i_b = m_q.begin();
            i_b != m_q.end();
            ++i_b)
        {
                if (!(*i_b))
                {
                        TRC_ERROR("block iter in nbq == nullptr\n");
                        return NTRNT_STATUS_ERROR;
                }
                size_t l_w = (*i_b)->written();
                if (l_w > i_offset)
                {
                        break;
                }
                i_offset -= l_w;
        }
        // ---------------------------------------
        // create new nbq and append remainder
        // ---------------------------------------
        nbq* l_nbq = new nbq(m_bsize);
        if (i_offset > 0)
        {
                nb_t& l_b = *(*i_b);
                if (i_offset >= l_b.written())
                {
                        TRC_ERROR("i_offset: %lu >= l_b.written(): %lu\n", i_offset, l_b.written());
                        if (l_nbq) {delete l_nbq; l_nbq = nullptr;}
                        return NTRNT_STATUS_ERROR;
                }
                // write the remainder
                l_nbq->b_write_add_avail();
                l_nbq->write(l_b.data() + i_offset, l_b.written() - i_offset);
                l_b.write_reset();
                l_b.write_inc(i_offset);
        }
        // ---------------------------------------
        // add the tail
        // ---------------------------------------
        ++i_b;
        while(i_b != m_q.end())
        {
                if (!(*i_b))
                {
                        TRC_ERROR("block iter in nbq == nullptr\n");
                        return NTRNT_STATUS_ERROR;
                }
                //NDBG_PRINT("adding tail block\n");
                l_nbq->m_q.push_back(*i_b);
                (*i_b)->read_reset();
                //NDBG_PRINT("removing tail block\n");
                m_cur_write_offset -= (*i_b)->written();
                l_nbq->m_cur_write_offset += (*i_b)->written();
                m_q.erase(i_b++);
        }
        l_nbq->m_cur_write_block = --(l_nbq->m_q.end());
        l_nbq->m_cur_read_block = l_nbq->m_q.begin();
        l_nbq->reset_read();
        m_cur_write_block = --m_q.end();
        reset_read();
        *ao_nbq_tail = l_nbq;
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nbq::join_ref(const nbq& ao_nbq_tail)
{
        const nbq& l_nbq_tail = ao_nbq_tail;
        for(nb_list_t::const_iterator i_b = l_nbq_tail.m_q.begin();
            i_b != l_nbq_tail.m_q.end();
            ++i_b)
        {
                if (!(*i_b))
                {
                        return NTRNT_STATUS_ERROR;
                }
                nb_t &l_b = *(*i_b);
                nb_t *l_b_ref = new nb_t(l_b.data(), l_b.written());
                m_q.push_back(l_b_ref);
                m_cur_write_offset += l_b_ref->written();
                m_total_read_avail += l_b_ref->written();
        }
        m_cur_write_block = m_q.end();
        // Join nbq with reference nbq
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
char*  nbq::b_write_ptr(void)
{
        if (m_cur_write_block == m_q.end())
        {
                return nullptr;
        }
        // -------------------------------------------------
        // lazy init
        // -------------------------------------------------
        (*m_cur_write_block)->init();
        // -------------------------------------------------
        // return write ptr
        // -------------------------------------------------
        return (*m_cur_write_block)->write_ptr();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
size_t nbq::b_write_avail(void)
{
        if (m_cur_write_block == m_q.end())
        {
                return 0;
        }
        return (*m_cur_write_block)->write_avail();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nbq::b_write_add_avail(void)
{
        nb_t *l_block = new nb_struct(m_bsize);
        m_q.push_back(l_block);
        if (m_q.size() == 1)
        {
                m_cur_read_block = m_q.begin();
                m_cur_write_block = m_q.begin();
        }
        else
        {
                if (((*m_cur_write_block)->write_avail() == 0) &&
                    (m_cur_write_block != --m_q.end()))
                {
                        ++m_cur_write_block;
                }
        }
        return (*m_cur_write_block)->write_avail();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void nbq::b_write_incr(size_t a_len)
{
        m_cur_write_offset += a_len;
        (*m_cur_write_block)->write_inc(a_len);
        m_total_read_avail += a_len;
        if (((*m_cur_write_block)->write_avail() == 0) &&
             (m_cur_write_block != --m_q.end()))
        {
                ++m_cur_write_block;
        }
        // check for cur read block
        if ((a_len > 0) &&
           ((*m_cur_read_block)->read_avail() == 0))
        {
                ++m_cur_read_block;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
char* nbq::b_read_ptr(void) const
{
        if (m_cur_read_block == m_q.end())
        {
                return nullptr;
        }
        return (*m_cur_read_block)->read_ptr();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nbq::b_read_avail(void) const
{
        if (m_cur_read_block == m_q.end())
        {
                return 0;
        }
        else if (m_cur_read_block == m_cur_write_block)
        {
                return m_total_read_avail;
        }
        else
        {
                return (*m_cur_read_block)->read_avail();
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void nbq::b_read_incr(size_t a_len)
{
        size_t l_avail = b_read_avail();
        m_total_read_avail -= a_len;
        l_avail -= a_len;
        (*m_cur_read_block)->read_inc(a_len);
        if (!l_avail &&
           m_total_read_avail)
        {
                ++m_cur_read_block;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void nbq::b_display_written(void)
{
        if (m_q.empty())
        {
                return;
        }
        size_t i_block_num = 0;
        for(nb_list_t::iterator i_b = m_q.begin(); i_b != m_q.end(); ++i_b, ++i_block_num)
        {
                if (!(*i_b))
                {
                        return;
                }
                NDBG_OUTPUT("+------------------------------------+\n");
                NDBG_OUTPUT("| Block: %lu -> %p\n", i_block_num, (*i_b));
                NDBG_OUTPUT("+------------------------------------+\n");
                nb_t &l_b = *(*i_b);
                mem_display((const uint8_t *)(l_b.data()), l_b.written());
                if (i_b == m_cur_write_block)
                {
                        break;
                }
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void nbq::b_display_all(void)
{
        size_t i_block_num = 0;
        for(nb_list_t::iterator i_b = m_q.begin(); i_b != m_q.end(); ++i_b, ++i_block_num)
        {
                if (!(*i_b))
                {
                        return;
                }
                NDBG_OUTPUT("+------------------------------------+\n");
                NDBG_OUTPUT("| Block: %lu -> %p\n", i_block_num, (*i_b));
                NDBG_OUTPUT("+------------------------------------+\n");
                nb_t &l_b = *(*i_b);
                mem_display((const uint8_t *)(l_b.data()), l_b.size());
        }
}
//! ----------------------------------------------------------------------------
//! Utils...
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
char* copy_part(nbq& a_nbq, size_t a_off, size_t a_len)
{
        char* l_buf = nullptr;
        l_buf = (char* )calloc(1, sizeof(char)*a_len + 1);
        if (!l_buf)
        {
                return nullptr;
        }
        a_nbq.read_from(a_off, l_buf, a_len);
        l_buf[a_len] = '\0';
        return l_buf;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void print_part(nbq& a_nbq, size_t a_off, size_t a_len)
{
        char* l_buf = copy_part(a_nbq, a_off, a_len);
        TRC_OUTPUT("%.*s", (int)a_len, l_buf);
        if (l_buf)
        {
                free(l_buf);
                l_buf = nullptr;
        }
}
} // ns_ntrnt
