//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
// ---------------------------------------------------------
// external
// ---------------------------------------------------------
#include "ntrnt/def.h"
// ---------------------------------------------------------
// internal
// ---------------------------------------------------------
#include "core/stub.h"
#include "support/ndebug.h"
#include "support/trace.h"
#include "support/sha1.h"
#include "support/nbq.h"
#include "support/util.h"
// ---------------------------------------------------------
// system
// ---------------------------------------------------------
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
stub::stub():
        m_init(false),
        m_sfile_list()
{
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
stub::~stub(void)
{
        // -------------------------------------------------
        // clear out map
        // -------------------------------------------------
        for (auto && i_f : m_sfile_list)
        {
                if (i_f.m_buf)
                {
                        int32_t l_s;
                        errno = 0;
                        l_s = munmap(i_f.m_buf, i_f.m_len);
                        if (l_s == -1)
                        {
                                TRC_ERROR("performing munmap.  Reason: %s", strerror(errno));
                                // do nothing...
                        }
                }
                if (i_f.m_fd >= 0)
                {
                        close(i_f.m_fd);
                        i_f.m_fd = -1;
                }
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t stub::init(const std::string& a_info_name,
                   size_t a_info_len,
                   const files_list_t& a_file_list)
{
        if (m_init)
        {
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // single file special case
        // -------------------------------------------------
        if (a_file_list.empty())
        {
                sfile_t l_sf;
                l_sf.m_len = a_info_len;
                l_sf.m_off = 0;
                l_sf.m_path.push_back(a_info_name);
                m_sfile_list.push_back(l_sf);
                m_init = true;
                // TODO REMOVE!!!
                display();
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // for file in list
        // -------------------------------------------------
        size_t l_off = 0;
        for (auto && i_f : a_file_list)
        {
                sfile_t l_sf;
                // -----------------------------------------
                // set fields
                // -----------------------------------------
                l_sf.m_len = i_f.m_len;
                l_sf.m_off = l_off;
                // -----------------------------------------
                // push root dir
                // -----------------------------------------
                l_sf.m_path.push_back(a_info_name);
                // -----------------------------------------
                // push each path in
                // -----------------------------------------
                for (auto && i_p : i_f.m_path)
                {
                        l_sf.m_path.push_back(i_p);
                }
                // -----------------------------------------
                // bump offset by length
                // -----------------------------------------
                l_off += l_sf.m_len;
        }
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        m_init = true;
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void stub::display(void)
{
        NDBG_OUTPUT("+++STUB+++\n");
        for (auto && i_f : m_sfile_list)
        {
                NDBG_OUTPUT("+---------------------------------------+\n");
                for (auto && i_p : i_f.m_path)
                {
                        NDBG_OUTPUT(": path: %s\n", i_p.c_str());
                }
                NDBG_OUTPUT(": len: %lu\n", i_f.m_len);
                NDBG_OUTPUT(": off: %lu\n", i_f.m_off);
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t stub::init_sfile(sfile_t& a_sfile)
{
        // -------------------------------------------------
        // check already initialized
        // -------------------------------------------------
        if (a_sfile.m_fd != -1)
        {
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // create full path
        // TODO not portable to windows but...
        // something like os path join?
        // -------------------------------------------------
        int32_t l_s;
        std::string l_path;
        for (auto && i_p : a_sfile.m_path)
        {
                l_path += i_p;
                if (i_p != a_sfile.m_path.back())
                {
                        l_s = ensure_dir(l_path);
                        if (l_s != NTRNT_STATUS_OK)
                        {
                                TRC_ERROR("performing ensure_dir [DIR: %s]", l_path.c_str());
                                return NTRNT_STATUS_ERROR;
                        }
                        l_path += "/";
                }
        }
        // -------------------------------------------------
        // open file
        // -------------------------------------------------
        errno = 0;
        a_sfile.m_fd = open(l_path.c_str(), O_RDWR | O_CREAT, 0666);
        if (a_sfile.m_fd == -1)
        {
                TRC_ERROR("performing open(%s).  Reason: %s", l_path.c_str(), strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // alloc size
        // -------------------------------------------------
        l_s = ntrnt_fallocate(a_sfile.m_fd, a_sfile.m_len);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing ntrnt_fallocate");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // mmap
        // -------------------------------------------------
        errno = 0;
        a_sfile.m_buf = mmap(NULL, a_sfile.m_len, PROT_READ | PROT_WRITE, MAP_SHARED, a_sfile.m_fd, 0);
        if(a_sfile.m_buf == ((void *)-1))
        {
                TRC_ERROR("performing mmap of size: %zu.  Reason: %s", a_sfile.m_len, strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t stub::write(const uint8_t* a_buf, size_t a_off, size_t a_len)
{
        if (!m_init)
        {
                TRC_ERROR("not initalized");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // walk list to find first offset
        // -------------------------------------------------
        auto i_f = m_sfile_list.begin();
        while((i_f != m_sfile_list.end()) &&
              ((i_f->m_off+i_f->m_len) < a_off))
        {
                ++i_f;
        }
        if (i_f == m_sfile_list.end())
        {
                TRC_ERROR("offset: %u not found", (unsigned int)a_off);
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // write up to end or no remainder
        // -------------------------------------------------
        size_t l_rem = a_len;
        const uint8_t* l_src = a_buf;
        size_t l_first_off = a_off - i_f->m_off;
        while((i_f != m_sfile_list.end()) &&
               l_rem)
        {
                // -----------------------------------------
                // ensure initialized
                // -----------------------------------------
                int32_t l_s;
                l_s = init_sfile(*i_f);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing init_sfile");
                        return NTRNT_STATUS_ERROR;
                }
                // -----------------------------------------
                // get buffer offset
                // -----------------------------------------
                size_t l_f_rem = i_f->m_len;
                uint8_t* l_dst = ((uint8_t*)i_f->m_buf);
                if (l_first_off)
                {
                        l_f_rem = i_f->m_len - l_first_off;
                        l_dst = ((uint8_t*)i_f->m_buf) + l_first_off;
                        l_first_off = 0;
                }
                size_t l_f_write = (l_f_rem > l_rem) ? l_rem : l_f_rem;
                // -----------------------------------------
                // write
                // -----------------------------------------
                memcpy(l_dst, l_src, l_f_write);
                // -----------------------------------------
                // counters
                // -----------------------------------------
                l_src += l_f_write;
                l_rem -= l_f_write;
        }
        // -------------------------------------------------
        // TODO -check if hit end before could read all
        // -------------------------------------------------
        if (l_rem)
        {
                TRC_ERROR("failed to write all requested: [remainder: %u]", (unsigned int)l_rem);
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t stub::read(nbq* a_q, size_t a_off, size_t a_len)
{
        if (!m_init)
        {
                TRC_ERROR("not initalized");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // walk list to find first offset
        // -------------------------------------------------
        auto i_f = m_sfile_list.begin();
        while((i_f != m_sfile_list.end()) &&
              ((i_f->m_off+i_f->m_len) < a_off))
        {
                ++i_f;
        }
        if (i_f == m_sfile_list.end())
        {
                TRC_ERROR("offset: %u not found", (unsigned int)a_off);
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // early exit
        // TODO run more of the checks
        // -------------------------------------------------
        if (!a_q)
        {
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // write up to end or no remainder
        // -------------------------------------------------
        size_t l_rem = a_len;
        size_t l_first_off = a_off - i_f->m_off;
        while((i_f != m_sfile_list.end()) &&
               l_rem)
        {
                // -----------------------------------------
                // ensure initialized
                // -----------------------------------------
                int32_t l_s;
                l_s = init_sfile(*i_f);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing init_sfile");
                        return NTRNT_STATUS_ERROR;
                }
                // -----------------------------------------
                // get buffer offset
                // -----------------------------------------
                size_t l_f_rem = i_f->m_len;
                uint8_t* l_src = ((uint8_t*)i_f->m_buf);
                if (l_first_off)
                {
                        l_f_rem = i_f->m_len - l_first_off;
                        l_src = ((uint8_t*)i_f->m_buf) + l_first_off;
                        l_first_off = 0;
                }
                size_t l_f_write = (l_f_rem > l_rem) ? l_rem : l_f_rem;
                // -----------------------------------------
                // write
                // -----------------------------------------
                if (a_q)
                {
                        off_t l_w;
                        l_w = a_q->write((const char*)l_src, l_f_write);
                        UNUSED(l_w);
                }
                // -----------------------------------------
                // counters
                // -----------------------------------------
                l_rem -= l_f_write;
        }
        // -------------------------------------------------
        // TODO -check if hit end before could read all
        // -------------------------------------------------
        if (l_rem)
        {
                TRC_ERROR("failed to read all requested: [remainder: %u]", (unsigned int)l_rem);
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t stub::calc_sha1(id_t& ao_sha1, size_t a_off, size_t a_len)
{
        if (!m_init)
        {
                TRC_ERROR("not initalized");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // walk list to find first offset
        // -------------------------------------------------
        auto i_f = m_sfile_list.begin();
        while((i_f != m_sfile_list.end()) &&
              ((i_f->m_off+i_f->m_len) < a_off))
        {
                ++i_f;
        }
        if (i_f == m_sfile_list.end())
        {
                TRC_ERROR("offset: %u not found", (unsigned int)a_off);
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // write up to end or no remainder
        // -------------------------------------------------
        sha1 l_sha1;
        size_t l_rem = a_len;
        size_t l_first_off = a_off - i_f->m_off;
        while((i_f != m_sfile_list.end()) &&
               l_rem)
        {
                // -----------------------------------------
                // ensure initialized
                // -----------------------------------------
                int32_t l_s;
                l_s = init_sfile(*i_f);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing init_sfile");
                        return NTRNT_STATUS_ERROR;
                }
                // -----------------------------------------
                // get buffer offset
                // -----------------------------------------
                size_t l_f_rem = i_f->m_len;
                uint8_t* l_src = ((uint8_t*)i_f->m_buf);
                if (l_first_off)
                {
                        l_f_rem = i_f->m_len - l_first_off;
                        l_src = ((uint8_t*)i_f->m_buf) + l_first_off;
                        l_first_off = 0;
                }
                size_t l_f_write = (l_f_rem > l_rem) ? l_rem : l_f_rem;
                // -----------------------------------------
                // sha1 update
                // -----------------------------------------
                l_sha1.update(l_src, l_f_write);
                // -----------------------------------------
                // counters
                // -----------------------------------------
                l_rem -= l_f_write;
        }
        l_sha1.finish();
        memcpy(ao_sha1.m_data, l_sha1.get_hash(), sizeof(ao_sha1));
        // -------------------------------------------------
        // TODO -check if hit end before could read all
        // -------------------------------------------------
        if (l_rem)
        {
                TRC_ERROR("failed to read all requested: [remainder: %u]", (unsigned int)l_rem);
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
}
