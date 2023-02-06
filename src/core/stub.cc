//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "ntrnt/def.h"
#include "core/stub.h"
#include "support/ndebug.h"
#include "support/trace.h"
#include "support/sha1.h"
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
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
        m_file(),
        m_len(),
        m_fd(-1),
        m_buf(nullptr)
{
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
stub::~stub(void)
{
        if (m_buf)
        {
                int32_t l_s;
                errno = 0;
                l_s = munmap(m_buf, m_len);
                if (l_s == -1)
                {
                        TRC_ERROR("performing munmap.  Reason: %s", strerror(errno));
                        // do nothing...
                }
        }
        if (m_fd >= 0)
        {
                close(m_fd);
                m_fd = -1;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t stub::init(const std::string& a_file, size_t a_len)
{
        if (m_init)
        {
                return NTRNT_STATUS_OK;
        }
        m_file = a_file;
        m_len = a_len;
        // -------------------------------------------------
        // open file
        // -------------------------------------------------
        errno = 0;
        m_fd = open(m_file.c_str(), O_RDWR | O_CREAT, 0666);
        if (m_fd == -1)
        {
                TRC_ERROR("performing open(%s).  Reason: %s", m_file.c_str(), strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // alloc size
        // -------------------------------------------------
        int l_s = 0;
        errno = 0;
        l_s = posix_fallocate(m_fd, 0, m_len);
        if(l_s != 0) {

                TRC_ERROR("performing fallocate of size: %Zu.  Reason: %s\n", m_len, strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // mmap
        // -------------------------------------------------
        errno = 0;
        m_buf = mmap(NULL, m_len, PROT_READ | PROT_WRITE, MAP_SHARED, m_fd, 0);
        if(m_buf == ((void *)-1))
        {
                TRC_ERROR("performing mmap of size: %Zu.  Reason: %s\n", m_len, strerror(errno));
                return NTRNT_STATUS_ERROR;
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
int32_t stub::write(const uint8_t* a_buf, size_t a_off, size_t a_len)
{
        if (!m_init)
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // write to offset
        // -------------------------------------------------
        uint8_t* l_buf = (uint8_t*)m_buf + a_off;
        memcpy(l_buf, a_buf, a_len);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t stub::read(uint8_t* ao_buf, size_t a_off, size_t a_len)
{
        if (!m_init)
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // read from offset
        // -------------------------------------------------
        uint8_t* l_buf = (uint8_t*)m_buf + a_off;
        memcpy(ao_buf, l_buf, a_len);
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
                return NTRNT_STATUS_ERROR;
        }
        uint8_t* l_buf = (uint8_t*)m_buf + a_off;
        sha1 l_sha1;
        l_sha1.update(l_buf, a_len);
        l_sha1.finish();
        memcpy(ao_sha1.m_data, l_sha1.get_hash(), sizeof(ao_sha1));
        return NTRNT_STATUS_OK;
}
}
