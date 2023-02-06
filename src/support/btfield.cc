//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "ntrnt/def.h"
#include "support/btfield.h"
#include "support/ndebug.h"
#include <string.h>
#include <algorithm>
namespace ns_ntrnt {
#define _BTFIELD_BYTE_LEN 8
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
btfield::btfield(uint32_t a_size):
        m_bits(a_size),
        m_raw(nullptr),
        m_raw_len(0),
        m_dirty(true)
{
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
btfield::~btfield(void)
{
        if (m_raw) { free(m_raw); m_raw = nullptr; }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void btfield::set_size(size_t a_len)
{
        m_bits.clear();
        m_bits.resize(a_len);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void btfield::clear_all(void)
{
        for (auto && i_b : m_bits)
        {
                i_b = false;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t btfield::set(size_t a_bit, bool a_flag)
{
        if (a_bit >= m_bits.size())
        {
                return NTRNT_STATUS_ERROR;
        }
        if (m_bits[a_bit] == a_flag)
        {
                return NTRNT_STATUS_OK;
        }
        m_bits[a_bit] = a_flag;
        m_dirty = true;
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
bool btfield::test(size_t a_bit) const
{
        if (a_bit >= m_bits.size())
        {
                return false;
        }
        return m_bits[a_bit];
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
size_t btfield::get_count(void)
{
        size_t l_ret = 0;
        for (auto && i_b : m_bits)
        {
                if (i_b) { ++l_ret; }
        }
        return l_ret;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
bool btfield::has_all(void)
{
        // TODO std::count could be expensive use popcnt???
        size_t l_s = std::count(m_bits.begin(), m_bits.end(), true);
        return (l_s == m_bits.size());
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
bool btfield::has_none(void)
{
        // TODO std::count could be expensive use popcnt???
        size_t l_s = std::count(m_bits.begin(), m_bits.end(), true);
        return (l_s == 0);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t btfield::import_raw(const uint8_t* a_buf, size_t a_len, size_t a_bit_len)
{
        size_t l_bsize = a_len*_BTFIELD_BYTE_LEN;
        if (a_bit_len > l_bsize)
        {
                return NTRNT_STATUS_ERROR;
        }
        m_bits.resize(a_bit_len);
        size_t l_bt = 0;
        for (size_t i_byte = 0;
             (i_byte < a_len) &&
             (l_bt < a_bit_len);
            ++i_byte)
        {
                uint8_t l_byte = a_buf[i_byte];
                for (uint8_t i_bt = _BTFIELD_BYTE_LEN;
                     (i_bt) &&
                     (l_bt < a_bit_len);
                    --i_bt, ++l_bt)
                {
                        bool l_f = (l_byte & (1 << (i_bt-1)));
                        m_bits[l_bt] = l_f;
                }
        }
        m_dirty = true;
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t btfield::export_raw(uint8_t** ao_buf, size_t& ao_len)
{
        if (!ao_buf)
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // if not dirty -just return raw buffer
        // -------------------------------------------------
        if (!m_dirty)
        {
                *ao_buf = m_raw;
                ao_len = m_raw_len;
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // free pre-existing
        // -------------------------------------------------
        if (m_raw)
        {
                free(m_raw);
                m_raw = nullptr;
                m_raw_len = 0;
        }
        // -------------------------------------------------
        // regenerate
        // -------------------------------------------------
        size_t l_bts_size = m_bits.size();
        m_raw_len = l_bts_size/_BTFIELD_BYTE_LEN + (l_bts_size%_BTFIELD_BYTE_LEN?1:0);
        m_raw = (uint8_t*)malloc(sizeof(uint8_t)*m_raw_len);
        memset(m_raw, 0, m_raw_len);
        size_t l_bt = 0;
        for (size_t i_byte = 0;
             (i_byte < m_raw_len) &&
             (l_bt < l_bts_size);
            ++i_byte)
        {
                for (uint8_t i_bt = _BTFIELD_BYTE_LEN;
                     (i_bt) &&
                     (l_bt < l_bts_size);
                     --i_bt, ++l_bt)
                {
                        bool l_flag = m_bits[l_bt];
                        if (l_flag)
                        {
                                m_raw[i_byte] |= l_flag << (i_bt - 1);
                        }
                }
        }
        // -------------------------------------------------
        // done
        // -------------------------------------------------
        *ao_buf = m_raw;
        ao_len = m_raw_len;
        return NTRNT_STATUS_OK;
}
}
