//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "bencode/bencode.h"
#include "support/util.h"
#include "support/trace.h"
#include "support/ndebug.h"
// ---------------------------------------------------------
// std libs
// ---------------------------------------------------------
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _DISPLAY_INDENT 2
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#define _INCR_PTR() do { \
        ++m_cur_off; \
        ++m_cur_ptr; \
} while(0)
#define _INCR_PTR_BY(_len) do { \
        m_cur_off += _len; \
        m_cur_ptr += _len; \
} while(0)
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! "bencoding types"
//! ref: http://www.bittorrent.org/beps/bep_0003.html
//! ----------------------------------------------------------------------------
//!
//! *************************************************
//! ****** S T R I N G S ****************************
//! *************************************************
//! Strings are length-prefixed base ten followed by a colon and the string.
//! For example 4:spam corresponds to 'spam'.
//!
//! *************************************************
//! ****** I N T E G E R S **************************
//! *************************************************
//! Integers are represented by an 'i' followed by the number in base 10
//! followed by an 'e'.
//! For example i3e corresponds to 3 and i-3e corresponds to -3.
//! Integers have no size limitation. i-0e is invalid.
//! All encodings with a leading zero, such as i03e, are invalid, other than
//! i0e, which of course corresponds to 0.
//!
//! *************************************************
//! ******* L I S T S *******************************
//! *************************************************
//! Lists are encoded as an 'l' followed by their elements (also bencoded)
//! followed by an 'e'.
//! For example l4:spam4:eggse corresponds to
//! ['spam', 'eggs'].
//!
//! *************************************************
//! ******* D I C T I O N A R I E S *****************
//! *************************************************
//! Dictionaries are encoded as a 'd' followed by a list of alternating keys
//! and their corresponding values followed by an 'e'.
//! For example,
//! d3:cow3:moo4:spam4:eggse
//! corresponds to
//! {'cow': 'moo', 'spam': 'eggs'}
//! and
//! d4:spaml1:a1:bee
//! corresponds to
//! {'spam': ['a', 'b']}.
//! Keys must bdecode strings and appear in sorted order
//! (sorted as raw strings, not alphanumerics).
//!
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! static util
//! ----------------------------------------------------------------------------
static void delete_obj(be_obj_t& ao_obj);
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static void delete_list(be_list_t& ao_list)
{
        for(auto && i_m : ao_list)
        {
                be_obj_t& i_obj = i_m;
                delete_obj(i_obj);
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static void delete_dict(be_dict_t& ao_dict)
{
        for(auto && i_m : ao_dict)
        {
                be_obj_t& i_obj = i_m.second;
                delete_obj(i_obj);
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static void delete_obj(be_obj_t& ao_obj)
{
        switch (ao_obj.m_type)
        {
        // -------------------------------------------------
        // INT
        // -------------------------------------------------
        case BE_OBJ_INT:
        {
                be_int_t* l_obj = (be_int_t*)ao_obj.m_obj;
                delete l_obj;
                break;
        }
        // -------------------------------------------------
        // STRING
        // -------------------------------------------------
        case BE_OBJ_STRING:
        {
                be_string_t* l_obj = (be_string_t*)ao_obj.m_obj;
                delete l_obj;
                break;
        }
        // -------------------------------------------------
        // STRING
        // -------------------------------------------------
        case BE_OBJ_MUTABLE_STRING:
        {
                be_mutable_string_t* l_obj = (be_mutable_string_t*)ao_obj.m_obj;
                if (l_obj->m_data)
                {
                        free(l_obj->m_data);
                        l_obj->m_data = nullptr;
                }
                delete l_obj;
                break;
        }
        // -------------------------------------------------
        // LIST
        // -------------------------------------------------
        case BE_OBJ_LIST:
        {
                be_list_t* l_obj = (be_list_t*)ao_obj.m_obj;
                delete_list(*l_obj);
                delete l_obj;
                break;
        }
        // -------------------------------------------------
        // DICT
        // -------------------------------------------------
        case BE_OBJ_DICT:
        {
                be_dict_t* l_obj = (be_dict_t*)ao_obj.m_obj;
                delete_dict(*l_obj);
                delete l_obj;
                break;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
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
bdecode::bdecode(void):
        m_dict(),
        m_buf(nullptr),
        m_buf_len(0),
        m_cur_off(0),
        m_cur_ptr(nullptr)
{
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
bdecode::~bdecode(void)
{
        if (m_buf)
        {
                free(m_buf);
                m_buf = nullptr;
                m_buf_len = 0;
        }
        // -------------------------------------------------
        // delete dict
        // -------------------------------------------------
        delete_dict(m_dict);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t bdecode::init(void)
{
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        m_cur_off = 0;
        m_cur_ptr = m_buf;
        // -------------------------------------------------
        // verify dict
        // -------------------------------------------------
        if (*m_cur_ptr != 'd')
        {
                TRC_ERROR("metainfo file does not appear to bdecode a dict -no preceding 'd'");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // parse
        // -------------------------------------------------
        int32_t l_s;
        _INCR_PTR();
        l_s = parse_dict(m_dict);
        if (l_s != NTRNT_STATUS_OK)
        {
                // TODO ERROR
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t bdecode::init(const char* a_buf, size_t a_len)
{
        if (!a_buf ||
            !a_len)
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // copy in
        // -------------------------------------------------
        m_buf = (char *)malloc(sizeof(char)*a_len);
        memcpy(m_buf, a_buf, a_len);
        m_buf_len = a_len;
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        return init();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t bdecode::init(const char* a_file)
{
        int32_t l_s;
        // -------------------------------------------------
        // read in file
        // -------------------------------------------------
        l_s = read_file(a_file, &m_buf, &m_buf_len);
        if (l_s != NTRNT_STATUS_OK)
        {
                // TODO ERROR
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        return init();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void bdecode::get_cur_ptr(char** ao_ptr, size_t& ao_off, size_t& ao_len)
{
        if (!ao_ptr)
        {
                return;
        }
        *ao_ptr = m_cur_ptr;
        ao_off = m_cur_off;
        ao_len = m_buf_len;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t bdecode::parse_len(size_t& ao_len)
{
        // -------------------------------------------------
        // expect length
        // -------------------------------------------------
        const char *l_len_begin = m_cur_ptr;
        while (isdigit(*m_cur_ptr))
        {
                _INCR_PTR();
        }
        char *l_len_end = const_cast<char *>(m_cur_ptr);
        // -------------------------------------------------
        // find skip delim
        // -------------------------------------------------
        if (*m_cur_ptr != ':')
        {
                TRC_ERROR("cur_ptr != :");
                return NTRNT_STATUS_ERROR;
        }
        _INCR_PTR();
        // -------------------------------------------------
        // convert len
        // -------------------------------------------------
        errno = 0;
        ao_len = strtoul(l_len_begin, &l_len_end, 10);
        if (ao_len == ULONG_MAX)
        {
                TRC_ERROR("performing strtoul");
                return NTRNT_STATUS_ERROR;
        }
        if (errno != 0)
        {
                TRC_ERROR("errno != 0 [%d]", errno);
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t bdecode::parse_obj(be_obj_t& ao_obj)
{
        int32_t l_s = NTRNT_STATUS_OK;
        // -------------------------------------------------
        // setup buf
        // -------------------------------------------------
        char l_type = *m_cur_ptr;
        // -------------------------------------------------
        // for type
        // -------------------------------------------------
        // -------------------------------------------------
        // string
        // -------------------------------------------------
        if (isdigit(l_type))
        {
                // -----------------------------------------
                // parse
                // -----------------------------------------
                be_string_t* l_str = new be_string_t();
                l_s = parse_string(*l_str);
                if (l_s != NTRNT_STATUS_OK)
                {
                        if (l_str) { delete l_str; l_str = nullptr; }
                        return NTRNT_STATUS_ERROR;
                }
                // -----------------------------------------
                // set type
                // -----------------------------------------
                ao_obj.m_type = BE_OBJ_STRING;
                ao_obj.m_obj = l_str;
        }
        // -------------------------------------------------
        // integer
        // -------------------------------------------------
        else if (l_type == 'i')
        {
                // -----------------------------------------
                // parse
                // -----------------------------------------
                _INCR_PTR();
                be_int_t* l_int = new be_int_t();
                l_s = parse_int(*l_int);
                if (l_s != NTRNT_STATUS_OK)
                {
                        if (l_int) { delete l_int; l_int = nullptr; }
                        return NTRNT_STATUS_ERROR;
                }
                // -----------------------------------------
                // set type
                // -----------------------------------------
                ao_obj.m_type = BE_OBJ_INT;
                ao_obj.m_obj = l_int;
        }
        // -------------------------------------------------
        // list
        // -------------------------------------------------
        else if (l_type == 'l')
        {
                // -----------------------------------------
                // parse
                // -----------------------------------------
                _INCR_PTR();
                be_list_t* l_list = new be_list_t();
                l_s = parse_list(*l_list);
                if (l_s != NTRNT_STATUS_OK)
                {
                        delete_list(*l_list);
                        if (l_list) { delete l_list; l_list = nullptr; }
                        return NTRNT_STATUS_ERROR;
                }
                // -----------------------------------------
                // set type
                // -----------------------------------------
                ao_obj.m_type = BE_OBJ_LIST;
                ao_obj.m_obj = l_list;
        }
        // -------------------------------------------------
        // dictionary
        // -------------------------------------------------
        else if (l_type == 'd')
        {
                // -----------------------------------------
                // parse
                // -----------------------------------------
                _INCR_PTR();
                be_dict_t* l_dict = new be_dict_t();
                l_s = parse_dict(*l_dict);
                if (l_s != NTRNT_STATUS_OK)
                {
                        delete_dict(*l_dict);
                        if (l_dict) { delete l_dict; l_dict = nullptr; }
                        return NTRNT_STATUS_ERROR;
                }
                // -----------------------------------------
                // set type
                // -----------------------------------------
                ao_obj.m_type = BE_OBJ_DICT;
                ao_obj.m_obj = l_dict;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        else
        {
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t bdecode::parse_int(be_int_t& ao_int)
{
        // -------------------------------------------------
        // expect length
        // -------------------------------------------------
        const char *l_len_begin = m_cur_ptr;
        while ((*m_cur_ptr == '-') ||
               isdigit(*m_cur_ptr))
        {
                _INCR_PTR();
        }
        char *l_len_end = const_cast<char *>(m_cur_ptr);
        // -------------------------------------------------
        // find skip delim
        // -------------------------------------------------
        if (*m_cur_ptr != 'e')
        {
                TRC_ERROR("m_cur_ptr != 'e'");
                return NTRNT_STATUS_ERROR;
        }
        _INCR_PTR();
        // -------------------------------------------------
        // convert len
        // -------------------------------------------------
        errno = 0;
        ao_int = strtoll(l_len_begin, &l_len_end, 10);
        if (ao_int == LONG_MAX)
        {
                TRC_ERROR("performing strtoll");
                return NTRNT_STATUS_ERROR;
        }
        if (errno != 0)
        {
                TRC_ERROR("errno != 0 [%d]", errno);
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t bdecode::parse_string(be_string_t& ao_string)
{
        int32_t l_s = NTRNT_STATUS_OK;
        // -------------------------------------------------
        // expect length
        // -------------------------------------------------
        size_t l_len;
        l_s = parse_len(l_len);
        if (l_s != NTRNT_STATUS_OK)
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // read in string
        // -------------------------------------------------
        ao_string.m_data = m_cur_ptr;
        ao_string.m_len = l_len;
        _INCR_PTR_BY(l_len);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t bdecode::parse_list(be_list_t& ao_list)
{
        // -------------------------------------------------
        // while not end
        // -------------------------------------------------
        int32_t l_s = NTRNT_STATUS_OK;
        bool l_end = false;
        while (!l_end)
        {
                // -----------------------------------------
                // check for end
                // -----------------------------------------
                if (*m_cur_ptr == 'e')
                {
                        _INCR_PTR();
                        goto done;
                }
                // -----------------------------------------
                // parse obj
                // -----------------------------------------
                be_obj_t l_be_obj;
                l_s = parse_obj(l_be_obj);
                if (l_s != NTRNT_STATUS_OK)
                {
                        return NTRNT_STATUS_ERROR;
                }
                // -----------------------------------------
                // append
                // -----------------------------------------
                ao_list.push_back(l_be_obj);
        }
done:
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t bdecode::parse_dict(be_dict_t& a_be_dict)
{
        // -------------------------------------------------
        // while not end
        // -------------------------------------------------
        int32_t l_s = NTRNT_STATUS_OK;
        bool l_end = false;
        while (!l_end)
        {
                // -----------------------------------------
                // check for end
                // -----------------------------------------
                if (*m_cur_ptr == 'e')
                {
                        _INCR_PTR();
                        goto done;
                }
                // -----------------------------------------
                // read in key
                // -----------------------------------------
                be_string_t l_key;
                l_s = parse_string(l_key);
                if (l_s != NTRNT_STATUS_OK)
                {
                        return NTRNT_STATUS_ERROR;
                }
                std::string l_key_str;
                l_key_str.assign(l_key.m_data, l_key.m_len);
                // -----------------------------------------
                // parse obj
                // -----------------------------------------
                be_obj_t l_be_obj;
                l_be_obj.m_ptr = m_cur_ptr;
                l_s = parse_obj(l_be_obj);
                if (l_s != NTRNT_STATUS_OK)
                {
                        return NTRNT_STATUS_ERROR;
                }
                l_be_obj.m_len = m_cur_ptr - l_be_obj.m_ptr;
                // -----------------------------------------
                // append
                // -----------------------------------------
                a_be_dict[l_key_str] = l_be_obj;
        }
done:
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void bdecode::display_obj(const be_obj_t& a_obj, uint16_t a_indent)
{
        switch (a_obj.m_type)
        {
        // -------------------------------------------------
        // INT
        // -------------------------------------------------
        case BE_OBJ_INT:
        {
                const be_int_t& l_obj = *((const be_int_t*)a_obj.m_obj);
                NDBG_OUTPUT("%*c[INT]: %d\n", a_indent, ' ', (int)l_obj);
                break;
        }
        // -------------------------------------------------
        // STRING
        // -------------------------------------------------
        case BE_OBJ_STRING:
        {
                const be_string_t& l_obj = *((const be_string_t*)a_obj.m_obj);
                //NDBG_OUTPUT("%*c[STR]: %.*s\n", a_indent, ' ', (int)l_obj.m_len, l_obj.m_data);
                NDBG_OUTPUT("%*c[STR]: ", a_indent, ' ');
                for (uint32_t i_b = 0; i_b < l_obj.m_len; ++i_b)
                {
                        char l_c = l_obj.m_data[i_b];
                        if (isprint((int)(l_c)))
                        {
                                NDBG_OUTPUT("%c", l_c);
                        }
                        else
                        {
                                NDBG_OUTPUT(".");
                        }
                }
                NDBG_OUTPUT("\n");
                break;
        }
        // -------------------------------------------------
        // LIST
        // -------------------------------------------------
        case BE_OBJ_LIST:
        {
                const be_list_t& l_obj = *((const be_list_t*)a_obj.m_obj);
                NDBG_OUTPUT("%*c[LST]: -------------------> BEGIN\n", a_indent, ' ');
                display_list(l_obj, a_indent+_DISPLAY_INDENT);
                NDBG_OUTPUT("%*c[LST]: -------------------> END\n", a_indent, ' ');
                break;
        }

        // -------------------------------------------------
        // DICT
        // -------------------------------------------------
        case BE_OBJ_DICT:
        {
                const be_dict_t& l_obj = *((const be_dict_t*)a_obj.m_obj);
                NDBG_OUTPUT("%*c[DCT]: -------------------> BEGIN\n", a_indent, ' ');
                display_dict(l_obj, a_indent+_DISPLAY_INDENT);
                NDBG_OUTPUT("%*c[DCT]: -------------------> END\n", a_indent, ' ');
                break;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
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
void bdecode::display_dict(const be_dict_t& a_dict, uint16_t a_indent)
{
        for(auto && i_m : a_dict)
        {
                const be_obj_t& i_obj = i_m.second;
                NDBG_OUTPUT("%*c[KEY]: %s\n", a_indent+_DISPLAY_INDENT, ' ', i_m.first.c_str());
                display_obj(i_obj, a_indent+_DISPLAY_INDENT+_DISPLAY_INDENT);
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void bdecode::display_list(const be_list_t& a_list, uint16_t a_indent)
{
        for(auto && i_m : a_list)
        {
                const be_obj_t& i_obj = i_m;
                display_obj(i_obj, a_indent+_DISPLAY_INDENT);
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void bdecode::display(void)
{
        display_dict(m_dict, 0);
}
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                    B E N C O D E   W R I T E R
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
bencode_writer::bencode_writer(void):
        m_root(),
        m_dict(),
        m_cur_key(),
        m_cur_obj(nullptr),
        m_data()
{
        m_root.m_len = 0;
        m_root.m_obj = (be_obj_ptr_t)(&m_dict);
        m_root.m_parent = nullptr;
        m_root.m_ptr = 0;
        m_root.m_type = BE_OBJ_DICT;
        m_cur_obj = &(m_root);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
bencode_writer::~bencode_writer(void)
{
        delete_dict(m_dict);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void bencode_writer::w_start_dict(void)
{
        if (!m_cur_obj)
        {
                TRC_ERROR("error");
                return;
        }
        be_obj_t* l_cur_obj = (be_obj_t*)(m_cur_obj);
        // -------------------------------------------------
        // create dict
        // -------------------------------------------------
        be_dict_t* l_dict = new be_dict_t();
        be_obj_t l_obj;
        l_obj.m_obj = l_dict;
        l_obj.m_type = BE_OBJ_DICT;
        l_obj.m_parent = l_cur_obj;
        if (0) {}
        // -------------------------------------------------
        // append to list
        // -------------------------------------------------
        else if (l_cur_obj->m_type == BE_OBJ_LIST)
        {
                be_list_t* l_plist = (be_list_t*)(l_cur_obj->m_obj);
                l_plist->push_back(l_obj);
                m_cur_obj = &(l_plist->back());
                return;
        }
        // -------------------------------------------------
        // append to dict
        // -------------------------------------------------
        else if (l_cur_obj->m_type == BE_OBJ_DICT)
        {
                if (m_cur_key.empty())
                {
                        if (l_dict) { delete l_dict; l_dict = nullptr; }
                        return;
                }
                be_dict_t* l_pdict = (be_dict_t*)(l_cur_obj->m_obj);
                // TODO evict if exists... (will leak)
                (*l_pdict)[m_cur_key] = l_obj;
                m_cur_obj = &((*l_pdict)[m_cur_key]);
                m_cur_key.clear();
                return;
        }
        if (l_dict) { delete l_dict; l_dict = nullptr; }
        TRC_ERROR("error");
        return;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void bencode_writer::w_end_dict(void)
{
        if (!m_cur_obj)
        {
                TRC_ERROR("error");
                return;
        }
        be_obj_t* l_cur_obj = (be_obj_t*)(m_cur_obj);
        if (!l_cur_obj)
        {
                TRC_ERROR("error");
                return;
        }
        m_cur_obj = l_cur_obj->m_parent;
        return;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void bencode_writer::w_start_list(void)
{
        if (!m_cur_obj)
        {
                TRC_ERROR("error");
                return;
        }
        be_obj_t* l_cur_obj = (be_obj_t*)(m_cur_obj);
        // -------------------------------------------------
        // can only append list to dict
        // -------------------------------------------------
        if ((l_cur_obj->m_type != BE_OBJ_DICT) ||
            (m_cur_key.empty()))
        {
                TRC_ERROR("error");
                return;
        }
        // -------------------------------------------------
        // create list
        // -------------------------------------------------
        be_list_t* l_list = new be_list_t();
        be_obj_t l_obj;
        l_obj.m_obj = l_list;
        l_obj.m_type = BE_OBJ_LIST;
        l_obj.m_parent = l_cur_obj;
        // -------------------------------------------------
        // append to dict
        // -------------------------------------------------
        be_dict_t* l_pdict = (be_dict_t*)(l_cur_obj->m_obj);
        // TODO evict if exists... (will leak)
        (*l_pdict)[m_cur_key] = l_obj;
        m_cur_obj = &((*l_pdict)[m_cur_key]);
        m_cur_key.clear();
        return;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void bencode_writer::w_end_list(void)
{
        if (!m_cur_obj)
        {
                TRC_ERROR("error");
                return;
        }
        be_obj_t* l_cur_obj = (be_obj_t*)(m_cur_obj);
        if (!l_cur_obj)
        {
                TRC_ERROR("error");
                return;
        }
        m_cur_obj = l_cur_obj->m_parent;
        return;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void bencode_writer::w_key(const std::string& a_key)
{
        m_cur_key = a_key;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void bencode_writer::w_string(const std::string& a_str)
{
        if (!m_cur_obj)
        {
                TRC_ERROR("error");
                return;
        }
        be_obj_t* l_cur_obj = (be_obj_t*)(m_cur_obj);
        // -------------------------------------------------
        // create dict
        // -------------------------------------------------
        be_mutable_string_t* l_str = new be_mutable_string_t();
        l_str->m_data = (char*)malloc(a_str.length());
        l_str->m_len = a_str.length();
        strncpy(l_str->m_data, a_str.data(), l_str->m_len);
        be_obj_t l_obj;
        l_obj.m_obj = l_str;
        l_obj.m_type = BE_OBJ_MUTABLE_STRING;
        l_obj.m_parent = l_cur_obj;
        if (0) {}
        // -------------------------------------------------
        // append to list
        // -------------------------------------------------
        else if (l_cur_obj->m_type == BE_OBJ_LIST)
        {
                be_list_t* l_plist = (be_list_t*)(l_cur_obj->m_obj);
                l_plist->push_back(l_obj);
                return;
        }
        // -------------------------------------------------
        // append to dict
        // -------------------------------------------------
        else if (l_cur_obj->m_type == BE_OBJ_DICT)
        {
                if (m_cur_key.empty())
                {
                        if (l_str) { delete l_str; l_str = nullptr; }
                        return;
                }
                be_dict_t* l_pdict = (be_dict_t*)(l_cur_obj->m_obj);
                // TODO evict if exists... (will leak)
                (*l_pdict)[m_cur_key] = l_obj;
                m_cur_key.clear();
                return;
        }
        if (l_str) { delete l_str; l_str = nullptr; }
        TRC_ERROR("error");
        return;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void bencode_writer::w_string(const char* a_buf, size_t a_len)
{
        if (!m_cur_obj)
        {
                TRC_ERROR("error");
                return;
        }
        be_obj_t* l_cur_obj = (be_obj_t*)(m_cur_obj);
        // -------------------------------------------------
        // create dict
        // -------------------------------------------------
        be_mutable_string_t* l_str = new be_mutable_string_t();
        l_str->m_data = (char*)malloc(a_len);
        l_str->m_len = a_len;
        memcpy(l_str->m_data, a_buf, l_str->m_len);
        be_obj_t l_obj;
        l_obj.m_obj = l_str;
        l_obj.m_type = BE_OBJ_MUTABLE_STRING;
        l_obj.m_parent = l_cur_obj;
        if (0) {}
        // -------------------------------------------------
        // append to list
        // -------------------------------------------------
        else if (l_cur_obj->m_type == BE_OBJ_LIST)
        {
                be_list_t* l_plist = (be_list_t*)(l_cur_obj->m_obj);
                l_plist->push_back(l_obj);
                return;
        }
        // -------------------------------------------------
        // append to dict
        // -------------------------------------------------
        else if (l_cur_obj->m_type == BE_OBJ_DICT)
        {
                if (m_cur_key.empty())
                {
                        if (l_str) { delete l_str; l_str = nullptr; }
                        return;
                }
                be_dict_t* l_pdict = (be_dict_t*)(l_cur_obj->m_obj);
                // TODO evict if exists... (will leak)
                (*l_pdict)[m_cur_key] = l_obj;
                m_cur_key.clear();
                return;
        }
        if (l_str) { delete l_str; l_str = nullptr; }
        TRC_ERROR("error");
        return;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void bencode_writer::w_int(int64_t a_val)
{
        if (!m_cur_obj)
        {
                TRC_ERROR("error");
                return;
        }
        be_obj_t* l_cur_obj = (be_obj_t*)(m_cur_obj);
        // -------------------------------------------------
        // create dict
        // -------------------------------------------------
        be_int_t* l_int = new be_int_t();
        *l_int = a_val;
        be_obj_t l_obj;
        l_obj.m_obj = l_int;
        l_obj.m_type = BE_OBJ_INT;
        l_obj.m_parent = l_cur_obj;
        if (0) {}
        // -------------------------------------------------
        // append to list
        // -------------------------------------------------
        else if (l_cur_obj->m_type == BE_OBJ_LIST)
        {
                be_list_t* l_plist = (be_list_t*)(l_cur_obj->m_obj);
                l_plist->push_back(l_obj);
                return;
        }
        // -------------------------------------------------
        // append to dict
        // -------------------------------------------------
        else if (l_cur_obj->m_type == BE_OBJ_DICT)
        {
                if (m_cur_key.empty())
                {
                        if (l_int) { delete l_int; l_int = nullptr; }
                        return;
                }
                be_dict_t* l_pdict = (be_dict_t*)(l_cur_obj->m_obj);
                // TODO evict if exists... (will leak)
                (*l_pdict)[m_cur_key] = l_obj;
                m_cur_key.clear();
                return;
        }
        if (l_int) { delete l_int; l_int = nullptr; }
        TRC_ERROR("error");
        return;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void bencode_writer::serialize(const uint8_t** ao_buf, size_t& ao_len)
{
        if (!ao_buf)
        {
                TRC_ERROR("error");
                return;
        }
        // -------------------------------------------------
        // clear
        // -------------------------------------------------
        m_data.clear();
        // -------------------------------------------------
        // start
        // -------------------------------------------------
        s_dict(m_dict);
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        *ao_buf = m_data.data();
        ao_len = m_data.size();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void bencode_writer::s_dict(const be_dict_t& a_dict)
{
        m_data.push_back('d');
        // -------------------------------------------------
        // for item in dict
        // -------------------------------------------------
        for(auto && i_m : a_dict)
        {
                // -----------------------------------------
                // write key
                // -----------------------------------------
                char l_len_str[16];
                snprintf(l_len_str, 16, "%lu", i_m.first.length());
                m_data.insert(m_data.end(), l_len_str, l_len_str+strnlen(l_len_str, sizeof(l_len_str)));
                m_data.push_back(':');
                m_data.insert(m_data.end(), i_m.first.c_str(), i_m.first.c_str()+i_m.first.length());
                // -----------------------------------------
                // write obj
                // -----------------------------------------
                s_obj(i_m.second);
        }
        m_data.push_back('e');
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void bencode_writer::s_list(const be_list_t& a_list)
{
        m_data.push_back('l');
        // -------------------------------------------------
        // for item in dict
        // -------------------------------------------------
        for(auto && i_m : a_list)
        {
                // -----------------------------------------
                // write obj
                // -----------------------------------------
                s_obj(i_m);
        }
        m_data.push_back('e');
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void bencode_writer::s_obj(const be_obj_t& a_obj)
{
        switch (a_obj.m_type)
        {
        // -------------------------------------------------
        // INT
        // -------------------------------------------------
        case BE_OBJ_INT:
        {
                // -----------------------------------------
                // get int string
                // -----------------------------------------
                const be_int_t& l_obj = *((const be_int_t*)a_obj.m_obj);
                char l_int_str[32];
                snprintf(l_int_str, 32, "%d", (int)l_obj);
                // -----------------------------------------
                // append
                // -----------------------------------------
                m_data.push_back('i');
                m_data.insert(m_data.end(), l_int_str, l_int_str+strnlen(l_int_str, sizeof(l_int_str)));
                m_data.push_back('e');
                break;
        }
        // -------------------------------------------------
        // BE_OBJ_MUTABLE_STRING
        // -------------------------------------------------
        case BE_OBJ_MUTABLE_STRING:
        {
                // -----------------------------------------
                // get length string
                // -----------------------------------------
                const be_mutable_string_t& l_obj = *((const be_mutable_string_t*)a_obj.m_obj);
                char l_len_str[16];
                snprintf(l_len_str, 16, "%u", l_obj.m_len);
                // -----------------------------------------
                // append length str
                // -----------------------------------------
                m_data.insert(m_data.end(), l_len_str, l_len_str+strnlen(l_len_str, 16));
                m_data.push_back(':');
                // -----------------------------------------
                // append string
                // -----------------------------------------
                m_data.insert(m_data.end(), l_obj.m_data, l_obj.m_data+l_obj.m_len);
                break;
        }
        // -------------------------------------------------
        // LIST
        // -------------------------------------------------
        case BE_OBJ_LIST:
        {
                const be_list_t& l_obj = *((const be_list_t*)a_obj.m_obj);
                s_list(l_obj);
                break;
        }

        // -------------------------------------------------
        // DICT
        // -------------------------------------------------
        case BE_OBJ_DICT:
        {
                const be_dict_t& l_obj = *((const be_dict_t*)a_obj.m_obj);
                s_dict(l_obj);
                break;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                break;
        }
        }
}
}
