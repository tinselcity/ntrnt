#ifndef _BE_H
#define _BE_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
// ---------------------------------------------------------
// ntrnt external
// ---------------------------------------------------------
#include "ntrnt/def.h"
// ---------------------------------------------------------
// ntrnt internal
// ---------------------------------------------------------
#include "support/data.h"
// ---------------------------------------------------------
// std libs
// ---------------------------------------------------------
#include <stdint.h>
#if defined(__APPLE__) || defined(__darwin__)
  #include <strings.h>
#else
  #include <string.h>
#endif
#include <map>
#include <list>
#include <string>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! enum
//! ----------------------------------------------------------------------------
typedef enum {
        BE_OBJ_NONE = 0,
        BE_OBJ_STRING,
        BE_OBJ_INT,
        BE_OBJ_LIST,
        BE_OBJ_DICT
} be_obj_type_t;
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
// -----------------------------------------------
// raw obj
// -----------------------------------------------
typedef void* be_obj_ptr_t;
// -----------------------------------------------
// raw obj
// -----------------------------------------------
typedef struct _be_obj {
        be_obj_type_t m_type;
        be_obj_ptr_t m_obj;
        char* m_ptr;
        size_t m_len;
} be_obj_t;
//! ----------------------------------------------------------------------------
//! bencode dict
//! ----------------------------------------------------------------------------
typedef std::map <std::string, be_obj_t> be_dict_t;
typedef std::list<be_obj_t> be_list_t;
typedef data_t be_string_t;
typedef int be_int_t;
//! ----------------------------------------------------------------------------
//! bencode class
//! ----------------------------------------------------------------------------
class bencode {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        bencode(void);
        ~bencode(void);
        int32_t init(const char* a_file);
        int32_t init(const char* a_buf, size_t a_len);
        void display(void);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        be_dict_t m_dict;
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // disallow copy/assign
        bencode(const bencode&);
        bencode& operator=(const bencode&);
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        int32_t init(void);
        // -------------------------------------------------
        // parsing
        // -------------------------------------------------
        int32_t parse_dict(be_dict_t& ao_dict);
        int32_t parse_obj(be_obj_t& ao_obj);
        int32_t parse_string(be_string_t& ao_string);
        int32_t parse_list(be_list_t& ao_list);
        int32_t parse_int(be_int_t& ao_int);
        int32_t parse_len(size_t& ao_len);
        // -------------------------------------------------
        // display
        // -------------------------------------------------
        void display_dict(const be_dict_t& a_dict, uint16_t a_indent);
        void display_obj(const be_obj_t& a_obj, uint16_t a_indent);
        void display_list(const be_list_t& a_list, uint16_t a_indent);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        char* m_buf;
        size_t m_buf_len;
        // -------------------------------------------------
        // parsing
        // -------------------------------------------------
        size_t m_cur_off;
        char* m_cur_ptr;
};
}
#endif

