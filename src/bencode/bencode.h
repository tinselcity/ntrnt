#ifndef _NTRNT_BENCODE_H
#define _NTRNT_BENCODE_H
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
#include <list>
#include <map>
#include <string>
#include <vector>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! enum
//! ----------------------------------------------------------------------------
typedef enum {
  BE_OBJ_NONE = 0,
  BE_OBJ_STRING,
  BE_OBJ_INT,
  BE_OBJ_LIST,
  BE_OBJ_DICT,
  BE_OBJ_MUTABLE_STRING,
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
  _be_obj* m_parent;
} be_obj_t;
//! ----------------------------------------------------------------------------
//! bdecode dict
//! ----------------------------------------------------------------------------
typedef std::map<std::string, be_obj_t> be_dict_t;
typedef std::list<be_obj_t> be_list_t;
typedef data_t be_string_t;
typedef mutable_data_t be_mutable_string_t;
typedef int64_t be_int_t;
//! ----------------------------------------------------------------------------
//! bdecode class
//! ----------------------------------------------------------------------------
class bdecode {
 public:
  // -------------------------------------------------
  // public methods
  // -------------------------------------------------
  bdecode(void);
  ~bdecode(void);
  int32_t init(const char* a_file);
  int32_t init(const char* a_buf, size_t a_len);
  void get_cur_ptr(char** ao_ptr, size_t& ao_off, size_t& ao_len);
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
  bdecode(const bdecode&);
  bdecode& operator=(const bdecode&);
  // -------------------------------------------------
  // init
  // -------------------------------------------------
  int32_t init(void);
  // -------------------------------------------------
  // parsing
  // -------------------------------------------------
  int32_t parse_obj(be_obj_t& ao_obj);
  int32_t parse_dict(be_dict_t& ao_dict);
  int32_t parse_string(be_string_t& ao_string);
  int32_t parse_list(be_list_t& ao_list);
  int32_t parse_int(be_int_t& ao_int);
  int32_t parse_len(size_t& ao_len);
  // -------------------------------------------------
  // display
  // -------------------------------------------------
  void display_obj(const be_obj_t& a_obj, uint16_t a_indent);
  void display_dict(const be_dict_t& a_dict, uint16_t a_indent);
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
//! ----------------------------------------------------------------------------
//! bencode_writer class
//! ----------------------------------------------------------------------------
class bencode_writer {
 public:
  // -------------------------------------------------
  // types
  // -------------------------------------------------
  typedef std::vector<uint8_t> uint8_vec_t;
  // -------------------------------------------------
  // public methods
  // -------------------------------------------------
  bencode_writer(void);
  ~bencode_writer(void);
  void display(void);
  void w_start_dict(void);
  void w_end_dict(void);
  void w_start_list(void);
  void w_end_list(void);
  void w_key(const std::string& a_key);
  void w_string(const std::string& a_str);
  void w_string(const char* a_buf, size_t a_len);
  void w_int(int64_t a_val);
  void serialize(const uint8_t** ao_buf, size_t& ao_len);

 private:
  // -------------------------------------------------
  // private methods
  // -------------------------------------------------
  // disallow copy/assign
  bencode_writer(const bencode_writer&);
  bencode_writer& operator=(const bencode_writer&);
  void s_dict(const be_dict_t& a_dict);
  void s_list(const be_list_t& a_list);
  void s_obj(const be_obj_t& ao_obj);
  // -------------------------------------------------
  // private members
  // -------------------------------------------------
  be_obj_t m_root;
  be_dict_t m_dict;
  std::string m_cur_key;
  be_obj_ptr_t m_cur_obj;
  uint8_vec_t m_data;
};
}  // namespace ns_ntrnt
#endif
