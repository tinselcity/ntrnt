#ifndef _NTRNT_STUB_H
#define _NTRNT_STUB_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include "ntrnt/types.h"
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class nbq;
//! ----------------------------------------------------------------------------
//! \class: stub
//! ----------------------------------------------------------------------------
class stub {
 public:
  // -------------------------------------------------
  // types
  // -------------------------------------------------
  typedef struct _sfile {
    std::list<std::string> m_path;
    size_t m_len;
    size_t m_off;
    int m_fd;
    _sfile() : m_path(), m_len(0), m_off(0), m_fd(-1) {}
    _sfile(const _sfile& a_that)
        : m_path(a_that.m_path),
          m_len(a_that.m_len),
          m_off(a_that.m_off),
          m_fd(a_that.m_fd) {}

   private:
    _sfile& operator=(const _sfile&);
  } sfile_t;
  typedef std::list<sfile_t> sfile_list_t;
  // -------------------------------------------------
  // public methods
  // -------------------------------------------------
  stub(void);
  ~stub(void);
  int32_t init(const std::string& a_info_name, size_t a_info_len,
               const files_list_t& a_file_list);
  // -------------------------------------------------
  // writing/reading/validating
  // -------------------------------------------------
  int32_t write(const uint8_t* a_buf, size_t a_off, size_t a_len);
  int32_t read(nbq* a_q, size_t a_off, size_t a_len);
  int32_t calc_sha1(id_t& ao_sha1, size_t a_off, size_t a_len);
  void display(void);

 private:
  // -------------------------------------------------
  // private methods
  // -------------------------------------------------
  // disallow copy/assign
  stub(const stub&);
  stub& operator=(const stub&);
  int32_t init_sfile(sfile_t& a_sfile);
  // -------------------------------------------------
  // private members
  // -------------------------------------------------
  bool m_init;
  sfile_list_t m_sfile_list;
};
}  // namespace ns_ntrnt
#endif
