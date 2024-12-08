//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
// ---------------------------------------------------------
// external includes
// ---------------------------------------------------------
#include "ntrnt/def.h"
// ---------------------------------------------------------
// internal includes
// ---------------------------------------------------------
#include "conn/scheme.h"
#include "support/data.h"
// ---------------------------------------------------------
// stl
// ---------------------------------------------------------
#include <map>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::map<std::string, scheme_t, case_i_comp> str_scheme_map_t;
typedef std::map<scheme_t, std::string> scheme_str_map_t;
//! ----------------------------------------------------------------------------
//! initialize the map statically
//! ----------------------------------------------------------------------------
const str_scheme_map_t::value_type g_str_scheme_map_pairs[] = {
    str_scheme_map_t::value_type("none", SCHEME_NONE),
    str_scheme_map_t::value_type("http", SCHEME_TCP),
    str_scheme_map_t::value_type("https", SCHEME_TLS),
    str_scheme_map_t::value_type("udp", SCHEME_UDP),
    str_scheme_map_t::value_type("wss", SCHEME_WSS)};
const str_scheme_map_t g_str_scheme_map(
    g_str_scheme_map_pairs,
    g_str_scheme_map_pairs +
        (sizeof(g_str_scheme_map_pairs) / sizeof(g_str_scheme_map_pairs[0])));
//! ----------------------------------------------------------------------------
//! agg function mapping
//! Initialize the map statically
//! ----------------------------------------------------------------------------
const scheme_str_map_t::value_type g_scheme_str_map_pairs[] = {
    scheme_str_map_t::value_type(SCHEME_NONE, "none"),
    scheme_str_map_t::value_type(SCHEME_TCP, "http"),
    scheme_str_map_t::value_type(SCHEME_TLS, "https"),
    scheme_str_map_t::value_type(SCHEME_UDP, "udp"),
    scheme_str_map_t::value_type(SCHEME_WSS, "wss")};
const scheme_str_map_t g_scheme_str_map(
    g_scheme_str_map_pairs,
    g_scheme_str_map_pairs +
        (sizeof(g_scheme_str_map_pairs) / sizeof(g_scheme_str_map_pairs[0])));
//! ----------------------------------------------------------------------------
//!  \details TODO
//!  \return  TODO
//!  \param   TODO
//! ----------------------------------------------------------------------------
scheme_t get_scheme(const std::string& a_str) {
  scheme_t l_agg = SCHEME_NONE;
  str_scheme_map_t::const_iterator i_a = g_str_scheme_map.find(a_str);
  if (i_a != g_str_scheme_map.end()) {
    l_agg = i_a->second;
  }
  return l_agg;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
std::string get_scheme_str(scheme_t a_scheme) {
  std::string l_str = "none";
  scheme_str_map_t::const_iterator i_a = g_scheme_str_map.find(a_scheme);
  if (i_a != g_scheme_str_map.end()) {
    l_str = i_a->second;
  }
  return l_str;
}
}  // namespace ns_ntrnt
