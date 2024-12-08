//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <string.h>
#include <string>
#include "catch/catch.hpp"
#include "ntrnt/def.h"
#include "support/ndebug.h"
#include "support/util.h"
//! ----------------------------------------------------------------------------
//! Tests
//! ----------------------------------------------------------------------------
TEST_CASE("util test", "[util]") {
  // -------------------------------------------------
  // hex to binary
  // -------------------------------------------------
  SECTION("hex2bin") {
    std::string l_hex = "7d8f057f09bd5cc4fc3577603577119728974b9a";
    uint8_t l_buf[20];
    size_t l_buf_len = 0;
    int32_t l_s;
    // -----------------------------------------
    // convert hex to binary
    // -----------------------------------------
    l_s = ns_ntrnt::hex2bin(l_buf, l_buf_len, l_hex.c_str(), l_hex.length());
    REQUIRE((l_s == NTRNT_STATUS_OK));
    REQUIRE((l_buf_len == 20));
    // -----------------------------------------
    // convert binary back to hex
    // -----------------------------------------
    char* l_hex_out = nullptr;
    l_s = ns_ntrnt::bin2hex(&l_hex_out, l_buf, l_buf_len);
    REQUIRE((l_s == NTRNT_STATUS_OK));
    std::string l_cmp = l_hex_out;
    REQUIRE((l_cmp == l_hex));
    if (l_hex_out) {
      free(l_hex_out);
      l_hex_out = nullptr;
    }
  }
}
