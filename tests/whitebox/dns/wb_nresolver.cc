//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <string.h>
#include <string>
#include "catch/catch.hpp"
#include "dns/nresolver.h"
#include "ntrnt/def.h"
#include "support/ndebug.h"
//! ----------------------------------------------------------------------------
//! Tests
//! ----------------------------------------------------------------------------
TEST_CASE("nresolver test", "[dns]") {
  // -------------------------------------------------
  // is_valid_ip
  // -------------------------------------------------
  SECTION("is_valid_ip") {
    bool l_s;
    l_s = ns_ntrnt::is_valid_ip_address("127.0.0.1");
    REQUIRE((l_s == true));
    l_s = ns_ntrnt::is_valid_ip_address("wibblies");
    REQUIRE((l_s == false));
    l_s = ns_ntrnt::is_valid_ip_address("2a03:2880:f10d:83:face:b00c:0:25de");
    REQUIRE((l_s == true));
  }
}
