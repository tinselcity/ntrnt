//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "ntrnt/def.h"
#include "support/net_util.h"
#include "support/ndebug.h"
#include <string.h>
#include <string>
//! ----------------------------------------------------------------------------
//! Tests
//! ----------------------------------------------------------------------------
TEST_CASE( "net util test", "[net_util]" ) {
        // -------------------------------------------------
        // string conversion tests
        // -------------------------------------------------
        SECTION("sockaddr string conversions ipv6") {
                struct sockaddr_storage l_sas;
                std::string l_str;
                std::string l_str_cvt;
                int32_t l_s;
                // -----------------------------------------
                // ipv4
                // -----------------------------------------
                l_str = "122.4.45.122:12345";
                l_s = ns_ntrnt::str_to_sas(l_str, l_sas);
                REQUIRE((l_s == NTRNT_STATUS_OK));
                l_str_cvt = ns_ntrnt::sas_to_str(l_sas);
                REQUIRE((l_str_cvt == l_str));
                // -----------------------------------------
                // ipv6
                // -----------------------------------------
                l_str = "[2001:db8:1234:ffff:ffff:ffff:ffff:ffff]:12345";
                l_s = ns_ntrnt::str_to_sas(l_str, l_sas);
                REQUIRE((l_s == NTRNT_STATUS_OK));
                l_str_cvt = ns_ntrnt::sas_to_str(l_sas);
                REQUIRE((l_str_cvt == l_str));
        }
}
