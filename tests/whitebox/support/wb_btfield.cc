//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "ntrnt/def.h"
#include "support/btfield.h"
#include "support/ndebug.h"
#include <string.h>
#include <string>
//! ----------------------------------------------------------------------------
//! Tests
//! ----------------------------------------------------------------------------
TEST_CASE( "bitfield", "[btfield]" ) {
        // -------------------------------------------------
        // validate bitfield (btfield) works correctly (mostly)
        // -------------------------------------------------
        SECTION("btfield basic") {
                int32_t l_s;
                ns_ntrnt::btfield l_btfield;
                REQUIRE((l_btfield.get_size() == 0));
                uint8_t l_raw[3] = { 0xAF, 0xFF, 0xA0 };
                l_s = l_btfield.import_raw(l_raw, 3, 26);
                REQUIRE((l_s == NTRNT_STATUS_ERROR));
                l_s = l_btfield.import_raw(l_raw, 3, 22);
                REQUIRE((l_s == NTRNT_STATUS_OK));
                REQUIRE((l_btfield.get_size() == 22));
                REQUIRE((l_btfield.test(25) == false));
                // -----------------------------------------
                // check is set
                // -----------------------------------------
                REQUIRE((l_btfield.test( 0) == true));
                REQUIRE((l_btfield.test( 1) == false));
                REQUIRE((l_btfield.test( 2) == true));
                REQUIRE((l_btfield.test( 3) == false));
                REQUIRE((l_btfield.test(16) == true));
                REQUIRE((l_btfield.test(17) == false));
                REQUIRE((l_btfield.test(18) == true));
                REQUIRE((l_btfield.test(19) == false));
                REQUIRE((l_btfield.test(20) == false));
                REQUIRE((l_btfield.test(21) == false));
                // -----------------------------------------
                // verify export
                // -----------------------------------------
                uint8_t* l_exp_raw = nullptr;
                size_t l_exp_raw_len = 0;
                l_s = l_btfield.export_raw(&l_exp_raw, l_exp_raw_len);
                REQUIRE((l_s == NTRNT_STATUS_OK));
                REQUIRE((l_exp_raw_len == sizeof(l_raw)));
                REQUIRE((memcmp(l_exp_raw, l_raw, sizeof(l_raw)) == 0));
        }
        // -------------------------------------------------
        // validate bitfield has_all/has_none
        // -------------------------------------------------
        SECTION("btfield has_all/has_none") {
                int32_t l_s;
                ns_ntrnt::btfield l_btfield;
                REQUIRE((l_btfield.get_size() == 0));
                uint8_t l_raw[3] = { 0xFF, 0xFF, 0xF0 };
                l_s = l_btfield.import_raw(l_raw, 3, 24);
                REQUIRE((l_s == NTRNT_STATUS_OK));
                REQUIRE((l_btfield.has_all() == false));
                REQUIRE((l_btfield.has_none() == false));
                l_s = l_btfield.import_raw(l_raw, 3, 20);
                REQUIRE((l_s == NTRNT_STATUS_OK));
                REQUIRE((l_btfield.has_all() == true));
                REQUIRE((l_btfield.has_none() == false));
                uint8_t l_rawz[3] = { 0x00, 0x00, 0x00 };
                l_s = l_btfield.import_raw(l_rawz, 3, 24);
                REQUIRE((l_s == NTRNT_STATUS_OK));
                REQUIRE((l_btfield.has_all() == false));
                REQUIRE((l_btfield.has_none() == true));
        }
}
