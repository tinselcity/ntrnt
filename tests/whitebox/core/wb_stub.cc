//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "ntrnt/def.h"
#include "ntrnt/types.h"
#include "support/ndebug.h"
#include "support/util.h"
#include "core/stub.h"
//! ----------------------------------------------------------------------------
//!
//! ----------------------------------------------------------------------------
const uint8_t g_test_dat[64] = {
        0x2d, 0x71, 0x42, 0x34, 0x33, 0x35, 0x30, 0x2d,
        0x6e, 0x32, 0x2a, 0x70, 0x71, 0x54, 0x66, 0x68,
        0x2d, 0x71, 0x42, 0x34, 0x33, 0x35, 0x30, 0x2d,
        0x6e, 0x32, 0x2a, 0x70, 0x71, 0x54, 0x66, 0x68,
        0x2d, 0x71, 0x42, 0x34, 0x33, 0x35, 0x30, 0x2d,
        0x6e, 0x32, 0x2a, 0x70, 0x71, 0x54, 0x66, 0x68,
        0x2d, 0x71, 0x42, 0x34, 0x33, 0x35, 0x30, 0x2d,
        0x6e, 0x32, 0x2a, 0x70, 0x71, 0x54, 0x66, 0x68
};
//! ----------------------------------------------------------------------------
//! Tests
//! ----------------------------------------------------------------------------
TEST_CASE( "stub", "[stub]" ) {
        // -------------------------------------------------
        // validate peer map works correctly (mostly)
        // -------------------------------------------------
        SECTION("stub basic") {
                std::string l_file = "test.dat";
                size_t l_file_len = 128;
                ns_ntrnt::files_list_t l_fl;
                ns_ntrnt::stub l_stub;
                int32_t l_s;
                // -----------------------------------------
                // init
                // -----------------------------------------
                l_s = l_stub.init(l_file, l_file_len, l_fl);
                REQUIRE((l_s == NTRNT_STATUS_OK));
                // -----------------------------------------
                // write
                // -----------------------------------------
                l_s = l_stub.write(g_test_dat, 64, sizeof(g_test_dat));
                REQUIRE((l_s == NTRNT_STATUS_OK));
                // -----------------------------------------
                // write
                // -----------------------------------------
                ns_ntrnt::id_t l_id;
                l_s = l_stub.calc_sha1(l_id, 64, sizeof(g_test_dat));
                REQUIRE((l_s == NTRNT_STATUS_OK));
                NDBG_PRINT("id: %s\n", ns_ntrnt::id2str(l_id).c_str());
                l_s = l_stub.calc_sha1(l_id, 0, sizeof(g_test_dat));
                REQUIRE((l_s == NTRNT_STATUS_OK));
                NDBG_PRINT("id: %s\n", ns_ntrnt::id2str(l_id).c_str());
        }
}
