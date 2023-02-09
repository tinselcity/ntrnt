//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "ntrnt/def.h"
#include "ntrnt/types.h"
#include "support/ndebug.h"
#include "support/util.h"
#include "support/nbq.h"
#include "core/stub.h"
#include <string.h>
//! ----------------------------------------------------------------------------
//!
//! ----------------------------------------------------------------------------
const uint8_t g_zeros_dat[64] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
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
        // validate stub for single file
        // -------------------------------------------------
        SECTION("stub single file") {
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
                // calc sha
                // -----------------------------------------
                ns_ntrnt::id_t l_id;
                std::string l_exp;
                l_exp = "4498093bf7445b077ab54eb13737b493f72dda3c";
                l_s = l_stub.calc_sha1(l_id, 64, sizeof(g_test_dat));
                REQUIRE((l_s == NTRNT_STATUS_OK));
                REQUIRE((ns_ntrnt::id2str(l_id) == l_exp));
                l_exp = "c8d7d0ef0eedfa82d2ea1aa592845b9a6d4b02b7";
                l_s = l_stub.calc_sha1(l_id, 0, sizeof(g_test_dat));
                REQUIRE((l_s == NTRNT_STATUS_OK));
                REQUIRE((ns_ntrnt::id2str(l_id) == l_exp));
                // -----------------------------------------
                // read
                // -----------------------------------------
                off_t l_rs;
                uint8_t l_buf[64];
                ns_ntrnt::nbq l_q(1024);
                // -----------------------------------------
                // read first part
                // -----------------------------------------
                l_s = l_stub.read(&l_q, 0, 64);
                REQUIRE((l_s == NTRNT_STATUS_OK));
                l_rs = l_q.read((char*)l_buf, 64);
                REQUIRE((l_rs == 64));
                REQUIRE((memcmp(l_buf, g_zeros_dat, sizeof(g_zeros_dat)) == 0));
                // -----------------------------------------
                // read 2nd part
                // -----------------------------------------
                l_s = l_stub.read(&l_q, 64, 64);
                REQUIRE((l_s == NTRNT_STATUS_OK));
                l_rs = l_q.read((char*)l_buf, 64);
                REQUIRE((l_rs == 64));
                REQUIRE((memcmp(l_buf, g_test_dat, sizeof(g_test_dat)) == 0));
        }
        // -------------------------------------------------
        // validate stub for single file
        // -------------------------------------------------
        SECTION("stub multi file") {
                std::string l_file = "test";
                size_t l_file_len = 128;
                ns_ntrnt::files_list_t l_fl;
                ns_ntrnt::files_t l_f;
                // -----------------------------------------
                // add file
                // -----------------------------------------
                l_f.m_len = 0; l_f.m_path.clear();
                l_f.m_len = 64;
                l_f.m_path.push_back("file1.dat");
                l_fl.push_back(l_f);
                // -----------------------------------------
                // add file
                // -----------------------------------------
                l_f.m_len = 0; l_f.m_path.clear();
                l_f.m_len = 64;
                l_f.m_path.push_back("file2.dat");
                l_fl.push_back(l_f);
                // -----------------------------------------
                // init
                // -----------------------------------------
                ns_ntrnt::stub l_stub;
                int32_t l_s;
                l_s = l_stub.init(l_file, l_file_len, l_fl);
                REQUIRE((l_s == NTRNT_STATUS_OK));
                // -----------------------------------------
                // write
                // -----------------------------------------
                l_s = l_stub.write(g_zeros_dat, 0, sizeof(g_zeros_dat));
                REQUIRE((l_s == NTRNT_STATUS_OK));
                l_s = l_stub.write(g_zeros_dat, 64, sizeof(g_zeros_dat));
                REQUIRE((l_s == NTRNT_STATUS_OK));
                // -----------------------------------------
                // write
                // -----------------------------------------
                l_s = l_stub.write(g_test_dat, 32, sizeof(g_test_dat));
                REQUIRE((l_s == NTRNT_STATUS_OK));
                // -----------------------------------------
                // read 2nd part
                // -----------------------------------------
                off_t l_rs;
                uint8_t l_buf[64];
                ns_ntrnt::nbq l_q(1024);
                l_s = l_stub.read(&l_q, 32, 64);
                REQUIRE((l_s == NTRNT_STATUS_OK));
                l_rs = l_q.read((char*)l_buf, 64);
                REQUIRE((l_rs == 64));
                REQUIRE((memcmp(l_buf, g_test_dat, sizeof(g_test_dat)) == 0));
        }
}
