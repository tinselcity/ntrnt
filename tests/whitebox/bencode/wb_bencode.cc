//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "bencode/bencode.h"
#include "catch/catch.hpp"
#include "ntrnt/def.h"
#include "support/ndebug.h"
//! ----------------------------------------------------------------------------
//! Tests
//! ----------------------------------------------------------------------------
TEST_CASE("bencode", "[bencode]") {
  //ns_ntrnt::trc_log_level_set(ns_ntrnt::TRC_LOG_LEVEL_NONE);
  SECTION("bencode_writer") {
    // -----------------------------------------
    // write to buffer
    // -----------------------------------------
    ns_ntrnt::bencode_writer l_bw;
    l_bw.w_key("e");
    l_bw.w_int(1);
    l_bw.w_key("metadata_size");
    l_bw.w_int(28024);
    l_bw.w_key("p");
    l_bw.w_int(51413);
    l_bw.w_key("reqq");
    l_bw.w_int(512);
    l_bw.w_key("upload_only");
    l_bw.w_int(1);
    l_bw.w_key("v");
    l_bw.w_string("Ntrnt 0.0.0");
    l_bw.w_key("m");
    l_bw.w_start_dict();
    l_bw.w_key("ut_metadata");
    l_bw.w_int(3);
    l_bw.w_key("ut_pex");
    l_bw.w_int(1);
    l_bw.w_end_dict();
    const uint8_t* l_buf = nullptr;
    size_t l_buf_len = 0;
    l_bw.serialize(&l_buf, l_buf_len);
    // -----------------------------------------
    // parse
    // -----------------------------------------
    int32_t l_s;
    ns_ntrnt::bdecode l_bd;
    l_s = l_bd.init((const char*)l_buf, l_buf_len);
    REQUIRE((l_s == NTRNT_STATUS_OK));
  }
}
