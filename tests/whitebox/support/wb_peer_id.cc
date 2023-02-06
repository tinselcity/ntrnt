//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "ntrnt/types.h"
#include "ntrnt/def.h"
#include "support/peer_id.h"
#include "support/ndebug.h"
#include <stdint.h>
#include <string.h>
#include <string>
//! ----------------------------------------------------------------------------
//! sample
//! ----------------------------------------------------------------------------
const uint8_t g_peer_id_qb_v1[20] = {
        0x2d, 0x71, 0x42, 0x34,
        0x33, 0x35, 0x30, 0x2d,
        0x6e, 0x32, 0x2a, 0x70,
        0x71, 0x54, 0x66, 0x68,
        0x79, 0x61, 0x4a, 0x75
};
//! ----------------------------------------------------------------------------
//! sample
//! ----------------------------------------------------------------------------
const uint8_t g_peer_id_qb_v2[20] = {
        0x2d, 0x71, 0x42, 0x34,
        0x35, 0x30, 0x30, 0x2d,
        0x5f, 0x2a, 0x67, 0x69,
        0x32, 0x66, 0x52, 0x6b,
        0x31, 0x44, 0x30, 0x43
};
//! ----------------------------------------------------------------------------
//! sample
//! ----------------------------------------------------------------------------
const uint8_t g_peer_id_tr_v1[20] = {
        0x2d, 0x54, 0x52, 0x33,
        0x30, 0x30, 0x30, 0x2d,
        0x68, 0x39, 0x30, 0x64,
        0x77, 0x6c, 0x74, 0x6a,
        0x72, 0x6e, 0x65, 0x63
};
//! ----------------------------------------------------------------------------
//! Tests
//! ----------------------------------------------------------------------------
TEST_CASE( "peer id", "[peer_id]" ) {
        // -------------------------------------------------
        // validate bitfield (btfield) works correctly (mostly)
        // -------------------------------------------------
        SECTION("peer_id basic") {
                std::string l_peer_str;
                ns_ntrnt::peer_id_t l_id;
                memcpy(l_id.m_data, g_peer_id_qb_v1, sizeof(l_id));
                l_peer_str = ns_ntrnt::peer_id_to_str(l_id);
                REQUIRE((l_peer_str == "qBittorrent"));
                memcpy(l_id.m_data, g_peer_id_qb_v2, sizeof(l_id));
                l_peer_str = ns_ntrnt::peer_id_to_str(l_id);
                REQUIRE((l_peer_str == "qBittorrent"));
                memcpy(l_id.m_data, g_peer_id_tr_v1, sizeof(l_id));
                l_peer_str = ns_ntrnt::peer_id_to_str(l_id);
                REQUIRE((l_peer_str == "Transmission"));
        }
}
