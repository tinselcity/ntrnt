//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "ntrnt/def.h"
#include "support/net_util.h"
#include "core/peer_mgr.h"
#include "core/peer.h"
#include "support/ndebug.h"
#include <string.h>
#include <string>
//! ----------------------------------------------------------------------------
//! Tests
//! ----------------------------------------------------------------------------
TEST_CASE( "peer map", "[peer_map]" ) {
        // -------------------------------------------------
        // validate peer map works correctly (mostly)
        // -------------------------------------------------
        SECTION("peer_map") {
                int32_t l_s;
                ns_ntrnt::peer_map_t l_pm;
                // -----------------------------------------
                // compare two
                // -----------------------------------------
                struct sockaddr_storage l_sas1;
                std::string l_sas_str1;
                // -----------------------------------------
                // add one
                // -----------------------------------------
                l_sas_str1 = "122.4.45.122:12345";
                l_s = ns_ntrnt::str_to_sas(l_sas_str1, l_sas1);
                REQUIRE((l_s == NTRNT_STATUS_OK));
                l_pm[l_sas1] = (ns_ntrnt::peer*)(0xDEADBEEF);
                REQUIRE((l_pm.size() == 1));
                // -----------------------------------------
                // add same
                // -----------------------------------------
                l_sas_str1 = "122.4.45.122:12345";
                l_s = ns_ntrnt::str_to_sas(l_sas_str1, l_sas1);
                REQUIRE((l_s == NTRNT_STATUS_OK));
                l_pm[l_sas1] = (ns_ntrnt::peer*)(0xDEADDEAD);
                REQUIRE((l_pm.size() == 1));
                // -----------------------------------------
                // add new by port
                // -----------------------------------------
                l_sas_str1 = "122.4.45.122:12346";
                l_s = ns_ntrnt::str_to_sas(l_sas_str1, l_sas1);
                REQUIRE((l_s == NTRNT_STATUS_OK));
                l_pm[l_sas1] = (ns_ntrnt::peer*)(0xDEADDEAD);
                REQUIRE((l_pm.size() == 2));
                // -----------------------------------------
                // add new by address
                // -----------------------------------------
                l_sas_str1 = "122.4.45.123:12345";
                l_s = ns_ntrnt::str_to_sas(l_sas_str1, l_sas1);
                REQUIRE((l_s == NTRNT_STATUS_OK));
                l_pm[l_sas1] = (ns_ntrnt::peer*)(0xDEADDEAD);
                REQUIRE((l_pm.size() == 3));
                // -----------------------------------------
                // check values
                // -----------------------------------------
#if 0
                for (auto && i_p : l_pm)
                {
                        std::string l_str;
                        l_str = ns_ntrnt::sas_to_str(i_p.first);
                        NDBG_PRINT("address: %s\n", l_str.c_str());
                }
#endif
        }
}
