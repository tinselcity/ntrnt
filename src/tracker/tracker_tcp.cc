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
#include "support/trace.h"
#include "support/ndebug.h"
#include "support/data.h"
#include "support/util.h"
#include "support/net_util.h"
#include "core/torrent.h"
#include "core/session.h"
#include "http_parser/http_parser.h"
// ---------------------------------------------------------
// sha1
// ---------------------------------------------------------
#include <openssl/sha.h>
// ---------------------------------------------------------
// std
// ---------------------------------------------------------
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
// ---------------------------------------------------------
// stl
// ---------------------------------------------------------
#include <map>
#include <sstream>

#include "tracker_tcp.h"

#include "tracker_tcp_rqst.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _REQUEST_SIZE 16384
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
tracker_tcp::tracker_tcp(void):
                tracker()
{
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
tracker_tcp::~tracker_tcp(void)
{
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t tracker_tcp::announce(session& a_session, torrent& a_torrent)
{
        // -------------------------------------------------
        // get ipv6
        // -------------------------------------------------
        std::string l_ipv6_str = get_public_address_v6_str();
        std::string l_ipv6_enc;
        http_escape(l_ipv6_enc, l_ipv6_str, true);
        // -------------------------------------------------
        // create info hash
        // -------------------------------------------------
        char l_info_hash_encoded[64];
        encode_digest(l_info_hash_encoded, a_torrent.get_info_hash(), SHA_DIGEST_LENGTH);
        // -------------------------------------------------
        // create request
        // -------------------------------------------------
        tracker_tcp_rqst *l_rqst = new tracker_tcp_rqst();
        l_rqst->m_scheme = m_scheme;
        l_rqst->m_port = m_port;
        l_rqst->m_host = m_host;
        l_rqst->m_path = m_root;
        l_rqst->m_verb = "GET";
        // -------------------------------------------------
        // set query string
        // -------------------------------------------------
#if 0
        info_hash=%e1%e5i%d5%d9%bdX%01icP%5b%af%0f%02%16%dc%5d%a0%c9
        peer_id=-TR300Z-mb168nasia07
        port=51413
        uploaded=0
        downloaded=0
        left=1130114013
        numwant=80
        key=8535250
        compact=1
        supportcrypto=1
        event=started
        ipv6=2603:8001:8b01:dd0c:597:6213:dc56:15d9
#endif
        l_rqst->set_query("info_hash", l_info_hash_encoded);
        l_rqst->set_query("peer_id", get_peer_id().c_str());
        l_rqst->set_query("port", "51413");
        l_rqst->set_query("uploaded", "0");
        l_rqst->set_query("downloaded", "0");
        l_rqst->set_query("left", "1130114013");
        l_rqst->set_query("numwant", "80");
        l_rqst->set_query("key", "8535250");
        l_rqst->set_query("compact", "1");
        l_rqst->set_query("supportcrypto", "1");
        l_rqst->set_query("event", "started");
        l_rqst->set_query("ipv6", l_ipv6_enc);
        // -------------------------------------------------
        // enqueue
        // -------------------------------------------------
        int32_t l_s;
        l_s = a_session.enqueue(*l_rqst);
        if (l_s != NTRNT_STATUS_OK)
        {
                // TODO --cancel pending...
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
}
