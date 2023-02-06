//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "ntrnt/types.h"
#include "support/peer_id.h"
#include "support/ndebug.h"
#include <string.h>
#include <array>
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#define _FORMATTER(_type) std::string _formatter_##_type(const char* a_name, size_t a_name_len, const peer_id_t& a_id)
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::string (*_formatter_t)(const char* a_name, size_t a_name_len, const peer_id_t& a_id);
struct _client
{
    const char* m_prefix;
    const size_t m_prefix_len;
    const char* m_name;
    const size_t m_name_len;
    _formatter_t m_formatter;
    _client(const char* a_prefix, const char* a_name, _formatter_t a_formatter):
            m_prefix(a_prefix),
            m_prefix_len(strlen(m_prefix)),
            m_name(a_name),
            m_name_len(strlen(m_name)),
            m_formatter(a_formatter)
    {}
};
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                     G E N E R I C   F O R M A T T E R S
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(no_version)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(three_digit)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(four_digit)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(two_major_two_minor)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                  S P E C I F I C   A P P L I C A T I O N S
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(bitbuddy)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(bitlord)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(bits_on_wheels)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(bitrocket)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(utorrent)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(ctorrent)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(folx)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(ktorrent)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(mediaget)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(mldonkey)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(picotorrent)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(xtorrent)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(xfplay)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(aria2)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(blizzard)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(bittorrent_dna)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(mainline)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(burst)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(opera)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(plus)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(qvod)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(amazon)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(xbt)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(btpd)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
_FORMATTER(transmission)
{
        std::string l_str;
        l_str.assign(a_name, a_name_len);
        // TODO
        return l_str;
}
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                              C L I E N T S
//! ****************************************************************************
//! ----------------------------------------------------------------------------
const std::array<_client, 131> g_clients =
{ {
        { "-AD", "Advanced Download Manager", _formatter_three_digit},
        { "-AG", "Ares", _formatter_four_digit},
        { "-AR", "Arctic", _formatter_four_digit},
        { "-AT", "Artemis", _formatter_four_digit},
        { "-AV", "Avicora", _formatter_four_digit},
        { "-AX", "BitPump", _formatter_two_major_two_minor},
        { "-AZ", "Azureus / Vuze", _formatter_four_digit},
        { "-A~", "Ares", _formatter_three_digit},
        { "-BB", "BitBuddy", _formatter_bitbuddy},
        { "-BC", "BitComet", _formatter_two_major_two_minor},
        { "-BE", "BitTorrent SDK", _formatter_four_digit},
        { "-BF", "BitFlu", _formatter_no_version},
        { "-BG", "BTGetit", _formatter_four_digit},
        { "-BH", "BitZilla", _formatter_four_digit},
        { "-BI", "BiglyBT", _formatter_four_digit},
        { "-BL", "BitLord", _formatter_bitlord},
        { "-BM", "BitMagnet", _formatter_four_digit},
        { "-BN", "Baidu Netdisk", _formatter_no_version},
        { "-BOW", "Bits on Wheels", _formatter_bits_on_wheels},
        { "-BP", "BitTorrent Pro (Azureus + Spyware)", _formatter_four_digit},
        { "-BR", "BitRocket", _formatter_bitrocket},
        { "-BS", "BTSlave", _formatter_four_digit},
        { "-BT", "BitTorrent", _formatter_utorrent},
        { "-BW", "BitTorrent Web", _formatter_utorrent},
        { "-BX", "BittorrentX", _formatter_four_digit},
        { "-CD", "Enhanced CTorrent", _formatter_two_major_two_minor},
        { "-CT", "CTorrent", _formatter_ctorrent},
        { "-DE", "Deluge", _formatter_four_digit},
        { "-DP", "Propagate Data Client", _formatter_four_digit},
        { "-EB", "EBit", _formatter_four_digit},
        { "-ES", "Electric Sheep", _formatter_three_digit},
        { "-FC", "FileCroc", _formatter_four_digit},
        { "-FD", "Free Download Manager", _formatter_three_digit},
        { "-FG", "FlashGet", _formatter_two_major_two_minor},
        { "-FL", "Folx", _formatter_folx},
        { "-FT", "FoxTorrent/RedSwoosh", _formatter_four_digit},
        { "-FW", "FrostWire", _formatter_three_digit},
        { "-FX", "Freebox", _formatter_four_digit},
        { "-G3", "G3 Torrent", _formatter_no_version},
        { "-GR", "GetRight", _formatter_four_digit},
        { "-GS", "GSTorrent", _formatter_four_digit},
        { "-HK", "Hekate", _formatter_four_digit},
        { "-HL", "Halite", _formatter_three_digit},
        { "-HN", "Hydranode", _formatter_four_digit},
        { "-KG", "KGet", _formatter_four_digit},
        { "-KT", "KTorrent", _formatter_ktorrent},
        { "-LC", "LeechCraft", _formatter_four_digit},
        { "-LH", "LH-ABC", _formatter_four_digit},
        { "-LP", "Lphant", _formatter_two_major_two_minor},
        { "-LT", "libtorrent (Rasterbar)", _formatter_three_digit},
        { "-LW", "LimeWire", _formatter_no_version},
        { "-Lr", "LibreTorrent", _formatter_three_digit},
        { "-MG", "MediaGet", _formatter_mediaget},
        { "-MK", "Meerkat", _formatter_four_digit},
        { "-ML", "MLDonkey", _formatter_mldonkey},
        { "-MO", "MonoTorrent", _formatter_four_digit},
        { "-MP", "MooPolice", _formatter_three_digit},
        { "-MR", "Miro", _formatter_four_digit},
        { "-MT", "Moonlight", _formatter_four_digit},
        { "-NE", "BT Next Evolution", _formatter_four_digit},
        { "-NX", "Net Transport", _formatter_four_digit},
        { "-OS", "OneSwarm", _formatter_four_digit},
        { "-OT", "OmegaTorrent", _formatter_four_digit},
        { "-PD", "Pando", _formatter_four_digit},
        { "-PI", "PicoTorrent", _formatter_picotorrent},
        { "-QD", "QQDownload", _formatter_four_digit},
        { "-QT", "QT 4 Torrent example", _formatter_four_digit},
        { "-RS", "Rufus", _formatter_four_digit},
        { "-RT", "Retriever", _formatter_four_digit},
        { "-RZ", "RezTorrent", _formatter_four_digit},
        { "-SB", "~Swiftbit", _formatter_four_digit},
        { "-SD", "Thunder", _formatter_four_digit},
        { "-SM", "SoMud", _formatter_four_digit},
        { "-SP", "BitSpirit", _formatter_three_digit},
        { "-SS", "SwarmScope", _formatter_four_digit},
        { "-ST", "SymTorrent", _formatter_four_digit},
        { "-SZ", "Shareaza", _formatter_four_digit},
        { "-S~", "Shareaza", _formatter_four_digit},
        { "-TB", "Torch Browser", _formatter_no_version},
        { "-TN", "Torrent .NET", _formatter_four_digit},
        { "-TR", "Transmission", _formatter_transmission },
        { "-TS", "Torrentstorm", _formatter_four_digit},
        { "-TT", "TuoTu", _formatter_four_digit},
        { "-UE", "\xc2\xb5Torrent Embedded", _formatter_utorrent},
        { "-UL", "uLeecher!", _formatter_four_digit},
        { "-UM", "\xc2\xb5Torrent Mac", _formatter_utorrent},
        { "-UT", "\xc2\xb5Torrent", _formatter_utorrent},
        { "-UW", "\xc2\xb5Torrent Web", _formatter_utorrent},
        { "-VG", "Vagaa", _formatter_four_digit},
        { "-WS", "HTTP Seed", _formatter_no_version},
        { "-WT", "BitLet", _formatter_four_digit},
        { "-WT-", "BitLet", _formatter_no_version},
        { "-WW", "WebTorrent", _formatter_four_digit},
        { "-WY", "FireTorrent", _formatter_four_digit},
        { "-XC", "Xtorrent", _formatter_xtorrent},
        { "-XF", "Xfplay", _formatter_xfplay},
        { "-XL", "Xunlei", _formatter_four_digit},
        { "-XS", "XSwifter", _formatter_four_digit},
        { "-XT", "XanTorrent", _formatter_four_digit},
        { "-XX", "Xtorrent", _formatter_xtorrent},
        { "-ZO", "Zona", _formatter_four_digit},
        { "-ZT", "Zip Torrent", _formatter_four_digit},
        { "-bk", "BitKitten (libtorrent)", _formatter_four_digit},
        { "-lt", "libTorrent (Rakshasa)", _formatter_three_digit},
        { "-pb", "pbTorrent", _formatter_three_digit},
        { "-qB", "qBittorrent", _formatter_three_digit },
        { "-st", "SharkTorrent", _formatter_four_digit},
        { "10-------", "JVtorrent", _formatter_no_version},
        { "346-", "TorrentTopia", _formatter_no_version},
        { "A2", "aria2", _formatter_aria2},
        { "AZ2500BT", "BitTyrant (Azureus Mod)", _formatter_no_version},
        { "BLZ", "Blizzard Downloader", _formatter_blizzard},
        { "DNA", "BitTorrent DNA", _formatter_bittorrent_dna},
        { "FD6", "Free Download Manager 6", _formatter_no_version},
        { "LIME", "Limewire", _formatter_no_version},
        { "M", "BitTorrent", _formatter_mainline},
        { "Mbrst", "burst!", _formatter_burst},
        { "OP", "Opera", _formatter_opera},
        { "Pando", "Pando", _formatter_no_version},
        { "Plus", "Plus!", _formatter_plus},
        { "Q", "Queen Bee", _formatter_mainline},
        { "QVOD", "QVOD", _formatter_qvod},
        { "S3", "Amazon S3", _formatter_amazon},
        { "TIX", "Tixati", _formatter_two_major_two_minor},
        { "XBT", "XBT Client", _formatter_xbt},
        { "a00---0", "Swarmy", _formatter_no_version},
        { "a02---0", "Swarmy", _formatter_no_version},
        { "aria2-", "aria2", _formatter_no_version},
        { "btpd", "BT Protocol Daemon", _formatter_btpd},
        { "eX", "eXeem", _formatter_no_version},
        { "martini", "Martini Man", _formatter_no_version},
} };
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
std::string peer_id_to_str(peer_id_t& a_peer_id)
{
        // -------------------------------------------------
        // TODO -awful algo -O(N*M)
        // N -number of clients
        // M -prefix length per client
        // search entire client list for longest match
        // -------------------------------------------------
        size_t l_lm = 0;
        _formatter_t l_fm = nullptr;
        size_t l_idx = 0;
        size_t i_idx = 0;
        for (auto && i_c : g_clients)
        {
                if (memcmp(a_peer_id.m_data, i_c.m_prefix, i_c.m_prefix_len) == 0)
                {
                        if (i_c.m_prefix_len > l_lm)
                        {
                                l_idx = i_idx;
                                l_fm = i_c.m_formatter;
                                l_lm = i_c.m_prefix_len;
                        }
                }
                ++i_idx;
        }
        if (!l_fm)
        {
                return "__na__";
        }
        return l_fm(g_clients[l_idx].m_name, g_clients[l_idx].m_name_len, a_peer_id);
}
}
