//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "ntrnt/def.h"
#include "support/util.h"
#include "support/time_util.h"
#include "support/net_util.h"
#include "support/ndebug.h"
#include "core/session.h"
#include "core/tracker.h"
#include "core/peer.h"
// ---------------------------------------------------------
// rapidjson
// ---------------------------------------------------------
#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/prettywriter.h"
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::api_get_info(std::string& ao_body)
{
        // -------------------------------------------------
        // create body...
        // -------------------------------------------------
        rapidjson::StringBuffer l_strbuf;
        rapidjson::Writer<rapidjson::StringBuffer> l_writer(l_strbuf);
        l_writer.StartObject();
        // -------------------------------------------------
        // info
        // -------------------------------------------------
        l_writer.Key("info_hash");
        l_writer.String(m_info_hash_str.c_str());
        l_writer.Key("created_by");
        l_writer.String(m_created_by.c_str());
        l_writer.Key("creation_date");
        l_writer.String(epoch_to_str((uint64_t)(m_creation_date)).c_str());
        l_writer.Key("encoding");
        l_writer.String(m_encoding.c_str());
        l_writer.Key("comment");
        l_writer.String(m_comment.c_str());
        l_writer.Key("info_name");
        l_writer.String(m_info_pickr.m_info_name.c_str());
        l_writer.Key("length");
        l_writer.Int64(m_info_pickr.m_info_length);
        l_writer.Key("num_pieces");
        l_writer.Uint(m_info_pickr.m_info_pieces.size());
        l_writer.Key("pieces_length");
        l_writer.Int64(m_info_pickr.m_info_piece_length);
        // -------------------------------------------------
        // progress
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        // end object
        // -------------------------------------------------
        l_writer.EndObject();
        ao_body.assign(l_strbuf.GetString(), l_strbuf.GetSize());
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::api_get_trackers(std::string& ao_body)
{
        uint64_t l_now_s = get_time_s();
        // -------------------------------------------------
        // create body...
        // -------------------------------------------------
        rapidjson::StringBuffer l_strbuf;
        rapidjson::Writer<rapidjson::StringBuffer> l_writer(l_strbuf);
        l_writer.StartObject();
        // -------------------------------------------------
        // trackers
        // -------------------------------------------------
        l_writer.Key("trackers");
        l_writer.StartArray();
        for(auto && i_t : m_tracker_list)
        {
                tracker& l_t = *i_t;
                l_writer.StartObject();
                // -----------------------------------------
                // properties
                // -----------------------------------------
                l_writer.Key("host");
                l_writer.String(l_t.m_host.c_str());
                // -----------------------------------------
                // announce
                // -----------------------------------------
                l_writer.Key("announce_num");
                l_writer.Uint64(l_t.m_stat_announce_num);
                l_writer.Key("announce_last_s");
                l_writer.Uint64(l_now_s - l_t.m_stat_last_announce_time_s);
                l_writer.Key("announce_next_s");
                l_writer.Int64((int64_t)l_t.m_next_announce_s - (int64_t)l_now_s);
                l_writer.Key("announce_num_peers");
                l_writer.Uint64(l_t.m_stat_last_announce_num_peers + l_t.m_stat_last_announce_num_peers6);
                // -----------------------------------------
                // scrape
                // -----------------------------------------
                l_writer.Key("scrape_num");
                l_writer.Uint64(l_t.m_stat_scrape_num);
                l_writer.Key("scrape_last_s");
                l_writer.Uint64(l_now_s - l_t.m_stat_last_scrape_time_s);
                l_writer.Key("scrape_next_s");
                l_writer.Int64((int64_t)l_t.m_next_scrape_s - (int64_t)l_now_s);
                l_writer.Key("scrape_num_complete");
                l_writer.Uint64(l_t.m_stat_last_scrape_num_complete);
                l_writer.Key("scrape_num_downloaded");
                l_writer.Uint64(l_t.m_stat_last_scrape_num_downloaded);
                l_writer.Key("scrape_num_incomplete");
                l_writer.Uint64(l_t.m_stat_last_scrape_num_incomplete);
                l_writer.EndObject();
        }
        l_writer.EndArray();
        // -------------------------------------------------
        // end object
        // -------------------------------------------------
        l_writer.EndObject();
        ao_body.assign(l_strbuf.GetString(), l_strbuf.GetSize());
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t session::api_get_peers(std::string& ao_body)
{
        int32_t l_s;
        l_s = m_peer_mgr.get_peers_api(ao_body);
        if (l_s != NTRNT_STATUS_OK)
        {
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer_mgr::get_peers_api(std::string& ao_body)
{
        pthread_mutex_lock(&m_mutex);
        // -------------------------------------------------
        // create body...
        // -------------------------------------------------
        rapidjson::StringBuffer l_strbuf;
        rapidjson::Writer<rapidjson::StringBuffer> l_writer(l_strbuf);
        l_writer.StartObject();
        // -------------------------------------------------
        // trackers
        // -------------------------------------------------
        l_writer.Key("peers");
        l_writer.StartArray();
        for(auto && i_p : m_peer_vec)
        {
                peer* l_p_ptr = i_p;
                if (!l_p_ptr) { continue; }
                peer& l_p = *l_p_ptr;
                l_writer.StartObject();
                // -----------------------------------------
                // properties
                // -----------------------------------------
                l_writer.Key("host");
                l_writer.String(l_p.get_host().c_str());
                l_writer.Key("client");
                l_writer.String(l_p.get_btp_peer_str().c_str());
                l_writer.Key("from");
                switch(l_p.get_from())
                {
                case NTRNT_PEER_FROM_NONE: { l_writer.String("NONE"); break; }
                case NTRNT_PEER_FROM_SELF: { l_writer.String("SELF"); break; }
                case NTRNT_PEER_FROM_TRACKER: { l_writer.String("TRACKER"); break; }
                case NTRNT_PEER_FROM_DHT: { l_writer.String("DHT"); break; }
                case NTRNT_PEER_FROM_INBOUND: { l_writer.String("INBOUND"); break; }
                case NTRNT_PEER_FROM_PEX: { l_writer.String("PEX"); break; }
                default:
                {
                        l_writer.String("NONE");
                        break;
                }
                }
                // -----------------------------------------
                // status
                // -----------------------------------------
                l_writer.Key("status");
                switch(l_p.get_state())
                {
                case peer::STATE_NONE: { l_writer.String("NONE"); break; }
                case peer::STATE_UTP_CONNECTING: { l_writer.String("UTP_CONNECTING"); break; }
                case peer::STATE_PHE_SETUP: { l_writer.String("PHE_SETUP"); break; }
                case peer::STATE_PHE_CONNECTING: { l_writer.String("PHE_CONNECTING"); break; }
                case peer::STATE_HANDSHAKING: { l_writer.String("HANDSHAKING"); break; }
                case peer::STATE_CONNECTED: { l_writer.String("CONNECTED"); break; }
                default:
                {
                        l_writer.String("NONE");
                        break;
                }
                }
                // -----------------------------------------
                // error
                // -----------------------------------------
                l_writer.Key("error");
                switch(l_p.get_error())
                {
                case peer::ERROR_NONE: { l_writer.String("NONE"); break; }
                case peer::ERROR_TIMEOUT: { l_writer.String("TIMEOUT"); break; }
                case peer::ERROR_EOF: { l_writer.String("EOF"); break; }
                case peer::ERROR_EXPIRED_BR: { l_writer.String("EXPIRED_BR"); break; }
                case peer::ERROR_IDLE_TIMEOUT: { l_writer.String("IDLE_TIMEOUT"); break; }
                case peer::ERROR_CONNECT: { l_writer.String("CONNECT"); break; }
                case peer::ERROR_UTP_EOF: { l_writer.String("UTP_EOF"); break; }
                case peer::ERROR_UTP_CB_DONE: { l_writer.String("UTP_CB_DONE"); break; }
                case peer::ERROR_UTP_CB_ERROR: { l_writer.String("UTP_CB_ERROR"); break; }
                default:
                {
                        l_writer.String("NONE");
                        break;
                }
                }
                // -----------------------------------------
                // stats
                // -----------------------------------------
                l_writer.Key("recvd");
                l_writer.Uint64(l_p.m_stat_bytes_recv);
                l_writer.Key("recvd_per_s");
                l_writer.Uint64(l_p.m_stat_bytes_recv_per_s);
                l_writer.Key("sent");
                l_writer.Uint64(l_p.m_stat_bytes_sent);
                l_writer.Key("sent_per_s");
                l_writer.Uint64(l_p.m_stat_bytes_sent_per_s);
                // -----------------------------------------
                // geo
                // -----------------------------------------
                l_writer.Key("geoip2_country");
                l_writer.String(l_p.get_geoip2_country().c_str());
                l_writer.Key("geoip2_city");
                l_writer.String(l_p.get_geoip2_city().c_str());
                l_writer.Key("geoip2_lat");
                l_writer.Double(l_p.get_geoip2_lat());
                l_writer.Key("geoip2_lon");
                l_writer.Double(l_p.get_geoip2_lon());
                l_writer.EndObject();
        }
        l_writer.EndArray();
        // -------------------------------------------------
        // end object
        // -------------------------------------------------
        l_writer.EndObject();
        ao_body.assign(l_strbuf.GetString(), l_strbuf.GetSize());
        pthread_mutex_unlock(&m_mutex);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t peer_mgr::get_peers_str(std::string& ao_body)
{
        pthread_mutex_lock(&m_mutex);
        for(auto && i_p : m_peer_vec)
        {
                peer* l_p_ptr = i_p;
                if (!l_p_ptr) { continue; }
                peer& l_p = *l_p_ptr;
                ao_body += l_p.get_host();
                ao_body += "\n";
        }
        pthread_mutex_unlock(&m_mutex);
        return NTRNT_STATUS_OK;
}
}
