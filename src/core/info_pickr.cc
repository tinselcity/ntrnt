//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "ntrnt/def.h"
#include "support/trace.h"
#include "support/ndebug.h"
#include "support/sha1.h"
#include "core/session.h"
#include "core/pickr.h"
#include "core/peer.h"
#include "core/info_pickr.h"
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
info_pickr::info_pickr(session& a_session):
        m_session(a_session),
        m_complete(false),
        m_info_buf_pieces(),
        m_info_buf(nullptr),
        m_info_buf_len(0),
        m_info_name(),
        m_info_length(0),
        m_info_piece_length(0),
        m_info_pieces(),
        m_info_files(),
        m_stat_num_pieces_rqstd(0),
        m_stat_num_pieces_recvd(0)
{
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
info_pickr::~info_pickr(void)
{
        // -------------------------------------------------
        // cleanup meta info buffer if set
        // -------------------------------------------------
        if (m_info_buf) { free(m_info_buf); m_info_buf = nullptr; m_info_buf_len = 0;}
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t info_pickr::parse_info(const be_dict_t& a_dict)
{
        // -------------------------------------------------
        // *************************************************
        //                     I N F O
        // *************************************************
        // -------------------------------------------------
        for(auto && i_m : a_dict)
        {
#define _ELIF_FIELD(_str) else if(i_m.first == _str)
                const be_obj_t& i_obj = i_m.second;
                if (0) {}
                // -----------------------------------------
                // name
                // -----------------------------------------
                _ELIF_FIELD("name")
                {
                        if (i_obj.m_type != BE_OBJ_STRING)
                        {
                                continue;
                        }
                        const be_string_t& i_str = *((const be_string_t*)i_obj.m_obj);
                        m_info_name.assign(i_str.m_data, i_str.m_len);
                }
                // -----------------------------------------
                // length
                // -----------------------------------------
                _ELIF_FIELD("length")
                {
                        if (i_obj.m_type != BE_OBJ_INT)
                        {
                                continue;
                        }
                        const be_int_t& i_int = *((const be_int_t*)i_obj.m_obj);
                        m_info_length = i_int;
                }
                // -----------------------------------------
                // piece length
                // -----------------------------------------
                _ELIF_FIELD("piece length")
                {
                        if (i_obj.m_type != BE_OBJ_INT)
                        {
                                continue;
                        }
                        const be_int_t& i_int = *((const be_int_t*)i_obj.m_obj);
                        m_info_piece_length = i_int;
                }
                // -----------------------------------------
                // pieces
                // -----------------------------------------
                _ELIF_FIELD("pieces")
                {
                        if (i_obj.m_type != BE_OBJ_STRING)
                        {
                                continue;
                        }
                        const be_string_t& i_str = *((const be_string_t*)i_obj.m_obj);
                        size_t l_num_pieces = i_str.m_len/(sizeof(id_t));
                        for (size_t i_h = 0; i_h < l_num_pieces; ++i_h)
                        {
                                const char* l_b = i_str.m_data + (i_h*20);
                                id_t l_id;
                                memcpy(l_id.m_data, l_b, sizeof(id_t));
                                m_info_pieces.push_back(l_id);
                        }
                }
                // -----------------------------------------
                // files
                // -----------------------------------------
                _ELIF_FIELD("files")
                {
                        if (i_obj.m_type != BE_OBJ_LIST)
                        {
                                continue;
                        }
                        const be_list_t& i_list = *((const be_list_t*)i_obj.m_obj);
                        for(auto && i_m : i_list)
                        {
                                const be_obj_t& ii_obj = i_m;
                                if (ii_obj.m_type != BE_OBJ_DICT)
                                {
                                        continue;
                                }
                                const be_dict_t& l_file_dict = *((const be_dict_t*)ii_obj.m_obj);
                                files_t l_file;
                                for(auto && i_f : l_file_dict)
                                {
                                        const be_obj_t& iii_obj = i_f.second;
                                        if (0) {}
                                        // -----------------------------------------
                                        // length
                                        // -----------------------------------------
                                        else if(i_f.first == "length")
                                        {
                                                if (iii_obj.m_type != BE_OBJ_INT)
                                                {
                                                        continue;
                                                }
                                                const be_int_t& l_len = *((const be_int_t*)iii_obj.m_obj);
                                                l_file.m_len = l_len;
                                        }
                                        // -----------------------------------------
                                        // path list
                                        // -----------------------------------------
                                        else if(i_f.first == "path")
                                        {
                                                if (iii_obj.m_type != BE_OBJ_LIST)
                                                {
                                                        continue;
                                                }
                                                const be_list_t& ip_list = *((const be_list_t*)iii_obj.m_obj);
                                                for(auto && i_p : ip_list)
                                                {
                                                        const be_obj_t& i_p_obj = i_p;
                                                        if (i_p_obj.m_type != BE_OBJ_STRING)
                                                        {
                                                                continue;
                                                        }
                                                        const be_string_t& i_p_str = *((const be_string_t*)i_p_obj.m_obj);
                                                        std::string l_path;
                                                        l_path.assign(i_p_str.m_data, i_p_str.m_len);
                                                        l_file.m_path.push_back(l_path);
                                                }
                                        }
                                }
                                if (l_file.m_len &&
                                    !l_file.m_path.empty())
                                {
                                        m_info_files.push_back(l_file);
                                }
                        }
                }
        }
        // -------------------------------------------------
        // mark complete/init pickr
        // -------------------------------------------------
        int32_t l_s;
        l_s = m_session.get_pickr().init(*this);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing pickr init");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // mark complete
        // -------------------------------------------------
        m_complete = true;
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t info_pickr::parse_info(const char* a_buf, size_t a_len)
{
        // -------------------------------------------------
        // free old
        // -------------------------------------------------
        if (m_info_buf) { free(m_info_buf); m_info_buf = nullptr; m_info_buf_len = 0;}
        // -------------------------------------------------
        // copy in
        // -------------------------------------------------
        m_info_buf_len = a_len;
        m_info_buf = (uint8_t*)malloc(sizeof(uint8_t)*m_info_buf_len);
        memcpy(m_info_buf, a_buf, m_info_buf_len);
        // -------------------------------------------------
        // parse
        // -------------------------------------------------
        int32_t l_s;
        bdecode l_bd;
        l_s = l_bd.init((const char*)m_info_buf, m_info_buf_len);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing bencode decode init");
                if (m_info_buf) { free(m_info_buf); m_info_buf = nullptr; m_info_buf_len = 0;}
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // extract
        // -------------------------------------------------
        l_s = parse_info(l_bd.m_dict);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing parse_info");
                if (m_info_buf) { free(m_info_buf); m_info_buf = nullptr; m_info_buf_len = 0;}
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t info_pickr::validate_info(void)
{
        int32_t l_s;
        // -------------------------------------------------
        // checksum
        // -------------------------------------------------
        sha1 l_sha1;
        l_sha1.update((const uint8_t*)m_info_buf, m_info_buf_len);
        l_sha1.finish();
        // -------------------------------------------------
        // test
        // -------------------------------------------------
        l_s = memcmp(m_session.get_info_hash(), l_sha1.get_hash(), NTRNT_SHA1_SIZE);
        if (l_s != 0)
        {
                TRC_ERROR("bad hash cmp expected[%s] != checked[%s]",
                          m_session.get_info_hash_str().c_str(),
                          l_sha1.get_hash_hex());
                m_info_buf_pieces.clear_all();
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // parse
        // -------------------------------------------------
        bdecode l_bd;
        l_s = l_bd.init((const char*)m_info_buf, m_info_buf_len);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing bencode decode init");
                if (m_info_buf) { free(m_info_buf); m_info_buf = nullptr; m_info_buf_len = 0;}
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // extract
        // -------------------------------------------------
        l_s = parse_info(l_bd.m_dict);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing parse_info");
                if (m_info_buf) { free(m_info_buf); m_info_buf = nullptr; m_info_buf_len = 0;}
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t info_pickr::request_info_pieces(void)
{
        // -------------------------------------------------
        // if done...
        // -------------------------------------------------
        if (m_complete)
        {
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        //  for each active
        // -------------------------------------------------
        peer_vec_t& l_pc = m_session.get_peer_mgr().get_peer_connected_vec();
        for (auto && i_p : l_pc)
        {
                if (!i_p) { continue; }
                peer* l_peer = i_p;
                // -----------------------------------------
                // request more
                // -----------------------------------------
                int32_t l_s;
                l_s = peer_request_info(*l_peer);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing peer_request_more");
                        continue;
                }
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t info_pickr::peer_request_info(peer& a_peer)
{
        // -------------------------------------------------
        // check if supports meta data requests
        // -------------------------------------------------
        if (!a_peer.get_ltep_metadata_size() ||
            !a_peer.get_ltep_msg_support_ut_metadata())
        {
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // setup meta if missing
        // trusting first one as legitimate
        // -------------------------------------------------
        if (!m_info_buf_len)
        {
                m_info_buf_len = a_peer.get_ltep_metadata_size();
                m_info_buf = (uint8_t*)malloc((sizeof(uint8_t)*m_info_buf_len));
                size_t l_num = (m_info_buf_len / NTRNT_METADATA_PIECE_SIZE) + (m_info_buf_len%NTRNT_METADATA_PIECE_SIZE > 0);
                m_info_buf_pieces.set_size(l_num);
        }
        // -------------------------------------------------
        // request every missing piece
        // This is an aggressive noisy methodology badgering
        // all peers (pieces missing).
        // -------------------------------------------------
        for (size_t i_p = 0; i_p < m_info_buf_pieces.get_size(); ++i_p)
        {
                // -----------------------------------------
                // skip have
                // -----------------------------------------
                if (m_info_buf_pieces.test(i_p))
                {
                        continue;
                }
                // -----------------------------------------
                // request piece
                // -----------------------------------------
                int32_t l_s;
                l_s = a_peer.ltep_send_metadata_request(i_p);
                if (l_s != NTRNT_STATUS_OK)
                {
                        TRC_ERROR("performing peer ltep_send_metadata_request");
                        return NTRNT_STATUS_ERROR;
                }
                ++m_stat_num_pieces_rqstd;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t info_pickr::recv_info_piece(peer* a_peer, uint32_t a_idx, const char* a_buf, size_t a_len)
{
        ++m_stat_num_pieces_recvd;
        // -------------------------------------------------
        // have already?
        // -------------------------------------------------
        if (m_info_buf_pieces.test(a_idx))
        {
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // size check
        // -------------------------------------------------
        size_t l_exp_len = NTRNT_METADATA_PIECE_SIZE;
        // adjust for last
        if (a_idx == (m_info_buf_pieces.get_size() - 1))
        {
                size_t l_mod = m_info_buf_len%NTRNT_METADATA_PIECE_SIZE;
                if (l_mod)
                {
                        l_exp_len = l_mod;
                }
        }
        // -------------------------------------------------
        // discard unexpected lengths
        // -------------------------------------------------
        if (l_exp_len != a_len)
        {
                TRC_ERROR("bad length(%lu) for piece: %u / %lu",
                          a_len, a_idx, m_info_buf_pieces.get_size());
                // should warn with "OK" return status?
                // ie is acceptable error?
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // write and set
        // -------------------------------------------------
        size_t l_off = a_idx*NTRNT_METADATA_PIECE_SIZE;
        memcpy(m_info_buf+l_off, a_buf, a_len);
        m_info_buf_pieces.set(a_idx, true);
        if (!m_info_buf_pieces.has_all())
        {
                // need more
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // validate
        // -------------------------------------------------
        int32_t l_s;
        l_s = validate_info();
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_ERROR("performing torrent parse info");
                m_info_buf_pieces.clear_all();
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t info_pickr::get_info_piece(peer* a_peer,
                                   uint32_t a_idx,
                                   const char** ao_buf,
                                   size_t& ao_len)
{
        // -------------------------------------------------
        // sanity check
        // -------------------------------------------------
        if (!ao_buf)
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // check if has
        // -------------------------------------------------
        if (!m_info_buf_pieces.test(a_idx))
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get size
        // -------------------------------------------------
        ao_len = NTRNT_METADATA_PIECE_SIZE;
        // adjust for last
        if (a_idx == (m_info_buf_pieces.get_size() - 1))
        {
                size_t l_mod = m_info_buf_len%NTRNT_METADATA_PIECE_SIZE;
                if (l_mod)
                {
                        ao_len = l_mod;
                }
        }
        // -------------------------------------------------
        // return buf
        // -------------------------------------------------
        size_t l_off = a_idx*NTRNT_METADATA_PIECE_SIZE;
        *ao_buf = (const char*)(m_info_buf+l_off);
        return NTRNT_STATUS_OK;
}
}
