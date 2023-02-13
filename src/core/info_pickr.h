#ifndef _NTRNT_INFO_PICKR_H
#define _NTRNT_INFO_PICKR_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stddef.h>
#include <stdint.h>
#include "ntrnt/types.h"
#include "bencode/bencode.h"
#include "support/btfield.h"
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! internal fwd decl's
//! ----------------------------------------------------------------------------
class session;
class pickr;
class peer;
//! ----------------------------------------------------------------------------
//! \class pickr
//! ----------------------------------------------------------------------------
class info_pickr {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        info_pickr(session& a_session);
        ~info_pickr(void);
        // -------------------------------------------------
        // parsing
        // -------------------------------------------------
        int32_t parse_info(const char* a_buf, size_t a_len);
        // -------------------------------------------------
        // request/recv pieces
        // -------------------------------------------------
        int32_t request_info_pieces(void);
        int32_t recv_info_piece(peer* a_peer, uint32_t a_idx, const char* a_buf, size_t a_len);
        int32_t get_info_piece(peer* a_peer, uint32_t a_idx, const char** ao_buf, size_t& ao_len);
        // -------------------------------------------------
        // getters
        // -------------------------------------------------
        bool complete(void) { return m_complete; }
        size_t get_info_buf_len(void) { return m_info_buf_len; }
        const std::string& get_info_name(void) { return m_info_name; }
        int64_t get_info_length(void) { return m_info_length; }
        int64_t get_info_piece_length(void) { return m_info_piece_length; }
        size_t get_info_pieces_size(void) { return m_info_pieces.size(); }
        size_t get_info_files_size(void) { return m_info_files.size(); }
        const id_vector_t& get_info_pieces(void) { return m_info_pieces; }
        const files_list_t& get_info_files(void) { return m_info_files; }
        size_t get_info_buf_pieces_size(void) { return m_info_buf_pieces.get_size(); }
        size_t get_stat_num_pieces_rqstd(void) { return m_stat_num_pieces_rqstd; }
        size_t get_stat_num_pieces_recvd(void) { return m_stat_num_pieces_recvd; }
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // -------------------------------------------------
        // disallow copy/assign
        // -------------------------------------------------
        info_pickr(const info_pickr&);
        info_pickr& operator=(const info_pickr&);
        int32_t peer_request_info(peer& a_peer);
        int32_t validate_info(void);
        int32_t parse_info(const be_dict_t& a_dict);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        session& m_session;
        bool m_complete;
        // -------------------------------------------------
        // info storage
        // -------------------------------------------------
        btfield m_info_buf_pieces;
        uint8_t* m_info_buf;
        size_t m_info_buf_len;
        // -------------------------------------------------
        // parsed info properties
        // -------------------------------------------------
        std::string m_info_name;
        int64_t m_info_length;
        int64_t m_info_piece_length;
        id_vector_t m_info_pieces;
        files_list_t m_info_files;
        // -------------------------------------------------
        // stats
        // -------------------------------------------------
        size_t m_stat_num_pieces_rqstd;
        size_t m_stat_num_pieces_recvd;
};
}
#endif
