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
//! types
//! ----------------------------------------------------------------------------
typedef struct _files {
        std::list<std::string> m_path;
        size_t m_len;
        _files():
                m_path(),
                m_len(0)
        {}
} files_t;
typedef std::list<files_t> files_list_t;
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
        int32_t parse_info(const char* a_buf, size_t a_len);
        int32_t request_info_pieces(void);
        int32_t recv_info_piece(peer* a_peer, uint32_t a_idx, const char* a_buf, size_t a_len);
        int32_t get_info_piece(peer* a_peer, uint32_t a_idx, const char** ao_buf, size_t& ao_len);
        size_t get_info_buf_len(void) { return m_info_buf_len; }
        bool complete(void) { return m_complete; }
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
        int32_t parse_info(const be_dict_t& a_dict);
        int32_t validate_info(void);
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
        // sharing private fields with session
        // -------------------------------------------------
        friend session;
        friend pickr;
};
}
#endif
