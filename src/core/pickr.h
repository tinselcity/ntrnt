#ifndef _NTRNT_PICKR_H
#define _NTRNT_PICKR_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include <vector>
#include <unordered_map>
#include <list>
#include <support/btfield.h>
#include <core/stub.h>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! internal fwd decl's
//! ----------------------------------------------------------------------------
class info_pickr;
class nbq;
class peer;
class stub;
//! ----------------------------------------------------------------------------
//! blocks
//! ----------------------------------------------------------------------------
typedef struct _blocks {
        size_t m_len;
        btfield m_btfield;
        _blocks(size_t a_len):
                m_len(a_len),
                m_btfield()
        {
                size_t l_nb = (size_t)(m_len/NTRNT_TORRENT_BLOCK_SIZE) +
                                     ((m_len%NTRNT_TORRENT_BLOCK_SIZE) != 0);
                m_btfield.set_size(l_nb);
        }
} blocks_t;
typedef std::vector<blocks_t*> blocks_vec_t;
//! ----------------------------------------------------------------------------
//! \block_rqst
//! ----------------------------------------------------------------------------
typedef struct _block_rqst {
        void* m_ctx;
        uint32_t m_idx;
        uint32_t m_off;
        uint32_t m_len;
        uint64_t m_time_ms;
        _block_rqst():
                m_ctx(nullptr),
                m_idx(0),
                m_off(0),
                m_len(0),
                m_time_ms(0)
        {}
} block_rqst_t;
typedef std::vector<block_rqst_t> block_rqst_vec_t;
//typedef std::list<block_rqst_t> block_rqst_list_t;
//! ----------------------------------------------------------------------------
//! \class pickr
//! ----------------------------------------------------------------------------
class pickr {
public:
        // -------------------------------------------------
        // key <piece(uint32) << 32 | block(uint32)
        // -------------------------------------------------
        typedef uint64_t key_t;
        // -------------------------------------------------
        // types
        // -------------------------------------------------
        typedef enum {
                MODE_RANDOM = 0, // default
                MODE_SEQUENTIAL,
                MODE_ENDGAME
        } mode_t;
        // -------------------------------------------------
        // counts
        // -------------------------------------------------
        typedef std::unordered_map<void*, uint32_t> inflight_map_t;
        //typedef std::unordered_map<key_t, block_rqst_list_t> block_rqst_list_map_t;
        typedef std::unordered_map<key_t, block_rqst_t> block_rqst_map_t;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        pickr(session& a_session);
        ~pickr(void);
        int32_t init(info_pickr& a_info_pickr);
        // -------------------------------------------------
        // settings
        // -------------------------------------------------
        void set_mode(mode_t a_mode);
        // -------------------------------------------------
        // operations
        // -------------------------------------------------
        int32_t request_blocks(void);
        int32_t get_piece(peer* a_peer, uint32_t a_idx, uint32_t a_off, uint32_t a_len, nbq* a_q);
        int32_t recv_piece(peer* a_peer, nbq& a_q, uint32_t a_idx, uint32_t a_off, uint32_t l_len);
        // -------------------------------------------------
        // housekeeping
        // -------------------------------------------------
        int32_t rm_ctx(void* a_ctx, block_rqst_vec_t& ao_vec);
        int32_t rm_expired(block_rqst_vec_t& ao_vec);
        // -------------------------------------------------
        // debug/display
        // -------------------------------------------------
        uint64_t get_stat_rm_br_expired(void) { return m_stat_rm_br_expired;}
        uint64_t get_stat_rm_br_ctx(void) { return m_stat_rm_br_ctx;}
        uint64_t get_stat_rm_br_block(void) { return m_stat_rm_br_block;}
        btfield& get_pieces(void) { return m_pieces; }
        bool complete(void) { return m_complete; }
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // -------------------------------------------------
        // disallow copy/assign
        // -------------------------------------------------
        pickr(const pickr&);
        pickr& operator=(const pickr&);
        int32_t peer_request_more(peer& a_peer);
        int32_t get_block_rqsts(block_rqst_vec_t& ao_vec, peer& a_peer, const btfield& a_btfield);
        // -------------------------------------------------
        // writing/reading/validating
        // -------------------------------------------------
        int32_t write(nbq& a_nbq, uint32_t a_idx, uint32_t a_off, uint32_t a_len);
        //int32_t read(uint8_t* a_buf, uint32_t a_idx, uint32_t a_off, uint32_t a_len);
        bool validate_piece(uint32_t a_piece);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        session& m_session;
        mode_t m_mode;
        // -------------------------------------------------
        // rqst tracking
        // -------------------------------------------------
        //inflight_map_t m_inflight_map;
        block_rqst_map_t m_block_rqst_map;
        // -------------------------------------------------
        // use list for endgame -to allow for multiple
        // requests for same block
        // -------------------------------------------------
        //block_rqst_list_map_t m_block_rqst_list_map;
        size_t m_info_length;
        size_t m_info_piece_length;
        const id_vector_t* m_info_pieces;
        btfield m_pieces;
        blocks_vec_t m_blocks_vec;
        bool m_complete;
        stub m_stub;
        // -------------------------------------------------
        // stats
        // -------------------------------------------------
        size_t m_stat_rm_br_expired;
        size_t m_stat_rm_br_ctx;
        size_t m_stat_rm_br_block;
};
}
#endif
