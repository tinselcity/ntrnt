//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "core/pickr.h"
#include <string.h>
#include <algorithm>
#include "core/info_pickr.h"
#include "core/peer.h"
#include "core/session.h"
#include "ntrnt/def.h"
#include "support/btfield.h"
#include "support/nbq.h"
#include "support/ndebug.h"
#include "support/sha1.h"
#include "support/trace.h"
#include "support/util.h"
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
pickr::pickr(session& a_session)
    : m_init(false),
      m_session(a_session),
      m_mode(MODE_RANDOM),
      //m_inflight_map(),
      m_block_rqst_map(),
      m_info_length(0),
      m_info_piece_length(0),
      m_info_pieces(nullptr),
      m_pieces(),
      m_blocks_vec(),
      m_complete(false),
      m_stub(),
      m_stat_rm_br_expired(0),
      m_stat_rm_br_ctx(0),
      m_stat_rm_br_block(0),
      m_stat_num_blocks_rqstd(0),
      m_stat_num_blocks_recvd(0) {}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
pickr::~pickr(void) {
  // -------------------------------------------------
  // cleanup blocks
  // -------------------------------------------------
  for (auto&& i_b : m_blocks_vec) {
    if (i_b) {
      delete i_b;
      i_b = nullptr;
    }
  }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t pickr::init(info_pickr& a_info_pickr) {
  if (m_init) {
    return NTRNT_STATUS_OK;
  }
  // -------------------------------------------------
  // set blocks bitfields
  // -------------------------------------------------
  m_info_pieces = &(a_info_pickr.get_info_pieces());
  m_info_length = (size_t)a_info_pickr.get_info_length();
  m_info_piece_length = (size_t)a_info_pickr.get_info_piece_length();
  m_pieces.set_size(m_info_pieces->size());
  for (size_t i_idx = 0; i_idx < m_pieces.get_size(); ++i_idx) {
    size_t l_len = m_info_piece_length;
    if (i_idx == (m_pieces.get_size() - 1)) {
      size_t l_t_pmod = m_info_length % m_info_piece_length;
      if (l_t_pmod) {
        l_len = l_t_pmod;
      }
    }
    blocks_t* l_bs = new blocks_t(l_len);
    m_blocks_vec.push_back(l_bs);
  }
  // -------------------------------------------------
  // init stub
  // -------------------------------------------------
  int32_t l_s;
  l_s = m_stub.init(a_info_pickr.get_info_name(), m_info_length,
                    a_info_pickr.get_info_files());
  if (l_s != NTRNT_STATUS_OK) {
    TRC_ERROR("performing files init");
    return NTRNT_STATUS_ERROR;
  }
  m_init = true;
  // -------------------------------------------------
  // validate
  // -------------------------------------------------
  for (size_t i_idx = 0; i_idx < m_pieces.get_size(); ++i_idx) {
    bool l_f = false;
    l_f = validate_piece(i_idx);
    if (l_f) {
      m_pieces.set(i_idx, true);
    }
  }
  if (m_pieces.has_all()) {
    TRC_DEBUG("has all pieces");
    m_complete = true;
  }
  // -------------------------------------------------
  // done
  // -------------------------------------------------
  return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void pickr::set_mode(mode_t a_mode) {
  m_mode = a_mode;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t pickr::write(nbq& a_nbq, uint32_t a_idx, uint32_t a_off,
                     uint32_t a_len) {
  // -------------------------------------------------
  // block reading from nbq -up to length
  // -------------------------------------------------
  if (!a_len) {
    return NTRNT_STATUS_OK;
  }
  size_t l_off = (size_t)(a_idx) * (size_t)m_info_piece_length + a_off;
  size_t l_read = 0;
  size_t l_total_read_avail = a_nbq.read_avail();
  size_t l_left = (a_len > l_total_read_avail) ? l_total_read_avail : a_len;
  while (l_left) {
    size_t l_read_avail = a_nbq.b_read_avail();
    size_t l_read_size = (l_left > l_read_avail) ? l_read_avail : l_left;
    int32_t l_s;
    l_s = m_stub.write((const uint8_t*)a_nbq.b_read_ptr(), l_off, l_read_size);
    if (l_s != NTRNT_STATUS_OK) {
      TRC_ERROR("performing stub write");
      return NTRNT_STATUS_ERROR;
    }
    l_off += l_read_size;
    a_nbq.b_read_incr(l_read_size);
    l_left -= l_read_size;
    l_read += l_read_size;
  }
  a_nbq.shrink();
  UNUSED(l_read);
  return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
bool pickr::validate_piece(uint32_t a_piece) {
  if (!m_init) {
    return false;
  }
  if (!m_info_pieces) {
    TRC_ERROR("info pieces == null");
    return false;
  }
  // -------------------------------------------------
  // sanity check len
  // -------------------------------------------------
  const id_vector_t& l_ids = (*m_info_pieces);
  uint32_t l_num_pieces = l_ids.size();
  size_t l_size = (size_t)m_info_length;
  if (a_piece >= l_num_pieces) {
    TRC_ERROR("piece[%u] > number of pieces[%u]", a_piece, l_num_pieces);
    return false;
  }
  // -------------------------------------------------
  // calculate offset/length of piece
  // -------------------------------------------------
  size_t l_off = (size_t)(m_info_piece_length * (size_t)a_piece);
  size_t l_len = (size_t)m_info_piece_length;
  // -------------------------------------------------
  // last piece
  // -------------------------------------------------
  if (a_piece == (l_num_pieces - 1)) {
    size_t l_mod = l_size % m_info_piece_length;
    if (l_mod) {
      l_len = l_mod;
    }
  }
  // -------------------------------------------------
  // calc sha1
  // -------------------------------------------------
  const id_t& l_sha1_exp = l_ids[a_piece];
  id_t l_sha1_act;
  m_stub.calc_sha1(l_sha1_act, l_off, l_len);
  // -------------------------------------------------
  // compare
  // -------------------------------------------------
  int l_s;
  l_s = memcmp(l_sha1_act.m_data, l_sha1_exp.m_data, sizeof(l_sha1_exp));
  // -------------------------------------------------
  // invalid
  // -------------------------------------------------
  if (l_s != 0) {
    //TRC_ERROR("invalid sha1[piece: %u] actual: %s != expected: %s",
    //          a_piece,
    //          id2str(l_sha1_act).c_str(),
    //          id2str(l_sha1_exp).c_str());
    return false;
  }
  return true;
}
//! ----------------------------------------------------------------------------
//! \details: rm pending requests -ie for endgame
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
#if 0
int32_t pickr::rm_block(uint32_t a_idx, uint32_t a_blk, block_rqst_vec_t& ao_vec)
{
        // -------------------------------------------------
        // find block rqst list for key
        // -------------------------------------------------
        uint64_t l_key = (((uint64_t)a_idx << 32)) | ((uint64_t)(a_blk));
        auto i_br = m_block_rqst_map.find(l_key);
        if (i_br == m_block_rqst_map.end())
        {
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // add blocks to be removed to output
        // -------------------------------------------------
        block_rqst_t& l_br = i_br->second;
        ao_vec.push_back(l_br);
        // -------------------------------------------------
        // remove block
        // -------------------------------------------------
        ++m_stat_rm_br_block;
        m_block_rqst_map.erase(i_br);
        // -------------------------------------------------
        // decrement peer inflight count
        // -------------------------------------------------
        // TODO
        return NTRNT_STATUS_OK;
}
#endif
//! ----------------------------------------------------------------------------
//! \details: rm peer -ie if peer choked or was deleted
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t pickr::rm_ctx(void* a_ctx, block_rqst_vec_t& ao_vec) {
  if (!a_ctx) {
    TRC_ERROR("ctx == null");
    return NTRNT_STATUS_ERROR;
  }
  peer* l_p = (peer*)a_ctx;
  // -------------------------------------------------
  // rm all block rqsts
  // -------------------------------------------------
  uint32_t l_cnt = 0;
  auto i_br = m_block_rqst_map.begin();
  while (i_br != m_block_rqst_map.end()) {
    if (a_ctx == i_br->second.m_ctx) {
      ++m_stat_rm_br_ctx;
      ao_vec.push_back(i_br->second);
      m_block_rqst_map.erase(i_br++);
      if (l_p->m_num_block_rqst_inflight > 0) {
        --(l_p->m_num_block_rqst_inflight);
      }
      ++l_cnt;
    } else {
      ++i_br;
    }
  }
  if (l_cnt) {
    TRC_WARN("[PEER: %p] REMOVE [BLOCK_REQUESTS: %d]", a_ctx, l_cnt);
  }
  return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t pickr::rm_expired(block_rqst_vec_t& ao_vec) {
  // -------------------------------------------------
  // get now
  // -------------------------------------------------
  uint64_t l_now_ms = get_time_ms();
  // -------------------------------------------------
  // rm expired requests (older than N seconds)
  // -------------------------------------------------
  uint32_t l_cnt = 0;
  auto i_br = m_block_rqst_map.begin();
  while (i_br != m_block_rqst_map.end()) {
    if (l_now_ms >
        (i_br->second.m_time_ms + NTRNT_SESSION_PEER_INFLIGHT_EXPIRES_MS)) {
      peer* l_peer = (peer*)(i_br->second.m_ctx);
      if (l_peer) {
        l_peer->stat_add_br_expired(1);
        if (l_peer->m_num_block_rqst_inflight > 0) {
          --(l_peer->m_num_block_rqst_inflight);
        }
      }
      ++m_stat_rm_br_expired;
      ao_vec.push_back(i_br->second);
      m_block_rqst_map.erase(i_br++);
      ++l_cnt;
    } else {
      ++i_br;
    }
  }
  if (l_cnt) {
    TRC_WARN("[PEER: %p] EXPIRE [BLOCK_REQUESTS: %d]", nullptr, l_cnt);
  }
  return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
#if 0
void pickr::display(void)
{
        size_t i_br_idx = 0;
        for (auto && i_br : m_block_rqst_map)
        {
                block_rqst_t& l_br = i_br.second;
                NDBG_OUTPUT("BLOCK_REQUEST [%8lu] [key: 0x%16lX] (inflight):\n",
                            i_br_idx,
                            i_br.first);
                NDBG_OUTPUT(": ctx:  %p\n",  l_br.m_ctx);
                NDBG_OUTPUT(": idx:  %u\n",  l_br.m_idx);
                NDBG_OUTPUT(": off:  %u\n",  l_br.m_off);
                NDBG_OUTPUT(": len:  %u\n",  l_br.m_len);
                NDBG_OUTPUT(": time: %lu\n", l_br.m_time_ms);
                ++i_br_idx;
        }
}
#endif
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
#if 0
void pickr::display_pending(void* a_ctx)
{
        uint64_t l_now_ms = get_time_ms();
        for (auto && i_br : m_block_rqst_map)
        {
                block_rqst_t& l_br = i_br.second;
                if (l_br.m_ctx == a_ctx)
                {
                        NDBG_OUTPUT("PENDING BLOCK_REQUEST [PIECE: %6u] [BLOCK: %4u] [LEFT: %6ld ms]\n",
                                    l_br.m_idx,
                                    l_br.m_off/NTRNT_TORRENT_BLOCK_SIZE,
                                    (int64_t)(l_br.m_time_ms+NTRNT_SESSION_PEER_INFLIGHT_EXPIRES_MS) - (int64_t)l_now_ms);
                }
        }
}
#endif
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
#if 0
void pickr::display_stats(void)
{
        NDBG_OUTPUT("[PICKR] removed by: [EXPIRED: %6lu] [CTX: %6lu] [BLOCK: %6lu]\n",
                    m_stat_rm_br_expired,
                    m_stat_rm_br_ctx,
                    m_stat_rm_br_block);
}
#endif
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t pickr::request_blocks(void) {
  if (!m_init) {
    return NTRNT_STATUS_OK;
  }
  // -------------------------------------------------
  // expire old block requests
  // -------------------------------------------------
  int32_t l_s;
  block_rqst_vec_t l_brv;
  l_s = rm_expired(l_brv);
  UNUSED(l_s);
  UNUSED(l_brv);
  // -------------------------------------------------
  // if done...
  // -------------------------------------------------
  if (m_complete) {
    return NTRNT_STATUS_OK;
  }
  // -------------------------------------------------
  //  for each active
  // -------------------------------------------------
  peer_vec_t& l_swarm = m_session.get_peer_mgr().get_peer_connected_vec();
  for (auto&& i_p : l_swarm) {
    if (!i_p) {
      continue;
    }
    peer* l_peer = i_p;
    // -----------------------------------------
    // request more
    // -----------------------------------------
    l_s = peer_request_more(*l_peer);
    if (l_s != NTRNT_STATUS_OK) {
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
bool pickr::peer_is_interesting(peer& a_peer) {
  btfield& l_ph = a_peer.get_btp_pieces_have();
  for (size_t i_p = 0; i_p < m_pieces.get_size(); ++i_p) {
    if (!m_pieces.test(i_p) && l_ph.test(i_p)) {
      return true;
    }
  }
  return false;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t pickr::peer_request_more(peer& a_peer) {
  int32_t l_s;
  // -------------------------------------------------
  // check is connected
  // -------------------------------------------------
  if (a_peer.get_state() != peer::STATE_CONNECTED) {
    return NTRNT_STATUS_OK;
  }
  // -------------------------------------------------
  // get is interesting
  // -------------------------------------------------
  bool l_is_interesting = peer_is_interesting(a_peer);
  // -------------------------------------------------
  // if empty peer doesn't appear to have anything
  // of interest so relay
  // -------------------------------------------------
  if (!l_is_interesting && a_peer.get_btp_am_interested()) {
    a_peer.m_btp_am_interested = false;
    l_s = a_peer.btp_send_not_interested();
    if (l_s != NTRNT_STATUS_OK) {
      TRC_ERROR("performing btp_send_interested");
      return NTRNT_STATUS_ERROR;
    }
    return NTRNT_STATUS_OK;
  }
  // -------------------------------------------------
  // skip if choking
  // -------------------------------------------------
  if (a_peer.get_btp_peer_choking() || !a_peer.get_btp_am_interested()) {
    // -----------------------------------------
    // if is interesting and haven't already
    // expressed interest -send interested
    // -----------------------------------------
    if (l_is_interesting && !a_peer.get_btp_am_interested()) {
      a_peer.m_btp_am_interested = true;
      l_s = a_peer.btp_send_interested();
      if (l_s != NTRNT_STATUS_OK) {
        TRC_ERROR("performing btp_send_interested");
        return NTRNT_STATUS_ERROR;
      }
      return NTRNT_STATUS_OK;
    }
    // -----------------------------------------
    // send keep-alive if nothing else
    // -----------------------------------------
    a_peer.btp_send_keepalive();
    return NTRNT_STATUS_OK;
  }
  // -------------------------------------------------
  // calculate num blocks can request
  // -------------------------------------------------
  block_rqst_vec_t l_blk_rqst_vec;
  l_s = get_block_rqsts(l_blk_rqst_vec, a_peer, a_peer.get_btp_pieces_have());
  if (l_s == NTRNT_STATUS_ERROR) {
    TRC_ERROR("performing pickr get blocks");
    return NTRNT_STATUS_ERROR;
  }
  // -------------------------------------------------
  // make requests
  // -------------------------------------------------
  for (auto&& i_b : l_blk_rqst_vec) {
    ++m_stat_num_blocks_rqstd;
    l_s = a_peer.btp_send_request(i_b.m_idx, i_b.m_off, i_b.m_len);
    if (l_s != NTRNT_STATUS_OK) {
      TRC_ERROR("performing peer btp_send_request");
      return NTRNT_STATUS_ERROR;
    }
  }
  return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t pickr::get_block_rqsts(block_rqst_vec_t& ao_vec, peer& a_peer,
                               const btfield& a_btfield) {
  // -------------------------------------------------
  // get inflight count
  // -------------------------------------------------
  uint32_t l_max_reqq = (uint32_t)a_peer.get_ltep_reqq();
  uint32_t l_max = l_max_reqq - a_peer.m_num_block_rqst_inflight;
  if (!l_max) {
    return NTRNT_STATUS_OK;
  }
  // -------------------------------------------------
  // - find list of candidate pieces from intersection
  //   of torrent need and peer have (vector)
  // - shuffle vector
  // - loop over vector of pieces until populated max
  //   block requests
  //   - log rqsts created
  //   - increment inflight
  // -------------------------------------------------
  // -------------------------------------------------
  // find candidate list
  // -------------------------------------------------
  typedef struct _pb {
    uint32_t m_piece;
    uint32_t m_need;
    _pb() : m_piece(0), m_need(0) {}
    bool operator<(const _pb& that) const { return m_need < that.m_need; }
  } _pb_t;
  typedef std::vector<_pb_t> _piece_vec_t;
  _piece_vec_t l_pv;
  // -------------------------------------------------
  // sanity check size
  // -------------------------------------------------
  if (m_pieces.get_size() != a_btfield.get_size()) {
    TRC_ERROR("torrent peer bitfield size mismatch");
    return NTRNT_STATUS_ERROR;
  }
  for (size_t i_p = 0; i_p < m_pieces.get_size(); ++i_p) {
    // if don't have locally but peer does...
    if (!m_pieces.test(i_p) && a_btfield.test(i_p)) {
      // TODO len check!!!
      blocks_t& l_blks = *(m_blocks_vec[i_p]);
      _pb_t l_pb;
      l_pb.m_piece = i_p;
      l_pb.m_need = l_blks.m_btfield.get_size() - l_blks.m_btfield.get_count();
      l_pv.push_back(l_pb);
    }
  }
  // -------------------------------------------------
  // check if empty
  // -------------------------------------------------
  if (l_pv.empty()) {
    return NTRNT_STATUS_OK;
  }
  // -------------------------------------------------
  // shuffle
  // -------------------------------------------------
  std::random_shuffle(l_pv.begin(), l_pv.end());
  std::sort(l_pv.begin(), l_pv.end());
  // -------------------------------------------------
  // TODO consider sorting by blocks needed???
  // -------------------------------------------------
  // -------------------------------------------------
  // loop over vector of pieces until populated max
  // block requests
  // -------------------------------------------------
  for (auto&& i_p : l_pv) {
    // -----------------------------------------
    // get blocks for piece
    // -----------------------------------------
    // TODO len check!!!
    blocks_t& l_bs = *(m_blocks_vec[i_p.m_piece]);
    if (!l_bs.m_btfield.get_size()) {
      TRC_ERROR("empty bitfield");
      return NTRNT_STATUS_ERROR;
    }
    btfield& l_bf = l_bs.m_btfield;
    // -----------------------------------------
    // for each block
    // -----------------------------------------
    for (size_t i_b = 0; i_b < l_bf.get_size(); ++i_b) {
      uint32_t l_idx = i_p.m_piece;
      // ---------------------------------
      // skip has
      // ---------------------------------
      if (l_bf.test(i_b)) {
        continue;
      }
      // ---------------------------------
      // generate key
      // ---------------------------------
      uint64_t l_key = (((uint64_t)l_idx << 32)) | ((uint64_t)(i_b));
      // ---------------------------------
      // check for  inflight
      // ---------------------------------
      // TODO adjust for endgame
      // ---------------------------------
      auto i_brl = m_block_rqst_map.find(l_key);
      if (i_brl != m_block_rqst_map.end()) {
        continue;
      }
      // ---------------------------------
      // new entry
      // ---------------------------------
      block_rqst_t l_br;
      l_br.m_ctx = &a_peer;
      l_br.m_idx = l_idx;
      l_br.m_off = i_b * NTRNT_TORRENT_BLOCK_SIZE;
      l_br.m_len = NTRNT_TORRENT_BLOCK_SIZE;
      l_br.m_time_ms = get_time_ms();
      // ---------------------------------
      // adjust length for last block
      // ---------------------------------
      if (i_b == (l_bf.get_size() - 1)) {
        uint32_t l_mod = l_bs.m_len % NTRNT_TORRENT_BLOCK_SIZE;
        if (l_mod) {
          l_br.m_len = l_mod;
        }
      }
      // ---------------------------------
      // append to output
      // ---------------------------------
      ao_vec.push_back(l_br);
      // ---------------------------------
      // insert into map for tracking
      // ---------------------------------
      m_block_rqst_map[l_key] = l_br;
      ++a_peer.m_num_block_rqst_inflight;
      // ---------------------------------
      // bookeeping
      // ---------------------------------
      --l_max;
      if (l_max <= 0) {
        goto done;
      }
    }
  }
done:
  return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t pickr::get_piece(peer* a_peer, uint32_t a_idx, uint32_t a_off,
                         uint32_t a_len, nbq* a_q) {
  // -------------------------------------------------
  // check if has
  // -------------------------------------------------
  if (!m_pieces.test(a_idx)) {
    return NTRNT_STATUS_ERROR;
  }
  // -------------------------------------------------
  // get offset
  // -------------------------------------------------
  size_t l_off = a_idx * m_info_piece_length + a_off;
  if ((l_off + a_len) > m_info_length) {
    TRC_ERROR("requested piece+offset+len > size of torrent");
    return NTRNT_STATUS_ERROR;
  }
  // -------------------------------------------------
  // return ptr to data
  // TODO fix for multifile
  // -------------------------------------------------
  int32_t l_s;
  l_s = m_stub.read(a_q, l_off, a_len);
  if (l_s != NTRNT_STATUS_OK) {
    TRC_ERROR("performing stub read: [Q: %p] [OFF: %u] [LEN: %u]", a_q,
              (unsigned int)l_off, a_len);
    return NTRNT_STATUS_ERROR;
  }
  return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t pickr::recv_piece(peer* a_peer, nbq& a_q, uint32_t a_idx,
                          uint32_t a_off, uint32_t a_len) {
  ++m_stat_num_blocks_recvd;
  if (a_q.read_avail() < a_len) {
    TRC_ERROR("read avail < len");
    return NTRNT_STATUS_ERROR;
  }
  // -------------------------------------------------
  // recv
  // -------------------------------------------------
  bool l_f = false;
  int32_t l_s;
  bool l_new_piece = false;
  uint32_t l_block = a_off / NTRNT_TORRENT_BLOCK_SIZE;
  uint64_t l_key = (((uint64_t)a_idx << 32)) | ((uint64_t)(l_block));
  // -------------------------------------------------
  // block accepting/recv strategy is a:
  // "liberal in what is accepted and strict in what
  //  is tracked" approach.
  // This is due to observed behavior in peers that
  // send a choke but then respond with the previous
  // block requests.
  // -------------------------------------------------
  // -------------------------------------------------
  // check if already has block
  // discard if torrent already has block
  // -------------------------------------------------
  // TODO len check!!!
  blocks_t& l_pb = *(m_blocks_vec[a_idx]);
  if (l_pb.m_btfield.test(l_block)) {
    a_q.discard(a_len);
  }
  // -------------------------------------------------
  // write
  // -------------------------------------------------
  else {
    l_s = write(a_q, a_idx, a_off, a_len);
    if (l_s != NTRNT_STATUS_OK) {
      TRC_ERROR("performing torrent write");
      return NTRNT_STATUS_ERROR;
    }
    // -----------------------------------------
    // set torrent blocks bitfield
    // -----------------------------------------
    // TODO len check!!!
    blocks_t& l_bs = *(m_blocks_vec[a_idx]);
    l_bs.m_btfield.set(l_block, true);
    // -----------------------------------------
    // check all set
    // -----------------------------------------
    if (l_bs.m_btfield.has_all()) {
      // ---------------------------------
      // validate
      // ---------------------------------
      l_f = validate_piece(a_idx);
      if (!l_f) {
        // TODO -should prolly fail differently here
        TRC_ERROR("validating piece: %u", a_idx);
        return NTRNT_STATUS_ERROR;
      }
      m_pieces.set(a_idx, true);
      // ---------------------------------
      // check is complete
      // ---------------------------------
      if (m_pieces.has_all()) {
        m_complete = true;
      }
      l_new_piece = true;
    }
  }
  // -------------------------------------------------
  // broadcast have to swarm if got new piece
  // -------------------------------------------------
  if (l_new_piece) {
    peer_vec_t& l_pc = m_session.get_peer_mgr().get_peer_connected_vec();
    for (auto&& i_p : l_pc) {
      if (!i_p) {
        continue;
      }
      peer* l_peer = i_p;
      if (l_peer->get_state() != peer::STATE_CONNECTED) {
        continue;
      }
      l_s = l_peer->btp_send_have(a_idx);
      if (l_s != NTRNT_STATUS_OK) {
        TRC_ERROR("performing peer btp send have");
        return NTRNT_STATUS_ERROR;
      }
    }
  }
  // -------------------------------------------------
  // br tracking
  // -------------------------------------------------
  auto i_br = m_block_rqst_map.find(l_key);
  if (i_br != m_block_rqst_map.end()) {
    // -----------------------------------------
    // find block rqst to be removed
    // -----------------------------------------
    block_rqst_t& l_br = i_br->second;
    if (l_br.m_ctx == (void*)a_peer) {
      m_block_rqst_map.erase(i_br);
    }
  }
  if (a_peer->m_num_block_rqst_inflight > 0) {
    --(a_peer->m_num_block_rqst_inflight);
  }
  // -------------------------------------------------
  // if inflight < low water -request more
  // -------------------------------------------------
  if (!m_complete && (a_peer->m_num_block_rqst_inflight <
                      NTRNT_SESSION_PEER_INFLIGHT_LOW_WATER)) {
    l_s = peer_request_more(*a_peer);
    if (l_s != NTRNT_STATUS_OK) {
      TRC_ERROR("performing peer_request_more");
      return NTRNT_STATUS_ERROR;
    }
  }
  return NTRNT_STATUS_OK;
}
}  // namespace ns_ntrnt
