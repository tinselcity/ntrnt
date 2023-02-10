//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
// ---------------------------------------------------------
// internal
// ---------------------------------------------------------
#include "ntrnt/def.h"
// ---------------------------------------------------------
// internal
// ---------------------------------------------------------
#include "support/ndebug.h"
#include "support/trace.h"
#include "support/util.h"
#include "support/net_util.h"
#include "dht/dhsco.h"
// ---------------------------------------------------------
// rapidson -for load/store state
// ---------------------------------------------------------
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/prettywriter.h"
// ---------------------------------------------------------
// std lib
// ---------------------------------------------------------
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#ifndef _DHSCO_MSG_CONFIRM
#define _DHSCO_MSG_CONFIRM 0
#endif
#define _DHSCO_TOKEN_SIZE 8
// max number of peers store for given hash.
#define _DHSCO_MAX_PEERS 2048
// max number of hashes willing to track.
#define _DHSCO_MAX_HASHES 16384
// max number of searches keep data about.
#define _DHSCO_MAX_SEARCHES 1024
// time after which consider search to be expirable.
#define _DHSCO_SEARCH_EXPIRE_TIME (62 * 60)
// max number of in-flight queries per search.
#define _DHSCO_INFLIGHT_QUERIES 4
// retransmit timeout when performing searches.
#define _DHSCO_SEARCH_RETRANSMIT 10
#define _DHSCO_SEARCH_NODES 14
#define _DHSCO_MAX_TOKEN_BUCKET_TOKENS 400
// ---------------------------------------------------------
// masks
// ---------------------------------------------------------
#define WANT4 1
#define WANT6 2
// ---------------------------------------------------------
// parsing
// ---------------------------------------------------------
#define PARSE_TID_LEN 16
#define PARSE_TOKEN_LEN 128
#define PARSE_NODES_LEN (26 * 16)
#define PARSE_NODES6_LEN (38 * 16)
#define PARSE_VALUES_LEN 2048
#define PARSE_VALUES6_LEN 2048
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#define MAX(x, y) ((x) >= (y) ? (x) : (y))
#define MIN(x, y) ((x) <= (y) ? (x) : (y))
#define CHECK(offset, delta, size) \
                if(delta < 0 || offset + delta > size) goto fail
#define INC(offset, delta, size) \
                CHECK(offset, delta, size); \
                offset += delta
#define COPY(buf, offset, src, delta, size) \
                CHECK(offset, delta, size); \
                memcpy(buf + offset, src, delta); \
                offset += delta;
#define ADD_V(buf, offset, size) \
                if(m_have_v) { \
                        COPY(buf, offset, m_my_v, sizeof(m_my_v), size); \
                }
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! message types
//! ----------------------------------------------------------------------------
typedef enum _msg_type {
        MSG_TYPE_ERROR = 0,
        MSG_TYPE_REPLY = 1,
        MSG_TYPE_PING = 2,
        MSG_TYPE_FIND_NODE = 3,
        MSG_TYPE_GET_PEERS = 4,
        MSG_TYPE_ANNOUNCE_PEER = 5
} msg_type_t;
//! ----------------------------------------------------------------------------
//! \struct: node_t
//! ----------------------------------------------------------------------------
typedef struct _node
{
        uint8_t m_id[20];
        struct sockaddr_storage m_ss;
        int m_sslen;
        time_t m_time;
        // time of last message received
        time_t m_reply_time;
        // time of last correct reply received
        time_t m_pinged_time;
        // time of last request
        int m_pinged;
        // how many requests we sent since last reply
        struct _node *m_next;
} node_t;
//! ----------------------------------------------------------------------------
//! \struct: bucket_t
//! ----------------------------------------------------------------------------
typedef struct _bucket
{
        int m_af;
        uint8_t m_first[20];
        int m_count;
        // number of nodes
        int m_max_count;
        // max number of nodes for this bucket
        time_t m_time;
        // time of last reply in this bucket
        node_t* m_nodes;
        struct sockaddr_storage m_cached;
        // the address of a likely candidate
        int m_cached_len;
        struct _bucket *m_next;
} bucket_t;
//! ----------------------------------------------------------------------------
//! \struct: search_node_t
//! ----------------------------------------------------------------------------
typedef struct _search_node
{
        uint8_t m_id[20];
        struct sockaddr_storage m_ss;
        int m_sslen;
        time_t m_request_time;
        // the time of the last unanswered request
        time_t m_reply_time;
        // the time of the last reply
        int m_pinged;
        uint8_t m_token[40];
        int m_token_len;
        int m_replied;
        // whether we have received a reply
        int m_acked;
        // whether they acked our announcement
} search_node_t;
//! ----------------------------------------------------------------------------
//! \struct: search_t
//! When performing a search, we search for up to _DHSCO_SEARCH_NODES closest nodes
//! to the destination, and use the additional ones to backtrack if any of
//! the target 8 turn out to be dead.
//! ----------------------------------------------------------------------------
typedef struct _search
{
        uint16_t m_tid;
        int m_af;
        time_t m_step_time;
        // the time of the last search_step
        uint8_t m_id[20];
        uint16_t m_port;
        // 0 for pure m_searches
        int m_done;
        search_node_t m_nodes[_DHSCO_SEARCH_NODES];
        int m_num_nodes;
        struct _search* m_next;
} search_t;
//! ----------------------------------------------------------------------------
//! \struct: peer_t
//! ----------------------------------------------------------------------------
typedef struct _peer
{
        time_t m_time;
        uint8_t m_ip[16];
        uint16_t m_len;
        uint16_t m_port;
} peer_t;
//! ----------------------------------------------------------------------------
//! \struct: storage_t
//! ----------------------------------------------------------------------------
typedef struct _storage
{
        uint8_t m_id[20];
        int m_num_peers;
        int m_max_peers;
        peer_t* m_peers;
        struct _storage* m_next;
} storage_t;
//! ----------------------------------------------------------------------------
//! \struct: parsed_message_t
//! ----------------------------------------------------------------------------
typedef struct _parsed_message
{
        uint8_t m_tid[PARSE_TID_LEN];
        uint16_t m_tid_len;
        uint8_t m_id[20];
        uint8_t m_info_hash[20];
        uint8_t m_target[20];
        uint16_t m_port;
        uint16_t m_implied_port;
        uint8_t m_token[PARSE_TOKEN_LEN];
        uint16_t m_token_len;
        uint8_t m_nodes[PARSE_NODES_LEN];
        uint16_t m_nodes_len;
        uint8_t m_nodes6[PARSE_NODES6_LEN];
        uint16_t m_nodes6_len;
        uint8_t m_values[PARSE_VALUES_LEN];
        uint16_t m_values_len;
        uint8_t m_values6[PARSE_VALUES6_LEN];
        uint16_t m_values6_len;
        uint16_t m_want;
} parsed_message_t;
//! ----------------------------------------------------------------------------
//! globals
//! ----------------------------------------------------------------------------
static const uint8_t s_zeroes[20] = { 0 };
static const uint8_t s_v4_prefix[16] = {
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0xFF, 0xFF,
        0, 0, 0, 0
};
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                     S T A T I C   F U N C T I O N S
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: transaction-ids are 4-bytes long, with the first two bytes
//!           identifying the kind of request, and the remaining two a sequence
//!           number in host order.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static void _make_tid(uint8_t* a_tid_return, const char* a_prefix, uint16_t a_seq_no)
{
        a_tid_return[0] = a_prefix[0] & 0xFF;
        a_tid_return[1] = a_prefix[1] & 0xFF;
        memcpy(a_tid_return + 2, &a_seq_no, 2);
}
//! ----------------------------------------------------------------------------
//! \details: test if address is in local address range
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static bool _is_local(const struct sockaddr* a_sa)
{
        switch (a_sa->sa_family)
        {
        case AF_INET:
        {
                struct sockaddr_in* l_sin = (struct sockaddr_in*)a_sa;
                const uint8_t* l_addr = (const uint8_t*) &l_sin->sin_addr;
                return (l_sin->sin_port == 0) ||
                       (l_addr[0] == 0) ||
                       (l_addr[0] == 127) ||
                       ((l_addr[0] & 0xE0) == 0xE0);
        }
        case AF_INET6:
        {
                struct sockaddr_in6* l_sin6 = (struct sockaddr_in6*)a_sa;
                const uint8_t* l_addr = (const uint8_t*) &l_sin6->sin6_addr;
                return (l_sin6->sin6_port == 0) ||
                       (l_addr[0] == 0xFF) ||
                       (l_addr[0] == 0xFE &&
                       (l_addr[1] & 0xC0) == 0x80) ||
                       ((memcmp(l_addr, s_zeroes, 15) == 0) &&
                        ((l_addr[15] == 0) ||
                         (l_addr[15] == 1))) ||
                        (memcmp(l_addr, s_v4_prefix, 12) == 0);
        }
        default:
                return false;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int _parse_message(const uint8_t* a_buf,
                          int a_buf_len,
                          parsed_message_t *ao_msg)
{
        const uint8_t* p = nullptr;
        // -------------------------------------------------
        // ensure buffer is null-terminated.
        // -------------------------------------------------
        if (a_buf[a_buf_len] != '\0')
        {
                TRC_ERROR("Error _parse_message with unterminated buffer.");
                return NTRNT_STATUS_ERROR;
        }
#define _CHECK(ptr, len) if(((uint8_t*)ptr) + (len) > (a_buf) + (a_buf_len)) goto overflow;
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        p = (const uint8_t*)memmem(a_buf, a_buf_len, "1:t", 3);
        if (p)
        {
                long l;
                char *q;
                l = strtol((char*) p + 3, &q, 10);
                if (q && *q == ':' && l > 0 && l < PARSE_TID_LEN)
                {
                        _CHECK(q + 1, l);
                        memcpy(ao_msg->m_tid, q + 1, l);
                        ao_msg->m_tid_len = l;
                }
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        p = (const uint8_t*)memmem(a_buf, a_buf_len, "2:id20:", 7);
        if (p)
        {
                _CHECK(p + 7, 20);
                memcpy(ao_msg->m_id, p + 7, 20);
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        p = (const uint8_t*)memmem(a_buf, a_buf_len, "9:info_hash20:", 14);
        if (p)
        {
                _CHECK(p + 14, 20);
                memcpy(ao_msg->m_info_hash, p + 14, 20);
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        p = (const uint8_t*)memmem(a_buf, a_buf_len, "4:porti", 7);
        if (p)
        {
                long l;
                char *q;
                l = strtol((char*) p + 7, &q, 10);
                if (q && *q == 'e' && l > 0 && l < 0x10000)
                {
                        ao_msg->m_port = l;
                }
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        p = (const uint8_t*)memmem(a_buf, a_buf_len, "12:implied_porti", 16);
        if (p)
        {
                long l;
                char *q;
                l = strtol((char*) p + 16, &q, 10);
                if (q && *q == 'e' && l > 0 && l < 0x10000)
                {
                        ao_msg->m_implied_port = l;
                }
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        p = (const uint8_t*)memmem(a_buf, a_buf_len, "6:target20:", 11);
        if (p)
        {
                _CHECK(p + 11, 20);
                memcpy(ao_msg->m_target, p + 11, 20);
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        p = (const uint8_t*)memmem(a_buf, a_buf_len, "5:token", 7);
        if (p)
        {
                long l;
                char *q;
                l = strtol((char*) p + 7, &q, 10);
                if (q && *q == ':' && l > 0 && l < PARSE_TOKEN_LEN)
                {
                        _CHECK(q + 1, l);
                        memcpy(ao_msg->m_token, q + 1, l);
                        ao_msg->m_token_len = l;
                }
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        p = (const uint8_t*)memmem(a_buf, a_buf_len, "5:nodes", 7);
        if (p)
        {
                long l;
                char *q;
                l = strtol((char*) p + 7, &q, 10);
                if (q && *q == ':' && l > 0 && l <= PARSE_NODES_LEN)
                {
                        _CHECK(q + 1, l);
                        memcpy(ao_msg->m_nodes, q + 1, l);
                        ao_msg->m_nodes_len = l;
                }
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        p = (const uint8_t*)memmem(a_buf, a_buf_len, "6:nodes6", 8);
        if (p)
        {
                long l;
                char *q;
                l = strtol((char*) p + 8, &q, 10);
                if (q && *q == ':' && l > 0 && l <= PARSE_NODES6_LEN)
                {
                        _CHECK(q + 1, l);
                        memcpy(ao_msg->m_nodes6, q + 1, l);
                        ao_msg->m_nodes6_len = l;
                }
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        p = (const uint8_t*)memmem(a_buf, a_buf_len, "6:valuesl", 9);
        if (p)
        {
                int i = p - a_buf + 9;
                int j = 0, j6 = 0;
                while (1)
                {
                        long l;
                        char *q;
                        l = strtol((char*) a_buf + i, &q, 10);
                        if (q && *q == ':' && l > 0)
                        {
                                _CHECK(q + 1, l);
                                i = q + 1 + l - (char*) a_buf;
                                if (l == 6)
                                {
                                        if (j + l > PARSE_VALUES_LEN)
                                        {
                                                continue;
                                        }
                                        memcpy((char*) ao_msg->m_values + j, q + 1, l);
                                        j += l;
                                }
                                else if (l == 18)
                                {
                                        if (j6 + l > PARSE_VALUES6_LEN)
                                        {
                                                continue;
                                        }
                                        memcpy((char*) ao_msg->m_values6 + j6, q + 1, l);
                                        j6 += l;
                                }
                                else
                                {
                                        TRC_DEBUG("Received weird value -- %d bytes.", (int) l);
                                }
                        }
                        else
                        {
                                break;
                        }
                }
                if (i >= a_buf_len || a_buf[i] != 'e')
                {
                        TRC_WARN("unexpected end for values.");
                }
                ao_msg->m_values_len = j;
                ao_msg->m_values6_len = j6;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        p = (const uint8_t*)memmem(a_buf, a_buf_len, "4:wantl", 7);
        if (p)
        {
                int i = p - a_buf + 7;
                ao_msg->m_want = 0;
                while (a_buf[i] > '0' && a_buf[i] <= '9' && a_buf[i + 1] == ':' && i + 2 + a_buf[i] - '0' < a_buf_len)
                {
                        _CHECK(a_buf + i + 2, a_buf[i] - '0');
                        if (a_buf[i] == '2' && memcmp(a_buf + i + 2, "n4", 2) == 0)
                        {
                                ao_msg->m_want |= WANT4;
                        }
                        else if (a_buf[i] == '2' && memcmp(a_buf + i + 2, "n6", 2) == 0)
                        {
                                ao_msg->m_want |= WANT6;
                        }
                        else
                        {
                                TRC_WARN("unexpected want flag (%c)", a_buf[i]);
                        }
                        i += 2 + a_buf[i] - '0';
                }
                if (i >= a_buf_len || a_buf[i] != 'e')
                {
                        TRC_WARN("unexpected end for want.");
                }
        }
#undef _CHECK
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        if (memmem(a_buf, a_buf_len, "1:y1:r", 6))
        {
                return MSG_TYPE_REPLY;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        if (memmem(a_buf, a_buf_len, "1:y1:e", 6))
        {
                return MSG_TYPE_ERROR;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        if (!memmem(a_buf, a_buf_len, "1:y1:q", 6))
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        if (memmem(a_buf, a_buf_len, "1:q4:ping", 9))
        {
                return MSG_TYPE_PING;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        if (memmem(a_buf, a_buf_len, "1:q9:_find_node", 14))
        {
                return MSG_TYPE_FIND_NODE;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        if (memmem(a_buf, a_buf_len, "1:q9:get_peers", 14))
        {
                return MSG_TYPE_GET_PEERS;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        if (memmem(a_buf, a_buf_len, "1:q13:announce_peer", 19))
        {
                return MSG_TYPE_ANNOUNCE_PEER;
        }
        TRC_ERROR("unrecognized message");
        return NTRNT_STATUS_ERROR;
overflow:
        TRC_ERROR("Truncated message.");
        return NTRNT_STATUS_ERROR;
}
//! ----------------------------------------------------------------------------
//! \details: Forget about the ``XOR-metric''.
//!           An id is just a path from the root of the tree,
//!           so bits are numbered from the start.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int _id_cmp(const uint8_t* a_id1, const uint8_t* a_id2)
{
        // memcmp is guaranteed to perform an unsigned comparison.
        return memcmp(a_id1, a_id2, 20);
}
//! ----------------------------------------------------------------------------
//! \details: Find the lowest 1 bit in an id.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int _lowbit(const uint8_t* a_id)
{
        int i_b;
        int j_b;
        for (i_b = 19; i_b >= 0; i_b--)
        {
                if (a_id[i_b] != 0)
                {
                        break;
                }
        }
        if (i_b < 0)
        {
                return NTRNT_STATUS_ERROR;
        }
        for (j_b = 7; j_b >= 0; j_b--)
        {
                if ((a_id[i_b] & (0x80 >> j_b)) != 0)
                {
                        break;
                }
        }
        return 8 * i_b + j_b;
}
//! ----------------------------------------------------------------------------
//! \details: Determine whether id1 or id2 is closer to ref
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int xorcmp(const uint8_t* a_id1, const uint8_t* a_id2, const uint8_t* a_ref)
{
        int i_c;
        for (i_c = 0; i_c < 20; ++i_c)
        {
                uint8_t l_xor1;
                uint8_t l_xor2;
                if (a_id1[i_c] == a_id2[i_c])
                {
                        continue;
                }
                l_xor1 = a_id1[i_c] ^ a_ref[i_c];
                l_xor2 = a_id2[i_c] ^ a_ref[i_c];
                if (l_xor1 < l_xor2)
                {
                        return -1;
                }
                else
                {
                        return 1;
                }
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: keep m_buckets in a sorted linked list.
//!           A bucket b ranges from:
//!             b->first inclusive up to b->next->first exclusive.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int _in_bucket(const uint8_t* a_id, bucket_t* a_b)
{
        return (_id_cmp(a_b->m_first, a_id) <= 0) &&
               ((a_b->m_next == NULL) ||
                (_id_cmp(a_id, a_b->m_next->m_first) < 0));
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static bucket_t* _find_bucket(const uint8_t* a_id, bucket_t* a_b)
{
        bucket_t* i_b = a_b;
        if (i_b == NULL)
        {
                return NULL;
        }
        // -------------------------------------------------
        // walk buckets search for id
        // -------------------------------------------------
        while (1)
        {
                // -----------------------------------------
                // end
                // -----------------------------------------
                if (i_b->m_next == NULL)
                {
                        return i_b;
                }
                // -----------------------------------------
                // found bucket
                // -----------------------------------------
                if (_id_cmp(a_id, i_b->m_next->m_first) < 0)
                {
                        return i_b;
                }
                i_b = i_b->m_next;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static bucket_t* _previous_bucket(bucket_t* a_b, bucket_t* a_buckets)
{
        bucket_t* i_b = a_buckets;
        // -------------------------------------------------
        // if head == current -no previous element
        // -------------------------------------------------
        if(a_b == i_b)
        {
                return NULL;
        }
        // -------------------------------------------------
        // walk bucket list until find next == target
        // -------------------------------------------------
        while(1)
        {
                // -----------------------------------------
                // target not found -give up
                // -----------------------------------------
                if(i_b->m_next == NULL)
                {
                        return NULL;
                }
                // -----------------------------------------
                // next == target -return current
                // -----------------------------------------
                if(i_b->m_next == a_b)
                {
                        return i_b;
                }
                // -----------------------------------------
                // next in list
                // -----------------------------------------
                i_b = i_b->m_next;
        }
}
//! ----------------------------------------------------------------------------
//! \details: Every bucket contains an unordered list of nodes.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static node_t* _find_node(const uint8_t* a_id, bucket_t* a_buckets)
{
        bucket_t* i_b = _find_bucket(a_id, a_buckets);
        node_t* i_n;
        if(i_b == NULL)
        {
                return NULL;
        }
        i_n = i_b->m_nodes;
        while(i_n)
        {
                if(_id_cmp(i_n->m_id, a_id) == 0)
                {
                        return i_n;
                }
                i_n = i_n->m_next;
        }
        return NULL;
}
//! ----------------------------------------------------------------------------
//! \details: Return a random node in a bucket.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static node_t* _random_node(bucket_t* a_b)
{
        node_t* n;
        int nn;
        if (a_b->m_count == 0)
        {
                return NULL;
        }
        nn = random() % a_b->m_count;
        n = a_b->m_nodes;
        while (nn > 0 && n)
        {
                n = n->m_next;
                nn--;
        }
        return n;
}
//! ----------------------------------------------------------------------------
//! \details: Return the middle id of a bucket.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int _bucket_middle(bucket_t* a_b, uint8_t* a_id_return)
{
        int l_bit1 = _lowbit(a_b->m_first);
        int l_bit2 = a_b->m_next ? _lowbit(a_b->m_next->m_first) : -1;
        int l_bit = MAX(l_bit1, l_bit2) + 1;
        if (l_bit >= 160)
        {
                return NTRNT_STATUS_ERROR;
        }
        memcpy(a_id_return, a_b->m_first, 20);
        a_id_return[l_bit / 8] |= (0x80 >> (l_bit % 8));
        return 1;
}
//! ----------------------------------------------------------------------------
//! \details: Return a random id within a bucket.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static void _bucket_random(bucket_t* a_b, uint8_t* a_id_return)
{
        int l_bit1 = _lowbit(a_b->m_first);
        int l_bit2 = a_b->m_next ? _lowbit(a_b->m_next->m_first) : -1;
        int l_bit = MAX(l_bit1, l_bit2) + 1;
        if (l_bit >= 160)
        {
                memcpy(a_id_return, a_b->m_first, 20);
        }
        memcpy(a_id_return, a_b->m_first, l_bit / 8);
        a_id_return[l_bit / 8] = a_b->m_first[l_bit / 8] & (0xFF00 >> (l_bit % 8));
        a_id_return[l_bit / 8] |= random() & 0xFF >> (l_bit % 8);
        for (int i_b = l_bit / 8 + 1; i_b < 20; ++i_b)
        {
                a_id_return[i_b] = random() & 0xFF;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static bool _tid_match(const uint8_t* a_tid,
                      const char *a_prefix,
                      uint16_t *a_seqno_return)
{
        if ((a_tid[0] == (a_prefix[0] & 0xFF)) &&
            (a_tid[1] == (a_prefix[1] & 0xFF)))
        {
                if (a_seqno_return)
                {
                        memcpy(a_seqno_return, a_tid + 2, 2);
                }
                return true;
        }
        else
        {
                return false;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static node_t* _append_nodes(node_t* a_n1, node_t* a_n2)
{
        if (a_n1 == NULL)
        {
                return a_n2;
        }
        if (a_n2 == NULL)
        {
                return a_n1;
        }
        node_t* l_n = a_n1;
        while (l_n->m_next != NULL)
        {
                l_n = l_n->m_next;
        }
        l_n->m_next = a_n2;
        return a_n1;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int _insert_closest_node(uint8_t* nodes,
                               int a_num_nodes,
                               const uint8_t* id,
                               node_t* n)
{
        int l_size;
        if (n->m_ss.ss_family == AF_INET)
        {
                l_size = 26;
        }
        else if (n->m_ss.ss_family == AF_INET6)
        {
                l_size = 38;
        }
        else
        {
                abort();
        }
        int i_n;
        for (i_n = 0; i_n < a_num_nodes; ++i_n)
        {
                if (_id_cmp(n->m_id, nodes + l_size * i_n) == 0)
                {
                        return a_num_nodes;
                }
                if (xorcmp(n->m_id, nodes + l_size * i_n, id) < 0)
                {
                        break;
                }
        }
        if (i_n == 8)
        {
                return a_num_nodes;
        }
        if (a_num_nodes < 8)
        {
                ++a_num_nodes;
        }
        if (i_n < a_num_nodes - 1)
        {
                memmove(nodes + l_size * (i_n + 1), nodes + l_size * i_n, l_size * (a_num_nodes - i_n - 1));
        }
        if (n->m_ss.ss_family == AF_INET)
        {
                struct sockaddr_in* sin = (struct sockaddr_in*) &n->m_ss;
                memcpy(nodes + l_size * i_n, n->m_id, 20);
                memcpy(nodes + l_size * i_n + 20, &sin->sin_addr, 4);
                memcpy(nodes + l_size * i_n + 24, &sin->sin_port, 2);
        }
        else if (n->m_ss.ss_family == AF_INET6)
        {
                struct sockaddr_in6* sin6 = (struct sockaddr_in6*) &n->m_ss;
                memcpy(nodes + l_size * i_n, n->m_id, 20);
                memcpy(nodes + l_size * i_n + 20, &sin6->sin6_addr, 16);
                memcpy(nodes + l_size * i_n + 36, &sin6->sin6_port, 2);
        }
        else
        {
                abort();
        }
        return a_num_nodes;
}
//! ----------------------------------------------------------------------------
//! \details: definition of a known-good node.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
bool _node_good(node_t* a_n, struct timeval& a_now)
{
        bool l_s = false;
        l_s = ((a_n->m_pinged <= 2) &&
               (a_n->m_reply_time >= a_now.tv_sec - 7200) &&
               (a_n->m_time >= a_now.tv_sec - 900));
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int _buffer_closest_nodes(uint8_t* a_nodes,
                                int a_num_nodes,
                                const uint8_t* a_id,
                                bucket_t* a_b,
                                struct timeval& a_now)
{
        node_t* i_n = a_b->m_nodes;
        while (i_n)
        {
                if (_node_good(i_n, a_now))
                {
                        a_num_nodes = _insert_closest_node(a_nodes, a_num_nodes, a_id, i_n);
                }
                i_n = i_n->m_next;
        }
        return a_num_nodes;
}
//! ----------------------------------------------------------------------------
//! \details: storage_t stores all stored peer addresses for a given info hash.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static storage_t* _find_storage(const uint8_t* a_id, storage_t* a_storage)
{
        storage_t *i_st = a_storage;
        while (i_st)
        {
                if (_id_cmp(a_id, i_st->m_id) == 0)
                {
                        break;
                }
                i_st = i_st->m_next;
        }
        return i_st;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static void _flush_search_node(search_node_t* a_sn, search_t* a_sr)
{
        int i = a_sn - a_sr->m_nodes;
        int j;
        for (j = i; j < a_sr->m_num_nodes - 1; ++j)
        {
                a_sr->m_nodes[j] = a_sr->m_nodes[j + 1];
        }
        --a_sr->m_num_nodes;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static search_t* _new_search(search_t** ao_searches,
                             uint32_t& ao_num_searches,
                             const struct timeval& a_now)
{
        search_t *l_sr_oldest = NULL;
        // -------------------------------------------------
        // Find the l_sr_oldest done search
        // -------------------------------------------------
        search_t* l_sr = *ao_searches;
        while (l_sr)
        {
                if (l_sr->m_done &&
                    (l_sr_oldest == NULL ||
                     l_sr_oldest->m_step_time > l_sr->m_step_time))
                {
                        l_sr_oldest = l_sr;
                }
                l_sr = l_sr->m_next;
        }
        // -------------------------------------------------
        // The l_sr_oldest slot is expired.
        // -------------------------------------------------
        if (l_sr_oldest &&
            l_sr_oldest->m_step_time < a_now.tv_sec - _DHSCO_SEARCH_EXPIRE_TIME)
        {
                return l_sr_oldest;
        }
        // -------------------------------------------------
        // Allocate a new slot.
        // -------------------------------------------------
        if (ao_num_searches < _DHSCO_MAX_SEARCHES)
        {
                l_sr = (search_t*)calloc(1, sizeof(search_t));
                if (l_sr != NULL)
                {
                        l_sr->m_next = *ao_searches;
                        *ao_searches = l_sr;
                        ++ao_num_searches;
                        return l_sr;
                }
        }
        // -------------------------------------------------
        // Return oldest slot if done.
        // -------------------------------------------------
        if (l_sr_oldest &&
            l_sr_oldest->m_done)
        {
                return l_sr_oldest;
        }
        // -------------------------------------------------
        // No available slots found, return NULL.
        // -------------------------------------------------
        return NULL;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static void _make_token(const struct sockaddr* a_sa,
                        const uint8_t* a_secret,
                        uint8_t* ao_token_return)
{
        void* l_ip;
        int l_iplen;
        uint16_t l_port;
        if (a_sa->sa_family == AF_INET)
        {
                struct sockaddr_in* l_sin = (struct sockaddr_in*)a_sa;
                l_ip = &l_sin->sin_addr;
                l_iplen = 4;
                l_port = htons(l_sin->sin_port);
        }
        else if (a_sa->sa_family == AF_INET6)
        {
                struct sockaddr_in6* l_sin6 = (struct sockaddr_in6*)a_sa;
                l_ip = &l_sin6->sin6_addr;
                l_iplen = 16;
                l_port = htons(l_sin6->sin6_port);
        }
        else
        {
                abort();
        }
        g_dhsco_hash_cb(ao_token_return,
                        _DHSCO_TOKEN_SIZE,
                        a_secret,
                        sizeof(a_secret),
                        l_ip,
                        l_iplen,
                        (uint8_t*)
                        &l_port,
                        2);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int _token_match(const uint8_t* token,
                        int token_len,
                        const struct sockaddr* a_sa,
                        const uint8_t* a_secret)
{
        uint8_t t[_DHSCO_TOKEN_SIZE];
        if (token_len != _DHSCO_TOKEN_SIZE)
        {
                return 0;
        }
        _make_token(a_sa, a_secret, t);
        if (memcmp(t, token, _DHSCO_TOKEN_SIZE) == 0)
        {
                return 1;
        }
        _make_token(a_sa, a_secret, t);
        if (memcmp(t, token, _DHSCO_TOKEN_SIZE) == 0)
        {
                return 1;
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: while search in progress, don't necessarily keep the nodes being
//!           walked in main bucket table.  Search in progress is identified by
//!           a unique transaction id: short (small enough to fit in tansaction
//!           id of the protocol packets).
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static search_t* _find_search(uint16_t a_tid, int a_af, search_t* a_searches)
{
        search_t* l_sr = a_searches;
        while (l_sr)
        {
                if ((l_sr->m_tid == a_tid) &&
                    (l_sr->m_af == a_af))
                {
                        return l_sr;
                }
                l_sr = l_sr->m_next;
        }
        return NULL;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int dhsco::send_closest_nodes(const struct sockaddr* a_sa,
                              int a_sa_len,
                              const uint8_t* a_tid,
                              int a_tid_len,
                              const uint8_t* a_id,
                              int a_want,
                              int a_af,
                              storage_t *a_st,
                              const uint8_t* a_token,
                              int a_token_len)
{
        uint8_t l_nodes[8*26];
        uint8_t l_nodes6[8*38];
        int l_num_nodes = 0;
        int l_num_nodes6 = 0;
        bucket_t* i_b;
        if (a_want <= 0)
        {
                a_want = a_sa->sa_family == AF_INET ? WANT4 : WANT6;
        }
        if ((a_want & WANT4))
        {
                i_b = _find_bucket(a_id, m_buckets);
                if (i_b)
                {
                        l_num_nodes = _buffer_closest_nodes(l_nodes, l_num_nodes, a_id, i_b, m_now);
                        if (i_b->m_next)
                        {
                                l_num_nodes = _buffer_closest_nodes(l_nodes, l_num_nodes, a_id, i_b->m_next, m_now);
                        }
                        i_b = _previous_bucket(i_b, m_buckets);
                        if (i_b)
                        {
                                l_num_nodes = _buffer_closest_nodes(l_nodes, l_num_nodes, a_id, i_b, m_now);
                        }
                }
        }
        if ((a_want & WANT6))
        {
                i_b = _find_bucket(a_id, m_buckets6);
                if (i_b)
                {
                        l_num_nodes6 = _buffer_closest_nodes(l_nodes6, l_num_nodes6, a_id, i_b, m_now);
                        if (i_b->m_next)
                        {
                                l_num_nodes6 = _buffer_closest_nodes(l_nodes6, l_num_nodes6, a_id, i_b->m_next, m_now);
                        }
                        i_b = _previous_bucket(i_b, m_buckets6);
                        if (i_b)
                        {
                                l_num_nodes6 = _buffer_closest_nodes(l_nodes6, l_num_nodes6, a_id, i_b, m_now);
                        }
                }
        }
        //TRC_DEBUG("  (%d+%d l_nodes.)", l_num_nodes, l_num_nodes6);
        return send_nodes_peers(a_sa,
                                a_sa_len,
                                a_tid,
                                a_tid_len,
                                l_nodes,
                                l_num_nodes * 26,
                                l_nodes6,
                                l_num_nodes6 * 38,
                                a_af,
                                a_st,
                                a_token,
                                a_token_len);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
bool dhsco::node_blacklisted(const struct sockaddr* a_sa, int a_sa_len)
{
        if ((unsigned) a_sa_len > sizeof(struct sockaddr_storage))
        {
                abort();
        }
        if (g_dhsco_blacklisted_cb(a_sa, a_sa_len))
        {
                return 1;
        }
        for (auto && i_sas : m_blocklist)
        {
                if (memcmp(&(i_sas), a_sa, a_sa_len) == 0)
                {
                        return true;
                }
        }
        return false;
}
//! ----------------------------------------------------------------------------
//! \details: Search contains a list of nodes, sorted by decreasing distance to
//!           the target.  Just got a new candidate, insert it in correct
//!           position or discard it.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
search_node_t* dhsco::insert_search_node(const uint8_t* a_id,
                                         const struct sockaddr* a_sa,
                                         int a_sa_len,
                                         search_t* a_sr,
                                         int a_replied,
                                         uint8_t* a_token,
                                         int a_token_len)
{
        search_node_t* i_sn;
        int i;
        int j;
        if (a_sa->sa_family != a_sr->m_af)
        {
                TRC_DEBUG("Attempted to insert node in the wrong family.");
                return NULL;
        }
        for (i = 0; i < a_sr->m_num_nodes; ++i)
        {
                if (_id_cmp(a_id, a_sr->m_nodes[i].m_id) == 0)
                {
                        i_sn = &a_sr->m_nodes[i];
                        goto found;
                }
                if (xorcmp(a_id, a_sr->m_nodes[i].m_id, a_sr->m_id) < 0)
                {
                        break;
                }
        }
        if (i == _DHSCO_SEARCH_NODES)
        {
                return NULL;
        }
        if (a_sr->m_num_nodes < _DHSCO_SEARCH_NODES)
        {
                a_sr->m_num_nodes++;
        }
        for (j = a_sr->m_num_nodes - 1; j > i; j--)
        {
                a_sr->m_nodes[j] = a_sr->m_nodes[j - 1];
        }
        i_sn = &a_sr->m_nodes[i];
        memset(i_sn, 0, sizeof(search_node_t));
        memcpy(i_sn->m_id, a_id, 20);
found:
        memcpy(&i_sn->m_ss, a_sa, a_sa_len);
        i_sn->m_sslen = a_sa_len;
        if (a_replied)
        {
                i_sn->m_replied = 1;
                i_sn->m_reply_time = m_now.tv_sec;
                i_sn->m_request_time = 0;
                i_sn->m_pinged = 0;
        }
        if (a_token)
        {
                if (a_token_len >= 40)
                {
                        TRC_DEBUG("Error Overlong token.");
                }
                else
                {
                        memcpy(i_sn->m_token, a_token, a_token_len);
                        i_sn->m_token_len = a_token_len;
                }
        }
        return i_sn;
}
//! ----------------------------------------------------------------------------
//! \details: Insert the contents of a bucket into a search structure.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void dhsco::insert_search_bucket(bucket_t* a_b, search_t* a_sr)
{
        node_t* i_n = nullptr;
        i_n = a_b->m_nodes;
        while (i_n)
        {
                insert_search_node(i_n->m_id,
                                   (struct sockaddr*)&i_n->m_ss,
                                   i_n->m_sslen,
                                   a_sr,
                                   0,
                                   NULL,
                                   0);
                i_n = i_n->m_next;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void dhsco::rotate_secrets(void)
{
        m_rotate_secrets_time = m_now.tv_sec + 900 + random() % 1800;
        memcpy(m_old_secret, m_secret, sizeof(m_secret));
        int l_s;
        l_s = g_dhsco_random_bytes_cb(m_secret, sizeof(m_secret));
        UNUSED(l_s);
}
//! ----------------------------------------------------------------------------
//! \details: Called periodically to purge known-bad nodes.
//!           Note it's conservative:
//!           - Broken nodes in the table don't do harm,
//!           - Will recover as it finds better ones.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void dhsco::expire_buckets(bucket_t* a_bucket)
{
        bucket_t* i_b = a_bucket;
        while (i_b)
        {
                node_t* i_n;
                node_t* i_p;
                bool l_changed = false;
                while (i_b->m_nodes &&
                       i_b->m_nodes->m_pinged >= 4)
                {
                        i_n = i_b->m_nodes;
                        i_b->m_nodes = i_n->m_next;
                        --(i_b->m_count);
                        l_changed = true;
                        free(i_n);
                }
                i_p = i_b->m_nodes;
                while (i_p)
                {
                        while (i_p->m_next &&
                               i_p->m_next->m_pinged >= 4)
                        {
                                i_n = i_p->m_next;
                                i_p->m_next = i_n->m_next;
                                --(i_b->m_count);
                                l_changed = true;
                                free(i_n);
                        }
                        i_p = i_p->m_next;
                }
                if (l_changed)
                {
                        send_cached_ping(i_b);
                }
                i_b = i_b->m_next;
        }
        m_expire_data_time = m_now.tv_sec + 120 + random() % 240;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void dhsco::expire_storage(void)
{
        storage_t* l_st = m_storage;
        storage_t* l_prev = NULL;
        while (l_st)
        {
                // -----------------------------------------
                // clean peers
                // -----------------------------------------
                int i_p = 0;
                while (i_p < l_st->m_num_peers)
                {
                        if (l_st->m_peers[i_p].m_time < m_now.tv_sec - 32 * 60)
                        {
                                if (i_p != l_st->m_num_peers - 1)
                                {
                                        l_st->m_peers[i_p] = l_st->m_peers[l_st->m_num_peers - 1];
                                }
                                --(l_st->m_num_peers);
                        }
                        else
                        {
                                ++i_p;
                        }
                }
                // -----------------------------------------
                // storage empty -delete...
                // -----------------------------------------
                if (l_st->m_num_peers == 0)
                {
                        free(l_st->m_peers);
                        if (l_prev)
                        {
                                l_prev->m_next = l_st->m_next;
                        }
                        else
                        {
                                m_storage = l_st->m_next;
                        }
                        free(l_st);
                        if (l_prev)
                        {
                                l_st = l_prev->m_next;
                        }
                        else
                        {
                                l_st = m_storage;
                        }
                        if (m_num_storage > 0)
                        {
                                --m_num_storage;
                        }
                }
                // -----------------------------------------
                // loop to next
                // -----------------------------------------
                else
                {
                        l_prev = l_st;
                        l_st = l_st->m_next;
                }
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void dhsco::expire_searches(dht_callback_t *a_cb, void* a_ctx)
{
        search_t* l_sr = m_searches;
        search_t* l_prev = NULL;
        while (l_sr)
        {
                search_t* l_next = l_sr->m_next;
                if (l_sr->m_step_time < m_now.tv_sec - _DHSCO_SEARCH_EXPIRE_TIME)
                {
                        if (l_prev)
                        {
                                l_prev->m_next = l_next;
                        }
                        else
                        {
                                m_searches = l_next;
                        }
                        --m_num_searches;
                        if (!l_sr->m_done &&
                                        a_cb)
                        {
                                (*a_cb)(a_ctx,
                                        l_sr->m_af == AF_INET ? DHT_EVENT_SEARCH_DONE : DHT_EVENT_SEARCH_DONE6,
                                        l_sr->m_id,
                                        NULL,
                                        0);
                        }
                        free(l_sr);
                }
                else
                {
                        l_prev = l_sr;
                }
                l_sr = l_next;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int dhsco::store(const uint8_t* a_id,
                 const struct sockaddr* a_sa,
                 uint16_t a_port)
{
        // -------------------------------------------------
        // get ip and len
        // -------------------------------------------------
        int l_len;
        uint8_t* l_ip;
        if (a_sa->sa_family == AF_INET)
        {
                struct sockaddr_in* sin = (struct sockaddr_in*)a_sa;
                l_ip = (uint8_t*) &sin->sin_addr;
                l_len = 4;
        }
        else if (a_sa->sa_family == AF_INET6)
        {
                struct sockaddr_in6* sin6 = (struct sockaddr_in6*)a_sa;
                l_ip = (uint8_t*) &sin6->sin6_addr;
                l_len = 16;
        }
        else
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // find storage for id
        // -------------------------------------------------
        storage_t *i_st = nullptr;
        i_st = _find_storage(a_id, m_storage);
        if (i_st == NULL)
        {
                if (m_num_storage >= _DHSCO_MAX_HASHES)
                {
                        return NTRNT_STATUS_ERROR;
                }
                i_st = (storage_t*)calloc(1, sizeof(storage_t));
                if (i_st == NULL)
                {
                        return NTRNT_STATUS_ERROR;
                }
                memcpy(i_st->m_id, a_id, 20);
                i_st->m_next = m_storage;
                m_storage = i_st;
                m_num_storage++;
        }
        // -------------------------------------------------
        // find peer location
        // -------------------------------------------------
        int i;
        for (i = 0; i < i_st->m_num_peers; ++i)
        {
                if ((i_st->m_peers[i].m_port == a_port) &&
                    (i_st->m_peers[i].m_len == l_len) &&
                    (memcmp(i_st->m_peers[i].m_ip, l_ip, l_len) == 0))
                {
                        break;
                }
        }
        // -------------------------------------------------
        // if already there, only need to refresh
        // -------------------------------------------------
        if (i < i_st->m_num_peers)
        {
                i_st->m_peers[i].m_time = m_now.tv_sec;
                return 0;
        }
        // -------------------------------------------------
        // need to expand array.
        // -------------------------------------------------
        if (i >= i_st->m_max_peers)
        {
                peer_t *l_new_peers;
                int l_num;
                if (i_st->m_max_peers >= _DHSCO_MAX_PEERS)
                {
                        return 0;
                }
                l_num = i_st->m_max_peers == 0 ? 2 : 2 * i_st->m_max_peers;
                l_num = MIN(l_num, _DHSCO_MAX_PEERS);
                l_new_peers = (peer_t*)realloc(i_st->m_peers, l_num * sizeof(peer_t));
                if (l_new_peers == NULL)
                {
                        return NTRNT_STATUS_ERROR;
                }
                i_st->m_peers = l_new_peers;
                i_st->m_max_peers = l_num;
        }
        peer_t *i_p;
        i_p = &i_st->m_peers[i_st->m_num_peers++];
        i_p->m_time = m_now.tv_sec;
        i_p->m_len = l_len;
        memcpy(i_p->m_ip, l_ip, l_len);
        i_p->m_port = a_port;
        return 1;
}
//! ----------------------------------------------------------------------------
//! \details: The internal m_blacklist is an LRU cache of nodes that have sent
//!           incorrect messages.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void dhsco::blacklist_node(const uint8_t*a_id,
                           const struct sockaddr* a_sa,
                           int a_sa_len)
{
        node_t* l_n = nullptr;
        search_t* l_sr = nullptr;
        bucket_t* l_buckets;
        TRC_DEBUG("Blacklisting broken node.");
        if (!a_id)
        {
                goto block_address;
        }
        l_buckets = m_buckets;
        if (a_sa->sa_family != AF_INET)
        {
                l_buckets = m_buckets6;
        }
        // -------------------------------------------------
        // Make the node easy to discard.
        // -------------------------------------------------
        l_n = _find_node(a_id, l_buckets);
        if (l_n)
        {
                l_n->m_pinged = 3;
                pinged(l_n, NULL);
        }
        // -------------------------------------------------
        // Discard it from any m_searches in progress.
        // -------------------------------------------------
        l_sr = m_searches;
        while (l_sr)
        {
                for (int i_n = 0; i_n < l_sr->m_num_nodes; ++i_n)
                {
                        if (_id_cmp(l_sr->m_nodes[i_n].m_id, a_id) == 0)
                        {
                                _flush_search_node(&l_sr->m_nodes[i_n], l_sr);
                        }
                }
                l_sr = l_sr->m_next;
        }
        // -------------------------------------------------
        // ensure don't hear from it again.
        // -------------------------------------------------
block_address:
        sockaddr_storage l_sas;
        memcpy(&l_sas, a_sa, a_sa_len);
        m_blocklist.push_back(l_sas);
}
//! ----------------------------------------------------------------------------
//! \details: Rate control for requests we receive.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
bool dhsco::rate_limit(void)
{
        if (m_token_bucket_tokens == 0)
        {
                m_token_bucket_tokens = MIN(_DHSCO_MAX_TOKEN_BUCKET_TOKENS,
                                            100 * (m_now.tv_sec - m_token_bucket_time));
                m_token_bucket_time = m_now.tv_sec;
        }
        if (m_token_bucket_tokens == 0)
        {
                return true;
        }
        m_token_bucket_tokens -= 1;
        return false;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int dhsco::send_buf(const void* a_buf,
                    size_t a_len,
                    int a_flags,
                    const struct sockaddr* a_sa,
                    int a_sa_len)
{
        int l_s;
        if (a_sa_len == 0)
        {
                abort();
        }
        if (node_blacklisted(a_sa, a_sa_len))
        {
                TRC_DEBUG("Attempting to send to blacklisted node.");
                errno = EPERM;
                return NTRNT_STATUS_ERROR;
        }
        if (a_sa->sa_family == AF_INET)
        {
                l_s = m_dht_socket;
        }
        else if (a_sa->sa_family == AF_INET6)
        {
                l_s = m_dht_socket6;
        }
        else
        {
                l_s = -1;
        }
        if (l_s < 0)
        {
                errno = EAFNOSUPPORT;
                return NTRNT_STATUS_ERROR;
        }
        return g_dhsco_sendto_cb(l_s, a_buf, a_len, a_flags, a_sa, a_sa_len);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int dhsco::send_ping(const struct sockaddr* a_sa,
                     int a_sa_len,
                     const uint8_t* a_tid,
                     int a_tid_len)
{
        char l_buf[512];
        int i_off = 0;
        int l_s;
        l_s = snprintf(l_buf + i_off, 512 - i_off, "d1:ad2:id20:");
        INC(i_off, l_s, 512);
        COPY(l_buf, i_off, m_myid, 20, 512);
        l_s = snprintf(l_buf + i_off, 512 - i_off, "e1:q4:ping1:t%d:", a_tid_len);
        INC(i_off, l_s, 512);
        COPY(l_buf, i_off, a_tid, a_tid_len, 512);
        ADD_V(l_buf, i_off, 512);
        l_s = snprintf(l_buf + i_off, 512 - i_off, "1:y1:qe");
        INC(i_off, l_s, 512);
        return send_buf(l_buf, i_off, 0, a_sa, a_sa_len);
fail:
        errno = ENOSPC;
        return NTRNT_STATUS_ERROR;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int dhsco::send_pong(const struct sockaddr* a_sa,
                     int a_sa_len,
                     const uint8_t* a_tid,
                     int a_tid_len)
{
        char l_buf[512];
        int i = 0, l_s;
        l_s = snprintf(l_buf + i, 512 - i, "d1:rd2:id20:");
        INC(i, l_s, 512);
        COPY(l_buf, i, m_myid, 20, 512);
        l_s = snprintf(l_buf + i, 512 - i, "e1:t%d:", a_tid_len);
        INC(i, l_s, 512);
        COPY(l_buf, i, a_tid, a_tid_len, 512);
        ADD_V(l_buf, i, 512);
        l_s = snprintf(l_buf + i, 512 - i, "1:y1:re");
        INC(i, l_s, 512);
        return send_buf(l_buf, i, 0, a_sa, a_sa_len);
fail:
        errno = ENOSPC;
        return NTRNT_STATUS_ERROR;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int dhsco::send_find_node(const struct sockaddr* a_sa,
                          int a_sa_len,
                          const uint8_t* a_tid,
                          int a_tid_len,
                          const uint8_t* a_target,
                          int a_want,
                          int a_confirm)
{
        char l_buf[512];
        int i = 0, l_s;
        l_s = snprintf(l_buf + i, 512 - i, "d1:ad2:id20:");
        INC(i, l_s, 512);
        COPY(l_buf, i, m_myid, 20, 512);
        l_s = snprintf(l_buf + i, 512 - i, "6:target20:");
        INC(i, l_s, 512);
        COPY(l_buf, i, a_target, 20, 512);
        if (a_want > 0)
        {
                l_s = snprintf(l_buf + i, 512 - i, "4:wantl%s%se",
                               (a_want & WANT4) ? "2:n4" : "",
                               (a_want & WANT6) ? "2:n6" : "");
                INC(i, l_s, 512);
        }
        l_s = snprintf(l_buf + i, 512 - i, "e1:q9:find_node1:t%d:", a_tid_len);
        INC(i, l_s, 512);
        COPY(l_buf, i, a_tid, a_tid_len, 512);
        ADD_V(l_buf, i, 512);
        l_s = snprintf(l_buf + i, 512 - i, "1:y1:qe");
        INC(i, l_s, 512);
        return send_buf(l_buf, i, a_confirm ? _DHSCO_MSG_CONFIRM : 0, a_sa, a_sa_len);
fail:
        errno = ENOSPC;
        return NTRNT_STATUS_ERROR;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int dhsco::send_nodes_peers(const struct sockaddr* a_sa,
                            int a_sa_len,
                            const uint8_t* a_tid,
                            int a_tid_len,
                            const uint8_t* a_nodes,
                            int a_nodes_len,
                            const uint8_t* a_nodes6,
                            int a_nodes6_len,
                            int a_af,
                            storage_t *a_st,
                            const uint8_t* a_token,
                            int a_token_len)
{
        char l_buf[2048];
        int i = 0;
        int l_s;
        int j0;
        int j;
        int k;
        int len;
        l_s = snprintf(l_buf + i, 2048 - i, "d1:rd2:id20:");
        INC(i, l_s, 2048);
        COPY(l_buf, i, m_myid, 20, 2048);
        if (a_nodes_len > 0)
        {
                l_s = snprintf(l_buf + i, 2048 - i, "5:nodes%d:", a_nodes_len);
                INC(i, l_s, 2048);
                COPY(l_buf, i, a_nodes, a_nodes_len, 2048);
        }
        if (a_nodes6_len > 0)
        {
                l_s = snprintf(l_buf + i, 2048 - i, "6:nodes6%d:", a_nodes6_len);
                INC(i, l_s, 2048);
                COPY(l_buf, i, a_nodes6, a_nodes6_len, 2048);
        }
        if (a_token_len > 0)
        {
                l_s = snprintf(l_buf + i, 2048 - i, "5:token%d:", a_token_len);
                INC(i, l_s, 2048);
                COPY(l_buf, i, a_token, a_token_len, 2048);
        }
        // -------------------------------------------------
        // treat storage as circular list, and serve
        // randomly chosen slice.
        // To ensure fit within 1024 octets limit to 50
        // peers.
        // -------------------------------------------------
        if (a_st &&
            a_st->m_num_peers > 0)
        {
                len = a_af == AF_INET ? 4 : 16;
                j0 = random() % a_st->m_num_peers;
                j = j0;
                k = 0;
                l_s = snprintf(l_buf + i, 2048 - i, "6:valuesl");
                INC(i, l_s, 2048);
                do
                {
                        if (a_st->m_peers[j].m_len == len)
                        {
                                uint16_t swapped;
                                swapped = htons(a_st->m_peers[j].m_port);
                                l_s = snprintf(l_buf + i, 2048 - i, "%d:", len + 2);
                                INC(i, l_s, 2048);
                                COPY(l_buf, i, a_st->m_peers[j].m_ip, len, 2048);
                                COPY(l_buf, i, &swapped, 2, 2048);
                                k++;
                        }
                        j = (j + 1) % a_st->m_num_peers;
                } while (j != j0 && k < 50);
                l_s = snprintf(l_buf + i, 2048 - i, "e");
                INC(i, l_s, 2048);
        }
        l_s = snprintf(l_buf + i, 2048 - i, "e1:t%d:", a_tid_len);
        INC(i, l_s, 2048);
        COPY(l_buf, i, a_tid, a_tid_len, 2048);
        ADD_V(l_buf, i, 2048);
        l_s = snprintf(l_buf + i, 2048 - i, "1:y1:re");
        INC(i, l_s, 2048);
        return send_buf(l_buf, i, 0, a_sa, a_sa_len);
fail:
        errno = ENOSPC;
        return NTRNT_STATUS_ERROR;
}
//! ----------------------------------------------------------------------------
//! \details: Every bucket caches the address of a likely node.  Ping it.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int dhsco::send_cached_ping(bucket_t* a_bucket)
{
        uint8_t l_tid[4];
        int l_s;
        // set family to 0 when there's no cached node.
        if (a_bucket->m_cached.ss_family == 0)
        {
                return 0;
        }
        //TRC_DEBUG("Sending ping to cached node.");
        _make_tid(l_tid, "pn", 0);
        l_s = send_ping((struct sockaddr*) &a_bucket->m_cached, a_bucket->m_cached_len, l_tid, 4);
        a_bucket->m_cached.ss_family = 0;
        a_bucket->m_cached_len = 0;
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details: Called whenever send a request to a node,
//!           increases the ping count and, if reaches 3,
//!           sends ping to new candidate.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void dhsco::pinged(node_t* a_n, bucket_t* a_b)
{
        ++(a_n->m_pinged);
        a_n->m_pinged_time = m_now.tv_sec;
        if (a_n->m_pinged >= 3)
        {
                bucket_t* l_b;
                if (a_b)
                {
                        l_b = a_b;
                }
                else
                {
                        bucket_t* l_buckets = nullptr;
                        if (a_n->m_ss.ss_family == AF_INET)
                        {
                                l_buckets = m_buckets;
                        }
                        else
                        {
                                l_buckets = m_buckets6;
                        }
                        l_b = _find_bucket(a_n->m_id, l_buckets);
                }
                send_cached_ping(l_b);
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int dhsco::upkeep_buckets(int a_family)
{
        bucket_t* i_b = nullptr;
        bucket_t* l_buckets;
        if (a_family == AF_INET)
        {
                i_b = m_buckets;
                l_buckets = m_buckets;
        }
        else
        {
                i_b = m_buckets6;
                l_buckets = m_buckets6;
        }
        while (i_b)
        {
                // -----------------------------------------
                // 10 minutes for an 8-node bucket
                // -----------------------------------------
                int to = MAX(600 / (i_b->m_max_count / 8), 30);
                bucket_t* i_q;
                if (i_b->m_time >= m_now.tv_sec - to)
                {
                        i_b = i_b->m_next;
                        continue;
                }
                // -----------------------------------------
                // bucket hasn't seen positive confirmation
                // for a long time.
                // Pick random l_id in bucket's range, and
                // send request to a random node.
                // -----------------------------------------
                uint8_t l_id[20];
                node_t* i_n;
                _bucket_random(i_b, l_id);
                i_q = i_b;
                // -----------------------------------------
                // If bucket is empty, try to fill it from a
                // neighbour.
                // Occasionally do it gratuitiously to
                // recover from buckets full of broken nodes.
                // -----------------------------------------
                if (i_q->m_next &&
                    (i_q->m_count == 0 ||
                     (random() & 7) == 0))
                {
                        i_q = i_b->m_next;
                }
                if (i_q->m_count == 0 ||
                    (random() & 7) == 0)
                {
                        bucket_t* r;
                        r = _previous_bucket(i_b, l_buckets);
                        if (r && r->m_count > 0)
                        {
                                i_q = r;
                        }
                }
                if (!i_q)
                {
                        i_b = i_b->m_next;
                        continue;
                }
                i_n = _random_node(i_q);
                if (!i_n)
                {
                        i_b = i_b->m_next;
                        continue;
                }
                bucket_t* l_other_bucket;
                l_other_bucket = _find_bucket(l_id, l_buckets);
                // ---------------------------------
                // corresponding bucket in the other
                // family is not full
                // - querying both is useful.
                // ---------------------------------
                int l_want = -1;
                if (l_other_bucket &&
                    l_other_bucket->m_count < l_other_bucket->m_max_count)
                {
                        l_want = WANT4 | WANT6;
                }
                // ---------------------------------
                // Most of the time, this just adds
                // overhead.
                // However, it might help stitch
                // back one of the DHTs after a
                // network collapse, so query both,
                // but only very occasionally.
                // ---------------------------------
                else if (random() % 37 == 0)
                {
                        l_want = WANT4 | WANT6;
                }
                // -----------------------------------------
                // sending find for nodes
                // -----------------------------------------
                TRC_DEBUG("Sending _find_node for%s bucket maintenance.",
                          a_family == AF_INET6 ? " IPv6" : "");
                // -----------------------------------------
                // create tid
                // -----------------------------------------
                uint8_t l_tid[4];
                _make_tid(l_tid, "fn", 0);
                // -----------------------------------------
                // send find node
                // -----------------------------------------
                send_find_node((struct sockaddr*) &i_n->m_ss,
                                i_n->m_sslen,
                                l_tid,
                                4,
                                l_id,
                                l_want,
                                i_n->m_reply_time >= m_now.tv_sec - 15);
                // -----------------------------------------
                // pinged
                // -----------------------------------------
                pinged(i_n, i_q);
                // -----------------------------------------
                // to avoid sending queries back-to-back,
                // give up for now and reschedule ASAP
                // -----------------------------------------
                return 1;
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int dhsco::upkeep_neighborhood(int a_family)
{
        bucket_t* l_buckets = nullptr;
        if (a_family == AF_INET)
        {
                l_buckets = m_buckets;
        }
        else
        {
                l_buckets = m_buckets6;
        }
        bucket_t* i_b = _find_bucket(m_myid, l_buckets);
        if (i_b == NULL)
        {
                return 0;
        }
        // -------------------------------------------------
        // generate new id
        // -------------------------------------------------
        uint8_t l_id[20];
        memcpy(l_id, m_myid, 20);
        l_id[19] = random() & 0xFF;
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        bucket_t* i_q = i_b;
        if (i_q->m_next &&
            (i_q->m_count == 0 || (random() & 7) == 0))
        {
                i_q = i_b->m_next;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        if (i_q->m_count == 0 ||
            (random() & 7) == 0)
        {
                bucket_t* i_r;
                i_r = _previous_bucket(i_b, l_buckets);
                if (i_r &&
                    (i_r->m_count > 0))
                {
                        i_q = i_r;
                }
        }
        if (!i_q)
        {
                return 0;
        }
        // -------------------------------------------------
        // Since this node-id is same in both DHTs, it's
        // probably better to query both families.
        // -------------------------------------------------
        int l_want = m_dht_socket >= 0 && m_dht_socket6 >= 0 ? (WANT4 | WANT6) : -1;
        node_t* l_n = nullptr;
        l_n = _random_node(i_q);
        if (l_n)
        {
                uint8_t l_tid[4];
                //TRC_DEBUG("Sending _find_node for%s neighborhood maintenance.",
                //          a_family == AF_INET6 ? " IPv6" : "");
                _make_tid(l_tid, "fn", 0);
                send_find_node((struct sockaddr*)&(l_n->m_ss),
                               l_n->m_sslen,
                               l_tid,
                               4,
                               l_id,
                               l_want,
                               l_n->m_reply_time >= m_now.tv_sec - 15);
                pinged(l_n, i_q);
        }
        return 1;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int dhsco::send_get_peers(const struct sockaddr* a_sa,
                          int a_sa_len,
                          uint8_t* a_tid,
                          int a_tid_len,
                          uint8_t* a_infohash,
                          int a_want,
                          int a_confirm)
{
        char l_buf[512];
        int i = 0, l_s;
        l_s = snprintf(l_buf + i, 512 - i, "d1:ad2:id20:");
        INC(i, l_s, 512);
        COPY(l_buf, i, m_myid, 20, 512);
        l_s = snprintf(l_buf + i, 512 - i, "9:info_hash20:");
        INC(i, l_s, 512);
        COPY(l_buf, i, a_infohash, 20, 512);
        if (a_want > 0)
        {
                l_s = snprintf(l_buf + i, 512 - i, "4:wantl%s%se",
                               (a_want & WANT4) ? "2:n4" : "",
                               (a_want & WANT6) ? "2:n6" : "");
                INC(i, l_s, 512);
        }
        l_s = snprintf(l_buf + i, 512 - i, "e1:q9:get_peers1:t%d:", a_tid_len);
        INC(i, l_s, 512);
        COPY(l_buf, i, a_tid, a_tid_len, 512);
        ADD_V(l_buf, i, 512);
        l_s = snprintf(l_buf + i, 512 - i, "1:y1:qe");
        INC(i, l_s, 512);
        return send_buf(l_buf, i, a_confirm ? _DHSCO_MSG_CONFIRM : 0, a_sa, a_sa_len);
fail:
        errno = ENOSPC;
        return NTRNT_STATUS_ERROR;
}
//! ----------------------------------------------------------------------------
//! \details: must always return 0 or 1,
//!           never -1, not even on failure (see below).
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int dhsco::search_send_get_peers(search_t* a_sr, search_node_t* a_n)
{
        node_t* l_node;
        uint8_t l_tid[4];
        if (a_n == NULL)
        {
                int i;
                for (i = 0; i < a_sr->m_num_nodes; ++i)
                {
                        if (a_sr->m_nodes[i].m_pinged < 3 &&
                            !a_sr->m_nodes[i].m_replied &&
                            a_sr->m_nodes[i].m_request_time < m_now.tv_sec - _DHSCO_SEARCH_RETRANSMIT)
                        {
                                a_n = &a_sr->m_nodes[i];
                        }
                }
        }
        if (!a_n ||
            a_n->m_pinged >= 3 ||
            a_n->m_replied ||
            a_n->m_request_time >= m_now.tv_sec - _DHSCO_SEARCH_RETRANSMIT)
        {
                return 0;
        }
        //TRC_DEBUG("Sending get_peers.");
        _make_tid(l_tid, "gp", a_sr->m_tid);
        send_get_peers((struct sockaddr*) &a_n->m_ss,
                       a_n->m_sslen,
                       l_tid,
                       4,
                       a_sr->m_id,
                       -1,
                       a_n->m_reply_time >= m_now.tv_sec - _DHSCO_SEARCH_RETRANSMIT);
        ++a_n->m_pinged;
        a_n->m_request_time = m_now.tv_sec;
        // -------------------------------------------------
        // If node happens to be in our main routing table,
        // mark it as pinged.
        // -------------------------------------------------
        bucket_t* l_buckets = m_buckets;
        if (a_n->m_ss.ss_family != AF_INET)
        {
                l_buckets = m_buckets6;
        }
        l_node = _find_node(a_n->m_id, l_buckets);
        if (l_node)
        {
                pinged(l_node, NULL);
        }
        return 1;
}
//! ----------------------------------------------------------------------------
//! \details: Insert a new node into any incomplete search.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void dhsco::add_search_node(const uint8_t* a_id,
                            const struct sockaddr* a_sa,
                            int a_sa_len)
{
        search_t* l_sr;
        for (l_sr = m_searches; l_sr; l_sr = l_sr->m_next)
        {
                if (l_sr->m_af == a_sa->sa_family &&
                    l_sr->m_num_nodes < _DHSCO_SEARCH_NODES)
                {
                        search_node_t* i_n;
                        i_n = insert_search_node(a_id, a_sa, a_sa_len, l_sr, 0, NULL, 0);
                        if (i_n)
                        {
                                search_send_get_peers(l_sr, i_n);
                        }
                }
        }
}
//! ----------------------------------------------------------------------------
//! \details: just learned about a node, not necessarily a new one.
//!           Confirm is 1 if node sent a message, 2 if it sent us a reply.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
node_t* dhsco::new_node(const uint8_t* a_id,
                        const struct sockaddr* a_sa,
                        int a_sa_len,
                        int a_confirm)
{
        node_t* i_n;
        bucket_t* l_buckets = m_buckets;
        if (a_sa->sa_family != AF_INET)
        {
                l_buckets = m_buckets6;
        }
again:
        bucket_t* i_b;
        i_b = _find_bucket(a_id, l_buckets);
        if (i_b == NULL)
        {
                return NULL;
        }
        if (_id_cmp(a_id, m_myid) == 0)
        {
                return NULL;
        }
        if (_is_local(a_sa) ||
            node_blacklisted(a_sa, a_sa_len))
        {
                return NULL;
        }
        int l_my_bucket;
        l_my_bucket = _in_bucket(m_myid, i_b);
        if (a_confirm == 2)
        {
                i_b->m_time = m_now.tv_sec;
        }
        i_n = i_b->m_nodes;
        while (i_n)
        {
                if (_id_cmp(i_n->m_id, a_id) == 0)
                {
                        if (a_confirm ||
                            i_n->m_time < m_now.tv_sec - 15 * 60)
                        {
                                // Known node.  Update stuff.
                                memcpy((struct sockaddr*) &i_n->m_ss, a_sa, a_sa_len);
                                if (a_confirm)
                                {
                                        i_n->m_time = m_now.tv_sec;
                                }
                                if (a_confirm >= 2)
                                {
                                        i_n->m_reply_time = m_now.tv_sec;
                                        i_n->m_pinged = 0;
                                        i_n->m_pinged_time = 0;
                                }
                        }
                        if (a_confirm == 2)
                        {
                                add_search_node(a_id, a_sa, a_sa_len);
                        }
                        return i_n;
                }
                i_n = i_n->m_next;
        }
        // -------------------------------------------------
        // New node.
        // -------------------------------------------------
        if (l_my_bucket)
        {
                if (a_sa->sa_family == AF_INET)
                {
                        m_bucket_grow_time = m_now.tv_sec;
                }
                else
                {
                        m_bucket6_grow_time = m_now.tv_sec;
                }
        }
        // -------------------------------------------------
        // First, try to get rid of a known-bad node.
        // -------------------------------------------------
        i_n = i_b->m_nodes;
        while (i_n)
        {
                if (i_n->m_pinged >= 3 &&
                    i_n->m_pinged_time < m_now.tv_sec - 15)
                {
                        memcpy(i_n->m_id, a_id, 20);
                        memcpy((struct sockaddr*) &i_n->m_ss, a_sa, a_sa_len);
                        i_n->m_time = a_confirm ? m_now.tv_sec : 0;
                        i_n->m_reply_time = a_confirm >= 2 ? m_now.tv_sec : 0;
                        i_n->m_pinged_time = 0;
                        i_n->m_pinged = 0;
                        if (a_confirm == 2)
                        {
                                add_search_node(a_id, a_sa, a_sa_len);
                        }
                        return i_n;
                }
                i_n = i_n->m_next;
        }
        // -------------------------------------------------
        // if bucket full, ping a dubious node
        // -------------------------------------------------
        if (i_b->m_count >= i_b->m_max_count)
        {
                bool l_dubious = false;
                i_n = i_b->m_nodes;
                while (i_n)
                {
                        // ---------------------------------
                        // Pick first dubious node that was
                        // not pinged in last 15 seconds.
                        // Gives nodes time to reply, but
                        // tends to concentrate on same
                        // nodes, to get rid of bad nodes
                        // ASAP.
                        // ---------------------------------
                        if (!_node_good(i_n, m_now))
                        {
                                l_dubious = true;
                                if (i_n->m_pinged_time < m_now.tv_sec - 15)
                                {
                                        uint8_t tid[4];
                                        //TRC_DEBUG("Sending ping to dubious node.");
                                        _make_tid(tid, "pn", 0);
                                        send_ping((struct sockaddr*) &i_n->m_ss, i_n->m_sslen, tid, 4);
                                        i_n->m_pinged++;
                                        i_n->m_pinged_time = m_now.tv_sec;
                                        break;
                                }
                        }
                        i_n = i_n->m_next;
                }
                if (l_my_bucket &&
                    !l_dubious)
                {
                        // ---------------------------------
                        // keep splitting until no longer
                        // possible?
                        // ---------------------------------
                        int l_s;
                        l_s = split_bucket(i_b);
                        if (l_s == NTRNT_STATUS_OK)
                        {
                                goto again;
                        }
                        return NULL;
                }
                // -----------------------------------------
                // No space for this node.
                // Cache it away for later.
                // -----------------------------------------
                if (a_confirm || i_b->m_cached.ss_family == 0)
                {
                        memcpy(&i_b->m_cached, a_sa, a_sa_len);
                        i_b->m_cached_len = a_sa_len;
                }
                if (a_confirm == 2)
                {
                        add_search_node(a_id, a_sa, a_sa_len);
                }
                return NULL;
        }
        // -------------------------------------------------
        // Create a new node.
        // -------------------------------------------------
        i_n = (node_t*)calloc(1, sizeof(node_t));
        if (i_n == NULL)
        {
                return NULL;
        }
        memcpy(i_n->m_id, a_id, 20);
        memcpy(&i_n->m_ss, a_sa, a_sa_len);
        i_n->m_sslen = a_sa_len;
        i_n->m_time = a_confirm ? m_now.tv_sec : 0;
        i_n->m_reply_time = a_confirm >= 2 ? m_now.tv_sec : 0;
        i_n->m_next = i_b->m_nodes;
        i_b->m_nodes = i_n;
        ++i_b->m_count;
        if (a_confirm == 2)
        {
                add_search_node(a_id, a_sa, a_sa_len);
        }
        return i_n;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int dhsco::split_bucket(bucket_t* a_b)
{
        int l_s;
        node_t* l_nodes = NULL;
        node_t* i_n = NULL;
        TRC_DEBUG("Splitting.");
        l_s = split_bucket_helper(a_b, &l_nodes);
        if (l_s != NTRNT_STATUS_OK)
        {
                TRC_DEBUG("Couldn't split bucket");
                return NTRNT_STATUS_ERROR;
        }
        while (i_n != NULL ||
               l_nodes != NULL)
        {
                bucket_t* l_split = NULL;
                if (i_n == NULL)
                {
                        i_n = l_nodes;
                        l_nodes = l_nodes->m_next;
                        i_n->m_next = NULL;
                }
                // -----------------------------------------
                // Insert a new node into a bucket,
                // don't check for duplicates.
                // split bucket if necessary
                // -----------------------------------------
                bucket_t* l_buckets = m_buckets;
                if (i_n->m_ss.ss_family != AF_INET)
                {
                        l_buckets = m_buckets6;
                }
                bucket_t* i_b = _find_bucket(i_n->m_id, l_buckets);
                if (i_b == NULL)
                {
                        TRC_DEBUG("Couldn't insert node.");
                        free(i_n);
                        i_n = NULL;
                        return NTRNT_STATUS_OK;
                }
                if (i_b->m_count >= i_b->m_max_count)
                {
                        l_split = i_b;
                        if (!_in_bucket(m_myid, l_split))
                        {
                                free(i_n);
                                i_n = NULL;
                                return 1;
                        }
                        node_t* insert = NULL;
                        TRC_DEBUG("Splitting (recursive).");
                        l_s = split_bucket_helper(l_split, &insert);
                        if (l_s != NTRNT_STATUS_OK)
                        {
                                TRC_DEBUG("Couldn't split bucket.");
                                free(i_n);
                                i_n = NULL;
                                return NTRNT_STATUS_OK;
                        }
                        else
                        {
                                l_nodes = _append_nodes(l_nodes, insert);
                        }
                }
                else
                {
                        i_n->m_next = i_b->m_nodes;
                        i_b->m_nodes = i_n;
                        ++(i_b->m_count);
                        i_n = NULL;
                        return NTRNT_STATUS_OK;
                }
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Splits bucket, and returns list of nodes that must be reinserted
//!           into routing table.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t dhsco::split_bucket_helper(bucket_t* a_b, node_t** ao_nodes_return)
{
        // -------------------------------------------------
        // validate not in bucket
        // -------------------------------------------------
        if (!_in_bucket(m_myid, a_b))
        {
                TRC_DEBUG("Attempted to split wrong bucket.");
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // send cached ping ???
        // -------------------------------------------------
        send_cached_ping(a_b);
        // -------------------------------------------------
        // get new id
        // -------------------------------------------------
        uint8_t new_id[20];
        int l_s;
        l_s = _bucket_middle(a_b, new_id);
        if (l_s < 0)
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create new bucket
        // -------------------------------------------------
        bucket_t *l_new;
        l_new = (bucket_t*)calloc(1, sizeof(bucket_t));
        if (l_new == NULL)
        {
                return NTRNT_STATUS_ERROR;
        }
        l_new->m_af = a_b->m_af;
        memcpy(l_new->m_first, new_id, 20);
        l_new->m_time = a_b->m_time;
        // -------------------------------------------------
        // insert
        // -------------------------------------------------
        *ao_nodes_return = a_b->m_nodes;
        a_b->m_nodes = NULL;
        a_b->m_count = 0;
        l_new->m_next = a_b->m_next;
        a_b->m_next = l_new;
        // -------------------------------------------------
        // calc max counts
        // -------------------------------------------------
        if (_in_bucket(m_myid, a_b))
        {
                l_new->m_max_count = a_b->m_max_count;
                a_b->m_max_count = MAX(a_b->m_max_count / 2, 8);
        }
        else
        {
                l_new->m_max_count = MAX(a_b->m_max_count / 2, 8);
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int dhsco::send_announce_peer(const struct sockaddr* a_sa,
                              int a_sa_len,
                              uint8_t* a_tid,
                              int a_tid_len,
                              uint8_t* a_infohash,
                              uint16_t a_port,
                              uint8_t* a_token,
                              int a_token_len,
                              int a_confirm)
{
        char l_buf[512];
        int i = 0, l_s;
        l_s = snprintf(l_buf + i, 512 - i, "d1:ad2:id20:");
        INC(i, l_s, 512);
        COPY(l_buf, i, m_myid, 20, 512);
        l_s = snprintf(l_buf + i, 512 - i, "9:info_hash20:");
        INC(i, l_s, 512);
        COPY(l_buf, i, a_infohash, 20, 512);
        l_s = snprintf(l_buf + i, 512 - i, "4:porti%ue5:token%d:", (unsigned) a_port, a_token_len);
        INC(i, l_s, 512);
        COPY(l_buf, i, a_token, a_token_len, 512);
        l_s = snprintf(l_buf + i, 512 - i, "e1:q13:announce_peer1:t%d:", a_tid_len);
        INC(i, l_s, 512);
        COPY(l_buf, i, a_tid, a_tid_len, 512);
        ADD_V(l_buf, i, 512);
        l_s = snprintf(l_buf + i, 512 - i, "1:y1:qe");
        INC(i, l_s, 512);
        return send_buf(l_buf, i, a_confirm ? 0 : _DHSCO_MSG_CONFIRM, a_sa, a_sa_len);
fail:
        errno = ENOSPC;
        return NTRNT_STATUS_ERROR;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int dhsco::send_peer_announced(const struct sockaddr* a_sa,
                               int a_sa_len,
                               uint8_t* a_tid,
                               int a_tid_len)
{
        char l_buf[512];
        int i = 0, l_s;
        l_s = snprintf(l_buf + i, 512 - i, "d1:rd2:id20:");
        INC(i, l_s, 512);
        COPY(l_buf, i, m_myid, 20, 512);
        l_s = snprintf(l_buf + i, 512 - i, "e1:t%d:", a_tid_len);
        INC(i, l_s, 512);
        COPY(l_buf, i, a_tid, a_tid_len, 512);
        ADD_V(l_buf, i, 512);
        l_s = snprintf(l_buf + i, 512 - i, "1:y1:re");
        INC(i, l_s, 512);
        return send_buf(l_buf, i, 0, a_sa, a_sa_len);
fail:
        errno = ENOSPC;
        return NTRNT_STATUS_ERROR;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int dhsco::send_error(const struct sockaddr* a_sa,
                      int a_sa_len,
                      uint8_t* a_tid,
                      int a_tid_len,
                      int a_code,
                      const char *a_msg)
{
        char l_buf[512];
        int i = 0;
        int l_s;
        int l_msg_len;
        l_msg_len = strlen(a_msg);
        l_s = snprintf(l_buf + i, 512 - i, "d1:eli%de%d:", a_code, l_msg_len);
        INC(i, l_s, 512);
        COPY(l_buf, i, a_msg, l_msg_len, 512);
        l_s = snprintf(l_buf + i, 512 - i, "e1:t%d:", a_tid_len);
        INC(i, l_s, 512);
        COPY(l_buf, i, a_tid, a_tid_len, 512);
        ADD_V(l_buf, i, 512);
        l_s = snprintf(l_buf + i, 512 - i, "1:y1:ee");
        INC(i, l_s, 512);
        return send_buf(l_buf, i, 0, a_sa, a_sa_len);
fail:
        errno = ENOSPC;
        return NTRNT_STATUS_ERROR;
}
//! ----------------------------------------------------------------------------
//! \details: when search in progress, periodically call search_step to send
//!           further requests.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void dhsco::search_step(search_t* a_sr, dht_callback_t *a_cb, void* a_ctx)
{
        int i = 0;
        int j = 0;
        int all_done = 1;
        // -------------------------------------------------
        // Check if the first 8 live nodes have replied.
        // -------------------------------------------------
        for (i = 0; i < a_sr->m_num_nodes && j < 8; ++i)
        {
                search_node_t* i_sn = &a_sr->m_nodes[i];
                if (i_sn->m_pinged >= 3)
                {
                        continue;
                }
                if (!i_sn->m_replied)
                {
                        all_done = 0;
                        break;
                }
                ++j;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        if (all_done)
        {
                if (a_sr->m_port == 0)
                {
                        goto done;
                }
                else
                {
                        int all_acked = 1;
                        j = 0;
                        for (i = 0; i < a_sr->m_num_nodes && j < 8; ++i)
                        {
                                search_node_t* i_sn = &a_sr->m_nodes[i];
                                node_t* l_node;
                                uint8_t l_tid[4];
                                if (i_sn->m_pinged >= 3)
                                {
                                        continue;
                                }
                                // -------------------------
                                // A proposed extension to
                                // protocol consists in
                                // omitting token when
                                // storage tables are full.
                                // While don't think this
                                // makes a lot of sense
                                // -just sending positive
                                // reply is as good to deal
                                // -------------------------
                                if (i_sn->m_token_len == 0)
                                {
                                        i_sn->m_acked = 1;
                                }
                                if (!i_sn->m_acked)
                                {
                                        all_acked = 0;
                                        TRC_DEBUG("Sending announce_peer.");
                                        _make_tid(l_tid, "ap", a_sr->m_tid);
                                        send_announce_peer((struct sockaddr*) &i_sn->m_ss,
                                                           sizeof(struct sockaddr_storage),
                                                           l_tid,
                                                           4,
                                                           a_sr->m_id,
                                                           a_sr->m_port,
                                                           i_sn->m_token,
                                                           i_sn->m_token_len,
                                                           i_sn->m_reply_time >= m_now.tv_sec - 15);
                                        i_sn->m_pinged++;
                                        i_sn->m_request_time = m_now.tv_sec;
                                        bucket_t *l_buckets = m_buckets;
                                        if (i_sn->m_ss.ss_family != AF_INET)
                                        {
                                                l_buckets = m_buckets6;
                                        }
                                        l_node = _find_node(i_sn->m_id, l_buckets);
                                        if (l_node)
                                        {
                                                pinged(l_node, NULL);
                                        }
                                }
                                ++j;
                        }
                        if (all_acked)
                        {
                                goto done;
                        }
                }
                a_sr->m_step_time = m_now.tv_sec;
                return;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        if (a_sr->m_step_time + _DHSCO_SEARCH_RETRANSMIT >= m_now.tv_sec)
        {
                return;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        j = 0;
        for (i = 0; i < a_sr->m_num_nodes; ++i)
        {
                j += search_send_get_peers(a_sr, &a_sr->m_nodes[i]);
                if (j >= _DHSCO_INFLIGHT_QUERIES)
                {
                        break;
                }
        }
        a_sr->m_step_time = m_now.tv_sec;
        return;
done:
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        a_sr->m_done = 1;
        if (a_cb)
        {
                (*a_cb)(a_ctx,
                        a_sr->m_af == AF_INET ? DHT_EVENT_SEARCH_DONE : DHT_EVENT_SEARCH_DONE6,
                        a_sr->m_id,
                        NULL,
                        0);
        }
        a_sr->m_step_time = m_now.tv_sec;
}
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                                     A P I
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
dhsco::dhsco(int a_udp_fd, int a_udp6_fd, const uint8_t* a_id, const uint8_t* a_v):
        m_myid(),
        m_have_v(0),
        m_my_v(),
        m_dht_socket(a_udp_fd),
        m_dht_socket6(a_udp6_fd),
        m_buckets(nullptr),
        m_buckets6(nullptr),
        m_storage(nullptr),
        m_searches(nullptr),
        m_num_storage(0),
        m_num_searches(0),
        m_now(),
        m_bucket_grow_time(),
        m_bucket6_grow_time(),
        m_confirm_nodes_time(),
        m_token_bucket_time(),
        m_token_bucket_tokens(_DHSCO_MAX_TOKEN_BUCKET_TOKENS),
        m_search_id(),
        m_search_time(0),
        m_secret(),
        m_old_secret(),
        m_rotate_secrets_time(),
        m_expire_data_time(),
        m_blocklist(),
        m_bootstrap_nodes()
{
        // -------------------------------------------------
        // init buckets
        // -------------------------------------------------
        if (a_udp_fd >= 0)
        {
                m_buckets = (bucket_t*)calloc(1, sizeof(bucket_t));
                m_buckets->m_max_count = 128;
                m_buckets->m_af = AF_INET;
        }
        if (a_udp6_fd >= 0)
        {
                m_buckets6 = (bucket_t*)calloc(1, sizeof(bucket_t));
                m_buckets6->m_max_count = 128;
                m_buckets6->m_af = AF_INET6;
        }
        // -------------------------------------------------
        // init id
        // -------------------------------------------------
        memcpy(m_myid, a_id, 20);
        // -------------------------------------------------
        // v ???
        // -------------------------------------------------
        if (a_v)
        {
                memcpy(m_my_v, "1:v4:", 5);
                memcpy(m_my_v + 5, a_v, 4);
                m_have_v = true;
        }
        else
        {
                m_have_v = false;
        }
        // -------------------------------------------------
        // init times
        // -------------------------------------------------
        gettimeofday(&m_now, NULL);
        m_bucket_grow_time = m_now.tv_sec;
        m_bucket6_grow_time = m_now.tv_sec;
        m_confirm_nodes_time = m_now.tv_sec + random() % 3;
        m_token_bucket_time = m_now.tv_sec;
        // -------------------------------------------------
        // generate search id
        // -------------------------------------------------
        m_search_id = random() & 0xFFFF;
        // -------------------------------------------------
        // init secret
        // -------------------------------------------------
        memset(m_secret, 0, sizeof(m_secret));
        // -------------------------------------------------
        // rotate secret
        // -------------------------------------------------
        rotate_secrets();
        // -------------------------------------------------
        // expire buckets
        // -------------------------------------------------
        expire_buckets(m_buckets);
        expire_buckets(m_buckets6);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
dhsco::~dhsco(void)
{
        m_dht_socket = -1;
        m_dht_socket6 = -1;
        while (m_buckets)
        {
                bucket_t* i_b = m_buckets;
                m_buckets = i_b->m_next;
                while (i_b->m_nodes)
                {
                        node_t* n = i_b->m_nodes;
                        i_b->m_nodes = n->m_next;
                        free(n);
                }
                free(i_b);
        }
        while (m_buckets6)
        {
                bucket_t* i_b = m_buckets6;
                m_buckets6 = i_b->m_next;
                while (i_b->m_nodes)
                {
                        node_t* n = i_b->m_nodes;
                        i_b->m_nodes = n->m_next;
                        free(n);
                }
                free(i_b);
        }
        while (m_storage)
        {
                storage_t *st = m_storage;
                m_storage = m_storage->m_next;
                free(st->m_peers);
                free(st);
        }
        while (m_searches)
        {
                search_t* sr = m_searches;
                m_searches = m_searches->m_next;
                free(sr);
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int dhsco::ping_node(const struct sockaddr* a_sa, int a_sa_len)
{
        uint8_t tid[4];
        //TRC_DEBUG("Sending ping.");
        _make_tid(tid, "pn", 0);
        return send_ping(a_sa, a_sa_len, tid, 4);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t dhsco::periodic(const void* a_buf,
                        size_t a_buf_len,
                        const struct sockaddr* a_from,
                        int a_from_len,
                        time_t* a_to_sleep,
                        dht_callback_t* a_cb,
                        void* a_ctx)
{
        gettimeofday(&m_now, NULL);
        if (a_buf_len <= 0)
        {
                goto dont_read;
        }
        // -------------------------------------------------
        // *************************************************
        // sanitize input
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // test if local address ???
        // -------------------------------------------------
        if (_is_local(a_from))
        {
                goto dont_read;
        }
        // -------------------------------------------------
        // validate is not blocked
        // -------------------------------------------------
        if (node_blacklisted(a_from, a_from_len))
        {
                TRC_DEBUG("Received packet a_from blacklisted node.");
                goto dont_read;
        }
        // -------------------------------------------------
        // validate null terminated
        // -------------------------------------------------
        if (((char*) a_buf)[a_buf_len] != '\0')
        {
                TRC_DEBUG("Unterminated msg_type.");
                errno = EINVAL;
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // clear msg buffer
        // -------------------------------------------------
        int l_msg_type;
        parsed_message_t l_msg;
        memset(&l_msg, 0, sizeof(l_msg));
        // -------------------------------------------------
        // parse
        // -------------------------------------------------
        l_msg_type = _parse_message((const uint8_t*)a_buf, a_buf_len, &l_msg);
        if ((l_msg_type < 0) ||
            (l_msg_type == MSG_TYPE_ERROR) ||
            (_id_cmp(l_msg.m_id, s_zeroes) == 0))
        {
                //TRC_DEBUG("Unparseable l_msg_type: %.*s", (int)a_buf_len, (char*)a_buf);
                TRC_DEBUG("Unparseable msg: msg_type: %d", l_msg_type);
                goto dont_read;
        }
        // -------------------------------------------------
        // received from self?
        // -------------------------------------------------
        if (_id_cmp(l_msg.m_id, m_myid) == 0)
        {
                TRC_DEBUG("Received msg_type from self.");
                goto dont_read;
        }
        // -------------------------------------------------
        // rate limit?
        // -------------------------------------------------
        if ((l_msg_type > MSG_TYPE_REPLY) &&
            rate_limit())
        {
                TRC_DEBUG("Dropping request due to rate limiting.");
                goto dont_read;
        }
        // -------------------------------------------------
        // for msg type...
        // -------------------------------------------------
        switch (l_msg_type)
        {
        // -------------------------------------------------
        // MSG_TYPE_REPLY
        // -------------------------------------------------
        case MSG_TYPE_REPLY:
        {
                uint16_t l_ttid;
                // -----------------------------------------
                // block node if bad message
                // -----------------------------------------
                if (l_msg.m_tid_len != 4)
                {
                        TRC_WARN("Broken node truncates transaction ids: %.*s",
                                 (int)a_buf_len,
                                 (char*)a_buf);
                        // ---------------------------------
                        // this is bad, as it means will
                        // time-out all searches that go
                        // through this node. Kill it.
                        // ---------------------------------
                        blacklist_node(l_msg.m_id, a_from, a_from_len);
                        goto dont_read;
                }
                // -----------------------------------------
                // pong
                // -----------------------------------------
                if (_tid_match(l_msg.m_tid, "pn", NULL))
                {
                        //TRC_DEBUG("Pong!");
                        new_node(l_msg.m_id, a_from, a_from_len, 2);
                }
                // -----------------------------------------
                // ???
                // -----------------------------------------
                else if (_tid_match(l_msg.m_tid, "fn", NULL) ||
                         _tid_match(l_msg.m_tid, "gp", NULL))
                {
                        int l_gp = 0;
                        search_t* l_sr = NULL;
                        if (_tid_match(l_msg.m_tid, "gp", &l_ttid))
                        {
                                l_gp = 1;
                                l_sr = _find_search(l_ttid, a_from->sa_family, m_searches);
                        }
                        //TRC_DEBUG("Nodes found (%d+%d)%s!",
                        //          l_msg.m_nodes_len / 26,
                        //          l_msg.m_nodes6_len / 38,
                        //          l_gp ? " for get_peers" : "");
                        if (l_msg.m_nodes_len  % 26 != 0 ||
                            l_msg.m_nodes6_len % 38 != 0)
                        {
                                TRC_WARN("Unexpected length for node info!");
                                blacklist_node(l_msg.m_id, a_from, a_from_len);
                        }
                        else if (l_gp &&
                                 (l_sr == NULL))
                        {
                                TRC_WARN("Unknown search!");
                                new_node(l_msg.m_id, a_from, a_from_len, 1);
                        }
                        else
                        {
                                new_node(l_msg.m_id, a_from, a_from_len, 2);
                                // -------------------------
                                // ipv4
                                // -------------------------
                                for (int i = 0; i < l_msg.m_nodes_len / 26; ++i)
                                {
                                        uint8_t* ni = l_msg.m_nodes + i * 26;
                                        struct sockaddr_in sin;
                                        if (_id_cmp(ni, m_myid) == 0)
                                        {
                                                continue;
                                        }
                                        memset(&sin, 0, sizeof(sin));
                                        sin.sin_family = AF_INET;
                                        memcpy(&sin.sin_addr, ni + 20, 4);
                                        memcpy(&sin.sin_port, ni + 24, 2);
                                        new_node(ni, (struct sockaddr*) &sin, sizeof(sin), 0);
                                        if (l_sr &&
                                            (l_sr->m_af == AF_INET))
                                        {
                                                insert_search_node(ni, (struct sockaddr*) &sin, sizeof(sin), l_sr, 0, NULL, 0);
                                        }
                                }
                                // -------------------------
                                // ipv6
                                // -------------------------
                                for (int i = 0; i < l_msg.m_nodes6_len / 38; ++i)
                                {
                                        uint8_t* ni = l_msg.m_nodes6 + i * 38;
                                        struct sockaddr_in6 sin6;
                                        if (_id_cmp(ni, m_myid) == 0)
                                        {
                                                continue;
                                        }
                                        memset(&sin6, 0, sizeof(sin6));
                                        sin6.sin6_family = AF_INET6;
                                        memcpy(&sin6.sin6_addr, ni + 20, 16);
                                        memcpy(&sin6.sin6_port, ni + 36, 2);
                                        new_node(ni, (struct sockaddr*) &sin6, sizeof(sin6), 0);
                                        if (l_sr &&
                                            (l_sr->m_af == AF_INET6))
                                        {
                                                insert_search_node(ni, (struct sockaddr*) &sin6, sizeof(sin6), l_sr, 0, NULL, 0);
                                        }
                                }
                                // -------------------------
                                // received a reply, so
                                // number of requests in
                                // flight has decreased.
                                // Push another request.
                                // -------------------------
                                if (l_sr)
                                {
                                        search_send_get_peers(l_sr, NULL);
                                }
                        }
                        if (l_sr)
                        {
                                search_node_t* l_sn = nullptr;
                                l_sn = insert_search_node(l_msg.m_id,
                                                          a_from,
                                                          a_from_len,
                                                          l_sr,
                                                          1,
                                                          l_msg.m_token,
                                                          l_msg.m_token_len);
                                UNUSED(l_sn);
                                if ((l_msg.m_values_len > 0) ||
                                    (l_msg.m_values6_len > 0))
                                {
                                        //TRC_DEBUG("Got values (%d+%d)!",
                                        //          l_msg.m_values_len / 6,
                                        //          l_msg.m_values6_len / 18);
                                        if (a_cb)
                                        {
                                                if (l_msg.m_values_len > 0)
                                                {
                                                        (*a_cb)(a_ctx, DHT_EVENT_VALUES, l_sr->m_id, (void*) l_msg.m_values, l_msg.m_values_len);
                                                }
                                                if (l_msg.m_values6_len > 0)
                                                {
                                                        (*a_cb)(a_ctx, DHT_EVENT_VALUES6, l_sr->m_id, (void*) l_msg.m_values6, l_msg.m_values6_len);
                                                }
                                        }
                                }
                        }
                }
                // -----------------------------------------
                // reply to announce peer
                // -----------------------------------------
                else if (_tid_match(l_msg.m_tid, "ap", &l_ttid))
                {
                        search_t* l_sr;
                        //TRC_DEBUG("Got reply to announce_peer.");
                        l_sr = _find_search(l_ttid, a_from->sa_family, m_searches);
                        if (!l_sr)
                        {
                                TRC_WARN("Unknown search!");
                                new_node(l_msg.m_id, a_from, a_from_len, 1);
                        }
                        else
                        {
                                int i;
                                new_node(l_msg.m_id, a_from, a_from_len, 2);
                                for (i = 0; i < l_sr->m_num_nodes; ++i)
                                {
                                        if (_id_cmp(l_sr->m_nodes[i].m_id, l_msg.m_id) == 0)
                                        {
                                                l_sr->m_nodes[i].m_request_time = 0;
                                                l_sr->m_nodes[i].m_reply_time = m_now.tv_sec;
                                                l_sr->m_nodes[i].m_acked = 1;
                                                l_sr->m_nodes[i].m_pinged = 0;
                                                break;
                                        }
                                }
                                // See comment for gp above.
                                search_send_get_peers(l_sr, NULL);
                        }
                }
                // -----------------------------------------
                // unexpected
                // -----------------------------------------
                else
                {
                        TRC_WARN("Unexpected reply: %.*s", (int)a_buf_len, (char*)a_buf);
                }
                break;
        }
        // -------------------------------------------------
        // MSG_TYPE_PING
        // -------------------------------------------------
        case MSG_TYPE_PING:
        {
                //TRC_DEBUG("Ping (%d)!", l_msg.m_tid_len);
                new_node(l_msg.m_id, a_from, a_from_len, 1);
                //TRC_DEBUG("Sending pong.");
                send_pong(a_from, a_from_len, l_msg.m_tid, l_msg.m_tid_len);
                break;
        }
        // -------------------------------------------------
        // MSG_TYPE_FIND_NODE
        // -------------------------------------------------
        case MSG_TYPE_FIND_NODE:
        {
                //TRC_DEBUG("Find node!");
                new_node(l_msg.m_id, a_from, a_from_len, 1);
                //TRC_DEBUG("Sending closest nodes (%d).", l_msg.m_want);
                send_closest_nodes(a_from,
                                   a_from_len,
                                   l_msg.m_tid,
                                   l_msg.m_tid_len,
                                   l_msg.m_target,
                                   l_msg.m_want,
                                   0,
                                   NULL,
                                   NULL,
                                   0);
                break;
        }
        // -------------------------------------------------
        // MSG_TYPE_GET_PEERS
        // -------------------------------------------------
        case MSG_TYPE_GET_PEERS:
        {
                //TRC_DEBUG("Get_peers!");
                new_node(l_msg.m_id, a_from, a_from_len, 1);
                // -----------------------------------------
                // check for info hash
                // -----------------------------------------
                if (_id_cmp(l_msg.m_info_hash, s_zeroes) == 0)
                {
                        //TRC_DEBUG("Error Got get_peers with no info_hash.");
                        send_error(a_from,
                                   a_from_len,
                                   l_msg.m_tid,
                                   l_msg.m_tid_len,
                                   203,
                                   "Get_peers with no info_hash");
                        break;
                }
                storage_t *l_st = _find_storage(l_msg.m_info_hash, m_storage);
                uint8_t l_token[_DHSCO_TOKEN_SIZE];
                _make_token(a_from, m_secret, l_token);
                storage_t *l_storage = nullptr;
                int l_family = 0;
                if (l_st &&
                    l_st->m_num_peers > 0)
                {
                        //TRC_DEBUG("Sending found%s peers.", a_from->sa_family == AF_INET6 ? " IPv6" : "");
                        l_storage = l_st;
                        l_family = a_from->sa_family;
                }
                send_closest_nodes(a_from,
                                   a_from_len,
                                   l_msg.m_tid,
                                   l_msg.m_tid_len,
                                   l_msg.m_info_hash,
                                   l_msg.m_want,
                                   l_family,
                                   l_storage,
                                   l_token,
                                   _DHSCO_TOKEN_SIZE);
                break;
        }
        // -------------------------------------------------
        // MSG_TYPE_ANNOUNCE_PEER
        // -------------------------------------------------
        case MSG_TYPE_ANNOUNCE_PEER:
        {
                //TRC_DEBUG("Announce peer!");
                new_node(l_msg.m_id, a_from, a_from_len, 1);
                if (_id_cmp(l_msg.m_info_hash, s_zeroes) == 0)
                {
                        TRC_WARN("Announce_peer with no info_hash.");
                        send_error(a_from, a_from_len, l_msg.m_tid, l_msg.m_tid_len, 203, "Announce_peer with no info_hash");
                        break;
                }
                if (!_token_match(l_msg.m_token, l_msg.m_token_len, a_from, m_secret))
                {
                        TRC_WARN("Incorrect token for announce_peer.");
                        send_error(a_from, a_from_len, l_msg.m_tid, l_msg.m_tid_len, 203, "Announce_peer with wrong token");
                        break;
                }
                if (l_msg.m_implied_port != 0)
                {
                        // Do this even if port > 0 -as per specification.
                        switch (a_from->sa_family)
                        {
                        case AF_INET:
                        {
                                l_msg.m_port = htons(((struct sockaddr_in*) a_from)->sin_port);
                                break;
                        }
                        case AF_INET6:
                        {
                                l_msg.m_port = htons(((struct sockaddr_in6*) a_from)->sin6_port);
                                break;
                        }
                        }
                }
                if (l_msg.m_port == 0)
                {
                        TRC_WARN("Announce_peer with forbidden port %d.", l_msg.m_port);
                        int l_s;
                        l_s = send_error(a_from, a_from_len, l_msg.m_tid, l_msg.m_tid_len, 203, "Announce_peer with forbidden port number");
                        UNUSED(l_s);
                        break;
                }
                int l_s;
                l_s = store(l_msg.m_info_hash, a_from, l_msg.m_port);
                UNUSED(l_s);
                // -----------------------------------------
                // Note that if storage_store failed,
                // lie to the requestor.
                // To prevent them from backtracking, and
                // hence polluting the DHT.
                // -----------------------------------------
                //TRC_DEBUG("Sending peer announced.");
                l_s = send_peer_announced(a_from, a_from_len, l_msg.m_tid, l_msg.m_tid_len);
                UNUSED(l_s);
                break;
        }
        }
dont_read:
        // -------------------------------------------------
        // rotate secrets
        // -------------------------------------------------
        if (m_now.tv_sec >= m_rotate_secrets_time)
        {
                rotate_secrets();
        }
        // -------------------------------------------------
        // expire data
        // -------------------------------------------------
        if (m_now.tv_sec >= m_expire_data_time)
        {
                expire_buckets(m_buckets);
                expire_buckets(m_buckets6);
                expire_storage();
                expire_searches(a_cb, a_ctx);
        }
        // -------------------------------------------------
        // search step
        // -------------------------------------------------
        if ((m_search_time > 0) &&
            (m_now.tv_sec >= m_search_time))
        {
                search_t*l_sr;
                l_sr = m_searches;
                while (l_sr)
                {
                        if (!l_sr->m_done && l_sr->m_step_time + _DHSCO_SEARCH_RETRANSMIT / 2 + 1 <= m_now.tv_sec)
                        {
                                search_step(l_sr, a_cb, a_ctx);
                        }
                        l_sr = l_sr->m_next;
                }
                m_search_time = 0;
                l_sr = m_searches;
                while (l_sr)
                {
                        if (!l_sr->m_done)
                        {
                                time_t l_tm;
                                l_tm = l_sr->m_step_time +
                                     _DHSCO_SEARCH_RETRANSMIT +
                                     random() % _DHSCO_SEARCH_RETRANSMIT;
                                if (m_search_time == 0 ||
                                    m_search_time > l_tm)
                                {
                                        m_search_time = l_tm;
                                }
                        }
                        l_sr = l_sr->m_next;
                }
        }
        // -------------------------------------------------
        // perform maintenance
        // -------------------------------------------------
        if (m_now.tv_sec >= m_confirm_nodes_time)
        {
                int l_soon = 0;
                l_soon |= upkeep_buckets(AF_INET);
                l_soon |= upkeep_buckets(AF_INET6);
                if (!l_soon)
                {
                        if (m_bucket_grow_time >= m_now.tv_sec - 150)
                        {
                                l_soon |= upkeep_neighborhood(AF_INET);
                        }
                        if (m_bucket6_grow_time >= m_now.tv_sec - 150)
                        {
                                l_soon |= upkeep_neighborhood(AF_INET6);
                        }
                }
                // -----------------------------------------
                // Given the timeouts in upkeep_buckets,
                // with a 22-bucket table, worst case is
                // ping every 18 seconds
                // (22 m_buckets plus 11 m_buckets overhead
                // for the larger m_buckets).
                // Keep the "soon" case within 15 seconds,
                // giving some margin for neighbourhood
                // maintenance.
                // -----------------------------------------
                if (l_soon)
                {
                        m_confirm_nodes_time = m_now.tv_sec + 5 + random() % 10;
                }
                else
                {
                        m_confirm_nodes_time = m_now.tv_sec + 60 + random() % 120;
                }
        }
        // -------------------------------------------------
        // calculate time to sleep till
        // -------------------------------------------------
        if (m_confirm_nodes_time > m_now.tv_sec)
        {
                *a_to_sleep = m_confirm_nodes_time - m_now.tv_sec;
        }
        else
        {
                *a_to_sleep = 0;
        }
        if (m_search_time > 0)
        {
                if (m_search_time <= m_now.tv_sec)
                {
                        *a_to_sleep = 0;
                }
                else if (*a_to_sleep > m_search_time - m_now.tv_sec)
                {
                        *a_to_sleep = m_search_time - m_now.tv_sec;
                }
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Start a search.
//!           If port is non-zero, perform an announce when search is complete.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int dhsco::search(const uint8_t *a_id,
                  int a_port,
                  int a_af,
                  dht_callback_t *a_cb,
                  void* a_ctx)
{
        bucket_t* l_buckets = m_buckets;
        int l_sr_duplicate;
        if (a_af != AF_INET)
        {
                l_buckets = m_buckets6;
        }
        bucket_t* i_b = _find_bucket(a_id, l_buckets);
        if (i_b == NULL)
        {
                errno = EAFNOSUPPORT;
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Try to answer search locally.
        // In a fully grown DHT this is very unlikely, but
        // people are running modified versions of
        // this code in private DHTs with very few nodes.
        // What's wrong with flooding?
        // -------------------------------------------------
        storage_t* l_st = nullptr;
        l_st = _find_storage(a_id, m_storage);
        if (l_st &&
            a_cb)
        {
                uint16_t l_swapped;
                uint8_t l_buf[18];
                int i;
                //TRC_DEBUG("Found local data (%d peers).", l_st->m_num_peers);
                for (i = 0; i < l_st->m_num_peers; ++i)
                {
                        l_swapped = htons(l_st->m_peers[i].m_port);
                        if (l_st->m_peers[i].m_len == 4)
                        {
                                memcpy(l_buf, l_st->m_peers[i].m_ip, 4);
                                memcpy(l_buf + 4, &l_swapped, 2);
                                (*a_cb)(a_ctx, DHT_EVENT_VALUES, a_id, (void*)l_buf, 6);
                        }
                        else if (l_st->m_peers[i].m_len == 16)
                        {
                                memcpy(l_buf, l_st->m_peers[i].m_ip, 16);
                                memcpy(l_buf + 16, &l_swapped, 2);
                                (*a_cb)(a_ctx, DHT_EVENT_VALUES6, a_id, (void*)l_buf, 18);
                        }
                }
        }
        // -------------------------------------------------
        // search for id
        // -------------------------------------------------
        search_t* l_sr = m_searches;
        while (l_sr)
        {
                if ((l_sr->m_af == a_af) &&
                    (_id_cmp(l_sr->m_id, a_id) == 0))
                {
                        break;
                }
                l_sr = l_sr->m_next;
        }
        l_sr_duplicate = l_sr && !l_sr->m_done;
        // -------------------------------------------------
        // if found
        // -------------------------------------------------
        if (l_sr)
        {
                // -----------------------------------------
                // it's reusing data from an old search.
                // Reusing the same tid means that can merge
                // replies for both searches.
                // -----------------------------------------
                int i;
                l_sr->m_done = 0;
again:
                for (i = 0; i < l_sr->m_num_nodes; ++i)
                {
                        search_node_t* n;
                        n = &l_sr->m_nodes[i];
                        // Discard any doubtful nodes.
                        if ((n->m_pinged >= 3) ||
                            (n->m_reply_time < m_now.tv_sec - 7200))
                        {
                                _flush_search_node(n, l_sr);
                                goto again;
                        }
                        n->m_pinged = 0;
                        n->m_token_len = 0;
                        n->m_replied = 0;
                        n->m_acked = 0;
                }
        }
        // -------------------------------------------------
        // else create new search
        // -------------------------------------------------
        else
        {
                l_sr = _new_search(&m_searches, m_num_searches, m_now);
                if (l_sr == NULL)
                {
                        errno = ENOSPC;
                        return NTRNT_STATUS_ERROR;
                }
                l_sr->m_af = a_af;
                l_sr->m_tid = m_search_id++;
                l_sr->m_step_time = 0;
                memcpy(l_sr->m_id, a_id, 20);
                l_sr->m_done = 0;
                l_sr->m_num_nodes = 0;
        }
        l_sr->m_port = a_port;
        // -------------------------------------------------
        // insert into bucket
        // -------------------------------------------------
        insert_search_bucket(i_b, l_sr);
        if (l_sr->m_num_nodes < _DHSCO_SEARCH_NODES)
        {
                bucket_t* p = _previous_bucket(i_b, l_buckets);
                if (i_b->m_next)
                {
                        insert_search_bucket(i_b->m_next, l_sr);
                }
                if (p)
                {
                        insert_search_bucket(p, l_sr);
                }
        }
        if (l_sr->m_num_nodes < _DHSCO_SEARCH_NODES)
        {
                insert_search_bucket(_find_bucket(m_myid, l_buckets), l_sr);
        }
        // -------------------------------------------------
        // search step
        // -------------------------------------------------
        search_step(l_sr, a_cb, a_ctx);
        m_search_time = m_now.tv_sec;
        // -------------------------------------------------
        // done -return if was dupe
        // -------------------------------------------------
        if (l_sr_duplicate)
        {
                return 0;
        }
        else
        {
                return 1;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int dhsco::status(int a_family,
                  int* a_good,
                  int* a_dubious,
                  int* a_cached,
                  int* a_incoming)
{
        int l_good = 0;
        int l_dubious = 0;
        int l_cached = 0;
        int l_incoming = 0;
        bucket_t* b = a_family == AF_INET ? m_buckets : m_buckets6;
        while (b)
        {
                node_t* n = b->m_nodes;
                while (n)
                {
                        if (_node_good(n, m_now))
                        {
                                ++l_good;
                                if (n->m_time > n->m_reply_time)
                                {
                                        ++l_incoming;
                                }
                        }
                        else
                        {
                                ++l_dubious;
                        }
                        n = n->m_next;
                }
                if (b->m_cached.ss_family > 0)
                {
                        ++l_cached;
                }
                b = b->m_next;
        }
        if (a_good) { *a_good = l_good; }
        if (a_dubious) { *a_dubious = l_dubious; }
        if (a_cached) { *a_cached = l_cached; }
        if (a_incoming) { *a_incoming = l_incoming; }
        return l_good + l_dubious;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
size_t dhsco::bootstrap_size(void)
{
        return m_bootstrap_nodes.size();
}
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                            D I S P L A Y
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: calc how many bits two ids have in common.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int _common_bits(const uint8_t* a_id1, const uint8_t* a_id2)
{
        int i;
        for (i = 0; i < 20; ++i)
        {
                if (a_id1[i] != a_id2[i])
                {
                        break;
                }
        }
        if (i == 20)
        {
                return 160;
        }
        uint8_t l_xor;
        l_xor = a_id1[i] ^ a_id2[i];
        int j = 0;
        while ((l_xor & 0x80) == 0)
        {
                l_xor <<= 1;
                ++j;
        }
        return 8 * i + j;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static void _display_hex(const uint8_t* a_buf, uint32_t a_buf_len)
{
        for(uint32_t i_c = 0; i_c <= a_buf_len; ++i_c)
        {
                NDBG_OUTPUT("%02x", a_buf[i_c]);
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static void _display_buckets(bucket_t& a_b,
                             const uint8_t* a_myid,
                             struct timeval& a_now)
{
        node_t* i_n = a_b.m_nodes;
        NDBG_OUTPUT("Bucket ");
        // shorten display output 20 -> 4
        _display_hex(a_b.m_first, 20);
        NDBG_OUTPUT(" count %d/%d age %d%s%s:\n",
                    a_b.m_count,
                    a_b.m_max_count,
                    (int) (a_now.tv_sec - a_b.m_time),
                    _in_bucket(a_myid, &a_b) ? " (mine)" : "",
                    a_b.m_cached.ss_family ? " (cached)" : "");
        // -------------------------------------------------
        // for each node in bucket
        // -------------------------------------------------
        while (i_n)
        {
                char l_buf[512];
                uint16_t l_port = 0;
                NDBG_OUTPUT("    Node ");
                // shorten display output 20 -> 4
                _display_hex(i_n->m_id, 4);
                if (i_n->m_ss.ss_family == AF_INET)
                {
                        struct sockaddr_in* sin = (struct sockaddr_in*) &i_n->m_ss;
                        inet_ntop(AF_INET, &sin->sin_addr, l_buf, 512);
                        l_port = ntohs(sin->sin_port);
                }
                else if (i_n->m_ss.ss_family == AF_INET6)
                {
                        struct sockaddr_in6* sin6 = (struct sockaddr_in6*) &i_n->m_ss;
                        inet_ntop(AF_INET6, &sin6->sin6_addr, l_buf, 512);
                        l_port = ntohs(sin6->sin6_port);
                }
                else
                {
                        snprintf(l_buf, 512, "unknown(%d)", i_n->m_ss.ss_family);
                        l_port = 0;
                }
                if (i_n->m_ss.ss_family == AF_INET6)
                {
                        NDBG_OUTPUT(" [%s%40s%s]:%s%6u%s ",
                                    ANSI_COLOR_FG_YELLOW, l_buf, ANSI_COLOR_OFF,
                                    ANSI_COLOR_FG_CYAN, l_port, ANSI_COLOR_OFF);
                }
                else
                {
                        NDBG_OUTPUT(" %s%42s%s:%s%6u%s ",
                                    ANSI_COLOR_FG_YELLOW, l_buf, ANSI_COLOR_OFF,
                                    ANSI_COLOR_FG_CYAN, l_port, ANSI_COLOR_OFF);
                }
                if (i_n->m_time != i_n->m_reply_time)
                {
                        NDBG_OUTPUT("age %12ld, %12ld",
                                    (long) (a_now.tv_sec - i_n->m_time),
                                    (long) (a_now.tv_sec - i_n->m_reply_time));
                }
                else
                {
                        NDBG_OUTPUT("age %12ld, ____________", (long) (a_now.tv_sec - i_n->m_time));
                }
                NDBG_OUTPUT(" (%6d)", i_n->m_pinged);
                if (_node_good(i_n, a_now))
                {
                        NDBG_OUTPUT(" (%sgood%s)", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF);
                }
                else
                {
                        NDBG_OUTPUT(" (%sbad%s )", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
                }
                NDBG_OUTPUT("\n");
                i_n = i_n->m_next;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t dhsco::bootstrap_dq(void)
{
        if (m_bootstrap_nodes.empty())
        {
                return NTRNT_STATUS_OK;
        }
        // -------------------------------------------------
        // pop from q
        // -------------------------------------------------
        sas_t l_sas = m_bootstrap_nodes.front();
        m_bootstrap_nodes.pop();
        // -------------------------------------------------
        // ping node
        // -------------------------------------------------
        if (l_sas.ss_family == AF_INET)
        {
                return ping_node((const sockaddr*)&l_sas, sizeof(sockaddr_in));
        }
        else if (l_sas.ss_family == AF_INET6)
        {
                return ping_node((const sockaddr*)&l_sas, sizeof(sockaddr_in6));
        }
        return NTRNT_STATUS_ERROR;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void dhsco::display(void)
{
        // -------------------------------------------------
        // id
        // -------------------------------------------------
        NDBG_OUTPUT("myid: ");
        _display_hex(m_myid, 20);
        NDBG_OUTPUT("\n");
        // -------------------------------------------------
        // buckets
        // -------------------------------------------------
        bucket_t* i_b;
        // -------------------------------------------------
        // ipv4
        // -------------------------------------------------
        i_b = m_buckets;
        while (i_b)
        {
                _display_buckets(*i_b, m_myid, m_now);
                i_b = i_b->m_next;
        }
        NDBG_OUTPUT("\n");
        // -------------------------------------------------
        // ipv6
        // -------------------------------------------------
        i_b = m_buckets6;
        while (i_b)
        {
                _display_buckets(*i_b, m_myid, m_now);
                i_b = i_b->m_next;
        }
        NDBG_OUTPUT("\n");
        // -------------------------------------------------
        // searches
        // -------------------------------------------------
        search_t* i_sr = m_searches;
        while (i_sr)
        {
                NDBG_OUTPUT("Search%s id ", i_sr->m_af == AF_INET6 ? " (IPv6)" : "");
                // shorten display output 20 -> 4
                _display_hex(i_sr->m_id, 4);
                NDBG_OUTPUT(" age %d%s\n",
                            (int) (m_now.tv_sec - i_sr->m_step_time),
                            i_sr->m_done ? " (done)" : "");
                for (int i = 0; i < i_sr->m_num_nodes; ++i)
                {
                        search_node_t* i_n = &i_sr->m_nodes[i];
                        NDBG_OUTPUT("Node %d id ", i);
                        // shorten display output 20 -> 4
                        _display_hex(i_n->m_id, 4);
                        NDBG_OUTPUT(" bits %d age ", _common_bits(i_sr->m_id, i_n->m_id));
                        if (i_n->m_request_time)
                        {
                                NDBG_OUTPUT("%d, ", (int) (m_now.tv_sec - i_n->m_request_time));
                        }
                        NDBG_OUTPUT("%d", (int) (m_now.tv_sec - i_n->m_reply_time));
                        if (i_n->m_pinged)
                        {
                                NDBG_OUTPUT(" (%d)", i_n->m_pinged);
                        }
                        bucket_t* l_buckets = m_buckets;
                        if (i_sr->m_af != AF_INET)
                        {
                                l_buckets = m_buckets6;
                        }
                        NDBG_OUTPUT("%s%s.\n",
                                    _find_node(i_n->m_id, l_buckets) ? " (known)" : "",
                                    i_n->m_replied ? " (replied)" : "");
                }
                i_sr = i_sr->m_next;
        }
        NDBG_OUTPUT("\n");
        // -------------------------------------------------
        // storage
        // -------------------------------------------------
        storage_t* i_st = m_storage;
        while (i_st)
        {
                NDBG_OUTPUT("Storage ");
                // shorten display output 20 -> 4
                _display_hex(i_st->m_id, 4);
                NDBG_OUTPUT(" %d/%d nodes:", i_st->m_num_peers, i_st->m_max_peers);
                for (int i = 0; i < i_st->m_num_peers; ++i)
                {
                        char l_buf[100];
                        if (i_st->m_peers[i].m_len == 4)
                        {
                                inet_ntop(AF_INET, i_st->m_peers[i].m_ip, l_buf, 100);
                        }
                        else if (i_st->m_peers[i].m_len == 16)
                        {
                                l_buf[0] = '[';
                                inet_ntop(AF_INET6, i_st->m_peers[i].m_ip, l_buf + 1, 98);
                                strcat(l_buf, "]");
                        }
                        else
                        {
                                strcpy(l_buf, "???");
                        }
                        NDBG_OUTPUT(" %40s:%u (%ld)",
                                    l_buf,
                                    i_st->m_peers[i].m_port,
                                    (long) (m_now.tv_sec - i_st->m_peers[i].m_time));
                }
                i_st = i_st->m_next;
        }
        NDBG_OUTPUT("\n");
}
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                               S T A T E
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t dhsco::load(const std::string& a_file)
{
        // -------------------------------------------------
        // read
        // -------------------------------------------------
        char* l_buf = nullptr;
        size_t l_buf_len = 0;
        int32_t l_s;
        l_s = read_file(a_file.c_str(), &l_buf, &l_buf_len);
        if (l_s != NTRNT_STATUS_OK)
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Parse
        // NOTE: rapidjson assert's on errors -interestingly
        // -------------------------------------------------
        rapidjson::Document l_doc;
        l_doc.Parse(l_buf,l_buf_len);
#define CHECK_OBJ(_d) do { \
        if(!_d.IsObject())\
        {\
                TRC_ERROR("Json data not object: type: %d\n", _d.GetType());\
                return NTRNT_STATUS_ERROR;\
        } } while(0)
#define CHECK_ARR(_d) do { \
        if(!_d.IsArray())\
        {\
                TRC_ERROR("Json data not array: type: %d\n", _d.GetType());\
                return NTRNT_STATUS_ERROR;\
        } } while(0)
#define CHECK_STR(_d) do { \
        if(!_d.IsString())\
        {\
                TRC_ERROR("Json data not string: type: %d\n", _d.GetType());\
                return NTRNT_STATUS_ERROR;\
        } } while(0)
#define IF_MEM(_m, _str) else if((strncmp(_m->name.GetString(), _str, _m->name.GetStringLength())) == 0)
        CHECK_OBJ(l_doc);
        // -------------------------------------------------
        // Iterate over objects...
        // -------------------------------------------------
        for (rapidjson::Value::ConstMemberIterator i_m = l_doc.MemberBegin();
             i_m != l_doc.MemberEnd();
             ++i_m)
        {
                if(0){}
                // -----------------------------------------
                // id
                // -----------------------------------------
                IF_MEM(i_m, "id")
                {
                        if(!i_m->value.IsString())
                        {
                                if (l_buf) { free(l_buf); l_buf = nullptr; }
                                return NTRNT_STATUS_ERROR;
                        }
                        std::string l_hex_id;
                        size_t l_bin_len;
                        l_hex_id = i_m->value.GetString();
                        hex2bin(m_myid, l_bin_len, l_hex_id.c_str(), l_hex_id.length());
                }
                // -----------------------------------------
                // nodes
                // -----------------------------------------
                IF_MEM(i_m, "nodes")
                {
                        if(!i_m->value.IsArray())
                        {
                                if (l_buf) { free(l_buf); l_buf = nullptr; }
                                return NTRNT_STATUS_ERROR;
                        }
                        for(rapidjson::SizeType i_r = 0; i_r < i_m->value.Size(); ++i_r)
                        {
                                if (!i_m->value[i_r].IsString())
                                {
                                        if (l_buf) { free(l_buf); l_buf = nullptr; }
                                        return NTRNT_STATUS_ERROR;
                                }
                                std::string l_val = i_m->value[i_r].GetString();
                                sas_t l_sas;
                                l_s = str_to_sas(l_val, l_sas);
                                if (l_s != NTRNT_STATUS_OK)
                                {
                                        if (l_buf) { free(l_buf); l_buf = nullptr; }
                                        return NTRNT_STATUS_ERROR;
                                }
                                m_bootstrap_nodes.push(l_sas);
                        }
                }
                // -----------------------------------------
                // nodes6
                // -----------------------------------------
                IF_MEM(i_m, "nodes6")
                {
                        if(!i_m->value.IsArray())
                        {
                                if (l_buf) { free(l_buf); l_buf = nullptr; }
                                return NTRNT_STATUS_ERROR;
                        }
                        for(rapidjson::SizeType i_r = 0; i_r < i_m->value.Size(); ++i_r)
                        {
                                if (!i_m->value[i_r].IsString())
                                {
                                        if (l_buf) { free(l_buf); l_buf = nullptr; }
                                        return NTRNT_STATUS_ERROR;
                                }
                                std::string l_val = i_m->value[i_r].GetString();
                                sas_t l_sas;
                                l_s = str_to_sas(l_val, l_sas);
                                if (l_s != NTRNT_STATUS_OK)
                                {
                                        if (l_buf) { free(l_buf); l_buf = nullptr; }
                                        return NTRNT_STATUS_ERROR;
                                }
                                m_bootstrap_nodes.push(l_sas);
                        }
                }
        }
        if (l_buf) { free(l_buf); l_buf = nullptr; }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t dhsco::save(const std::string& a_file)
{
        // -------------------------------------------------
        // create writer
        // -------------------------------------------------
        rapidjson::StringBuffer l_str_buf;
        rapidjson::Writer<rapidjson::StringBuffer> l_writer(l_str_buf);
        l_writer.StartObject();
        // -------------------------------------------------
        // id
        // -------------------------------------------------
        int32_t l_s;
        std::string l_id;
        l_s = bin2hex_str(l_id, m_myid, 20);
        if (l_s != NTRNT_STATUS_OK)
        {
                return NTRNT_STATUS_ERROR;
        }
        l_writer.Key("id");
        l_writer.String(l_id.c_str());
        // -------------------------------------------------
        // buckets
        // -------------------------------------------------
        bucket_t* i_b = nullptr;
        node_t* i_n = nullptr;
        // -------------------------------------------------
        // ipv4/"nodes"
        // -------------------------------------------------
        l_writer.Key("nodes");
        l_writer.StartArray();
        // -------------------------------------------------
        // for restoring to work w/o discarding too many
        // nodes, list must start w/ contents of "my" bucket
        // -------------------------------------------------
        i_b = _find_bucket(m_myid, m_buckets);
        if (i_b == NULL)
        {
                goto gather_ipv6;
        }
        i_n = i_b->m_nodes;
        while (i_n)
        {
                if (_node_good(i_n, m_now))
                {
                        l_writer.String(sas_to_str(i_n->m_ss).c_str());
                }
                i_n = i_n->m_next;
        }
        i_b = m_buckets;
        while (i_b)
        {
                if (!_in_bucket(m_myid, i_b))
                {
                        i_n = i_b->m_nodes;
                        while (i_n)
                        {
                                if (_node_good(i_n, m_now))
                                {
                                        l_writer.String(sas_to_str(i_n->m_ss).c_str());
                                }
                                i_n = i_n->m_next;
                        }
                }
                i_b = i_b->m_next;
        }
gather_ipv6:
        l_writer.EndArray();
        // -------------------------------------------------
        // ipv6/"nodes6"
        // -------------------------------------------------
        l_writer.Key("nodes6");
        l_writer.StartArray();
        // -------------------------------------------------
        // for restoring to work w/o discarding too many
        // nodes, list must start w/ contents of "my" bucket
        // -------------------------------------------------
        i_b = _find_bucket(m_myid, m_buckets6);
        if (i_b == NULL)
        {
                goto done;
        }
        i_n = i_b->m_nodes;
        while (i_n)
        {
                if (_node_good(i_n, m_now))
                {
                        l_writer.String(sas_to_str(i_n->m_ss).c_str());
                }
                i_n = i_n->m_next;
        }
        i_b = m_buckets6;
        while (i_b)
        {
                if (!_in_bucket(m_myid, i_b))
                {
                        i_n = i_b->m_nodes;
                        while (i_n)
                        {
                                if (_node_good(i_n, m_now))
                                {
                                        l_writer.String(sas_to_str(i_n->m_ss).c_str());
                                }
                                i_n = i_n->m_next;
                        }
                }
                i_b = i_b->m_next;
        }
done:
        l_writer.EndArray();
        // -------------------------------------------------
        // finish
        // -------------------------------------------------
        l_writer.EndObject();
        // -------------------------------------------------
        // write to file
        // -------------------------------------------------
        l_s = write_file(a_file.c_str(), l_str_buf.GetString(), l_str_buf.GetSize());
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
#if 0
int dhsco::insert_node(const uint8_t* id, struct sockaddr* a_sa, int a_sa_len)
{
        node_t* l_n;
        if ((a_sa->sa_family != AF_INET) &&
            (a_sa->sa_family != AF_INET6))
        {
                errno = EAFNOSUPPORT;
                return NTRNT_STATUS_ERROR;
        }
        l_n = new_node(id, a_sa, a_sa_len, 0);
        return !!l_n;
}
#endif
}
