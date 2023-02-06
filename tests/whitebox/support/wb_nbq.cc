//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "ntrnt/def.h"
#include "support/nbq.h"
#include "support/ndebug.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define BLOCK_SIZE 256
//! ----------------------------------------------------------------------------
//! test helpers
//! ----------------------------------------------------------------------------
#define TO_HEX(i) (i <= 9 ? '0' + i : 'A' - 10 + i)
char *create_uniform_buf(uint32_t a_size)
{
        char *l_buf = (char *)malloc(a_size);
        for(uint32_t i_c = 0; i_c < a_size; ++i_c)
        {
                l_buf[i_c] = TO_HEX(i_c % 16);
        }
        return l_buf;
}
//! ----------------------------------------------------------------------------
//! test helpers
//! ----------------------------------------------------------------------------
char *create_buf(uint32_t a_size)
{
        char *l_buf = (char *)malloc(a_size);
        for(uint32_t i_c = 0; i_c < a_size; ++i_c)
        {
                l_buf[i_c] = (char)(0xFF&i_c);
        }
        return l_buf;
}
//! ----------------------------------------------------------------------------
//! test helpers
//! ----------------------------------------------------------------------------
void nbq_write(ns_ntrnt::nbq &a_nbq, char *a_buf, uint32_t a_write_size, uint32_t a_write_per)
{
        uint64_t l_write_size = a_write_size;
        uint64_t l_left = l_write_size;
        uint64_t l_written = 0;
        while(l_left)
        {
                int32_t l_s = 0;
                uint32_t l_write_size = ((a_write_per) > l_left)?l_left:(a_write_per);
                l_s = a_nbq.write(a_buf+l_written, l_write_size);
                if(l_s > 0)
                {
                        l_written += l_s;
                        l_left -= l_s;
                }
        }
}
//! ----------------------------------------------------------------------------
//! test helpers
//! ----------------------------------------------------------------------------
void nbq_read(ns_ntrnt::nbq &a_nbq, char *a_buf, uint32_t a_read_per)
{
        uint64_t l_read = 0;
        uint32_t l_per_read_size = (a_read_per);
        while(a_nbq.read_avail())
        {
                int32_t l_s = 0;
                l_s = a_nbq.read((a_buf+l_read), l_per_read_size);
                if(l_s > 0)
                {
                        l_read += l_s;
                }
        }
}
//! ----------------------------------------------------------------------------
//! verify contents of nbq
//! ----------------------------------------------------------------------------
int32_t verify_contents(ns_ntrnt::nbq &a_nbq, uint64_t a_len, uint16_t a_offset)
{
        uint64_t l_read = 0;
        //NDBG_PRINT("a_nbq.read_avail(): %lu\n", a_nbq.read_avail());
        while(a_nbq.read_avail() &&
              (l_read < a_len))
        {
                char l_cmp = TO_HEX((l_read + a_offset) % 16);
                int32_t l_s = 0;
                char l_char;
                l_s = a_nbq.read(&l_char, 1);
                //NDBG_PRINT("l_s: %d\n", l_s);
                if(l_s != 1)
                {
                        //NDBG_PRINT("error\n");
                        return NTRNT_STATUS_ERROR;
                }
                //NDBG_PRINT("l_cmp: %c l_char: %c -l_read: %lu\n", l_cmp, l_char, l_read);
                if(l_cmp != l_char)
                {
                        //NDBG_PRINT("error l_cmp: %c l_char: %c\n", l_cmp, l_char);
                        return NTRNT_STATUS_ERROR;
                }
                ++l_read;
        }
        if(l_read != a_len)
        {
                //NDBG_PRINT("error l_read = %lu a_len = %lu\n", l_read, a_len);
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! Verify contents of buf
//! ----------------------------------------------------------------------------
int32_t verify_contents(char *l_buf, uint64_t a_len, uint16_t a_offset)
{
        uint64_t l_read = 0;
        //NDBG_PRINT("a_nbq.read_avail(): %lu\n", a_nbq.read_avail());
        while(l_read < a_len)
        {
                char l_cmp = TO_HEX((l_read + a_offset) % 16);
                char l_char;
                l_char = l_buf[l_read];
                //NDBG_PRINT("l_cmp: %c l_char: %c -l_read: %lu\n", l_cmp, l_char, l_read);
                if(l_cmp != l_char)
                {
                        //NDBG_PRINT("error l_cmp: %c l_char: %c\n", l_cmp, l_char);
                        return NTRNT_STATUS_ERROR;
                }
                ++l_read;
        }
        if(l_read != a_len)
        {
                //NDBG_PRINT("error l_read = %lu a_len = %lu\n", l_read, a_len);
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! Tests
//! ----------------------------------------------------------------------------
TEST_CASE( "nbq test", "[nbq]" ) {
        //ns_ntrnt::trc_log_level_set(ns_ntrnt::TRC_LOG_LEVEL_NONE);
        SECTION("writing then reading to new") {
                ns_ntrnt::nbq l_nbq(BLOCK_SIZE);
                char *l_buf = create_buf(888);
                nbq_write(l_nbq, l_buf, 888, BLOCK_SIZE);
                REQUIRE(( l_nbq.read_avail() == 888 ));
                //l_nbq.b_display_all());
                char *l_rbuf = (char *)malloc(888);
                nbq_read(l_nbq, l_rbuf, BLOCK_SIZE);
                REQUIRE(( l_nbq.read_avail() == 0 ));
                if(l_buf)
                {
                        free(l_buf);
                        l_buf = NULL;
                }
                if(l_rbuf)
                {
                        free(l_rbuf);
                        l_rbuf = NULL;
                }
        }
        SECTION("reset writing then reading to new") {
                ns_ntrnt::nbq l_nbq(BLOCK_SIZE);
                char *l_buf = create_buf(888);
                l_nbq.reset_read();
                char *l_rbuf = (char *)malloc(888);
                REQUIRE(( l_nbq.read_avail() == 0 ));
                nbq_read(l_nbq, l_rbuf, BLOCK_SIZE);
                REQUIRE(( l_nbq.read_avail() == 0 ));
                l_nbq.reset_write();
                l_nbq.reset_read();
                REQUIRE(( l_nbq.read_avail() == 0 ));
                nbq_read(l_nbq, l_rbuf, BLOCK_SIZE);
                REQUIRE(( l_nbq.read_avail() == 0 ));
                nbq_write(l_nbq, l_buf, 888, BLOCK_SIZE);
                REQUIRE(( l_nbq.read_avail() == 888 ));
                nbq_read(l_nbq, l_rbuf, BLOCK_SIZE);
                REQUIRE(( l_nbq.read_avail() == 0 ));
                if(l_buf)
                {
                        free(l_buf);
                        l_buf = NULL;
                }
                if(l_rbuf)
                {
                        free(l_rbuf);
                        l_rbuf = NULL;
                }
        }
        SECTION("reset writing then reading") {
                ns_ntrnt::nbq l_nbq(BLOCK_SIZE);
                char *l_buf = create_buf(888);
                char *l_rbuf = (char *)malloc(888);
                l_nbq.reset();
                REQUIRE(( l_nbq.read_avail() == 0 ));
                nbq_write(l_nbq, l_buf, 888, BLOCK_SIZE);
                REQUIRE(( l_nbq.read_avail() == 888 ));
                nbq_read(l_nbq, l_rbuf, BLOCK_SIZE);
                REQUIRE(( l_nbq.read_avail() == 0 ));
                if(l_buf)
                {
                        free(l_buf);
                        l_buf = NULL;
                }
                if(l_rbuf)
                {
                        free(l_rbuf);
                        l_rbuf = NULL;
                }
        }
        SECTION("Reset Writing/Writing then Reading") {
                ns_ntrnt::nbq l_nbq(BLOCK_SIZE);
                char *l_buf = create_buf(1776);
                char *l_rbuf = (char *)malloc(1776);
                l_nbq.reset();
                REQUIRE(( l_nbq.read_avail() == 0 ));
                nbq_write(l_nbq, l_buf, 888, BLOCK_SIZE);
                nbq_write(l_nbq, l_buf, 888, BLOCK_SIZE);
                REQUIRE(( l_nbq.read_avail() == 1776 ));
                //l_nbq.b_display_all());
                nbq_read(l_nbq, l_rbuf, BLOCK_SIZE);
                REQUIRE(( l_nbq.read_avail() == 0 ));
                if(l_buf)
                {
                        free(l_buf);
                        l_buf = NULL;
                }
                if(l_rbuf)
                {
                        free(l_rbuf);
                        l_rbuf = NULL;
                }
        }
        SECTION("split") {
                ns_ntrnt::nbq l_nbq(BLOCK_SIZE);
                char *l_uni_buf = create_uniform_buf(703);
                char *l_rbuf = (char *)malloc(888);
                l_nbq.reset();
                nbq_write(l_nbq, l_uni_buf, 703, 133);
                REQUIRE(( l_nbq.read_avail() == 703 ));
                int32_t l_s;
                l_s = verify_contents(l_nbq, 703, 0);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                l_nbq.reset_read();
                ns_ntrnt::nbq *l_nbq_tail;
                // split at > written offset -return nothing
                l_s = l_nbq.split(&l_nbq_tail, 703);
                REQUIRE(( l_s == NTRNT_STATUS_ERROR ));
                REQUIRE(( l_nbq_tail == NULL ));
                REQUIRE(( l_nbq.read_avail() == 703 ));
                // split at 0 offset -return nothing
                l_s = l_nbq.split(&l_nbq_tail, 0);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                REQUIRE(( l_nbq_tail == NULL ));
                REQUIRE(( l_nbq.read_avail() == 703 ));
                l_s = l_nbq.split(&l_nbq_tail, 400);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                REQUIRE(( l_nbq_tail != NULL ));
                REQUIRE(( l_nbq_tail->read_avail() == 303 ));
                l_nbq.reset_read();
                l_s = verify_contents(l_nbq, 400, 0);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                l_nbq_tail->reset_read();
                l_s = verify_contents(*l_nbq_tail, 303, 0);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                if(l_nbq_tail)
                {
                        delete l_nbq_tail;
                        l_nbq_tail = NULL;
                }
                if(l_uni_buf)
                {
                        free(l_uni_buf);
                        l_uni_buf = NULL;
                }
                if(l_rbuf)
                {
                        free(l_rbuf);
                        l_rbuf = NULL;
                }
        }
        SECTION("join") {
                ns_ntrnt::nbq *l_nbq = new ns_ntrnt::nbq(BLOCK_SIZE);
                char *l_uni_buf = create_uniform_buf(703);
                l_nbq->reset();
                nbq_write(*l_nbq, l_uni_buf, 703, 155);
                REQUIRE(( l_nbq->read_avail() == 703 ));
                ns_ntrnt::nbq *l_nbq_tail = new ns_ntrnt::nbq(BLOCK_SIZE);
                nbq_write(*l_nbq_tail, l_uni_buf, 400, 200);
                int32_t l_s;
                l_s = l_nbq->join_ref(*l_nbq_tail);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                REQUIRE(( l_nbq->read_avail() == 1103 ));
                l_nbq->reset_read();
                // verify head
                l_s = verify_contents(*l_nbq, 703, 0);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                // verify tail
                l_s = verify_contents(*l_nbq, 400, 0);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                REQUIRE(( l_nbq->read_avail() == 0 ));
                if(l_nbq)
                {
                        delete l_nbq;
                        l_nbq = NULL;
                }
                l_nbq_tail->reset_read();
                l_s = verify_contents(*l_nbq_tail, 400, 0);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                if(l_uni_buf)
                {
                        free(l_uni_buf);
                        l_uni_buf = NULL;
                }
                if(l_nbq_tail)
                {
                        delete l_nbq_tail;
                        l_nbq_tail = NULL;
                }
        }
        SECTION("split and join") {
                ns_ntrnt::nbq *l_nbq = new ns_ntrnt::nbq(BLOCK_SIZE);
                char *l_uni_buf = create_uniform_buf(703);
                nbq_write(*l_nbq, l_uni_buf, 703, 133);
                REQUIRE(( l_nbq->read_avail() == 703 ));
                int32_t l_s;
                l_s = verify_contents(*l_nbq, 703, 0);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                l_nbq->reset_read();
                ns_ntrnt::nbq *l_nbq_tail;
                // split at > written offset -return nothing
                l_s = l_nbq->split(&l_nbq_tail, 703);
                REQUIRE(( l_s == NTRNT_STATUS_ERROR ));
                REQUIRE(( l_nbq_tail == NULL ));
                REQUIRE(( l_nbq->read_avail() == 703 ));
                // split at 0 offset -return nothing
                l_s = l_nbq->split(&l_nbq_tail, 0);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                REQUIRE(( l_nbq_tail == NULL ));
                REQUIRE(( l_nbq->read_avail() == 703 ));
                l_s = l_nbq->split(&l_nbq_tail, 400);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                REQUIRE(( l_nbq_tail != NULL ));
                REQUIRE(( l_nbq_tail->read_avail() == 303 ));
                l_nbq->reset_read();
                l_s = verify_contents(*l_nbq, 400, 0);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                if(l_nbq)
                {
                        delete l_nbq;
                        l_nbq = NULL;
                }
                l_nbq_tail->reset_read();
                l_s = verify_contents(*l_nbq_tail, 303, 0);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                // join to new
                ns_ntrnt::nbq *l_nbq_1 = new ns_ntrnt::nbq(BLOCK_SIZE);
                nbq_write(*l_nbq_1, l_uni_buf, 300, 155);
                REQUIRE(( l_nbq_1->read_avail() == 300 ));
                l_s = l_nbq_1->join_ref(*l_nbq_tail);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                REQUIRE(( l_nbq_1->read_avail() == 603 ));
                // verify head
                l_s = verify_contents(*l_nbq_1, 300, 0);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                // verify tail
                l_s = verify_contents(*l_nbq_1, 303, 0);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                if(l_nbq_1)
                {
                        delete l_nbq_1;
                        l_nbq_1 = NULL;
                }
                if(l_nbq_tail)
                {
                        delete l_nbq_tail;
                        l_nbq_tail = NULL;
                }
                if(l_uni_buf)
                {
                        free(l_uni_buf);
                        l_uni_buf = NULL;
                }
        }
        SECTION("write read write on boundaries") {
                ns_ntrnt::nbq l_nbq(4096);
                char *l_buf = create_uniform_buf(4*4096);
                char *l_rbuf = (char *)malloc(4*4096);
                nbq_write(l_nbq, l_buf, 4*4096, 4096);
                REQUIRE(( l_nbq.b_read_avail() == (4096)));
                REQUIRE(( l_nbq.read_avail() == (4*4096)));
                int32_t l_s;
                //l_nbq.b_display_all();
                l_s = verify_contents(l_nbq, 4*4096, 0);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                l_nbq.reset_read();
                nbq_read(l_nbq, l_rbuf, 4096);
                //ns_ntrnt::mem_display((const uint8_t *)l_rbuf, 4*4096, true);
                l_s = verify_contents(l_rbuf, 4*4096, 0);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                REQUIRE(( l_nbq.b_read_avail() == 0));
                REQUIRE(( l_nbq.read_avail() == 0));
                nbq_write(l_nbq, l_buf, 4*4096, 4096);
                REQUIRE(( l_nbq.b_read_avail() == (4096)));
                REQUIRE(( l_nbq.read_avail() == (4*4096)));
                nbq_read(l_nbq, l_rbuf, 4096);
                //ns_ntrnt::mem_display((const uint8_t *)l_rbuf, 4*4096, true);
                l_s = verify_contents(l_rbuf, 4*4096, 0);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                // -----------------------------------------
                // shrink
                // -----------------------------------------
                l_nbq.shrink();
                REQUIRE(( l_nbq.b_read_avail() == 0));
                REQUIRE(( l_nbq.read_avail() == 0));
                REQUIRE(( l_nbq.b_write_avail() == 0));
                REQUIRE(( l_nbq.b_read_avail() == 0));
                REQUIRE(( l_nbq.read_avail() == 0));
                // -----------------------------------------
                // write after shrink
                // -----------------------------------------
                nbq_write(l_nbq, l_buf, 4*4096, 4096);
                REQUIRE(( l_nbq.b_read_avail() == (4096)));
                REQUIRE(( l_nbq.read_avail() == (4*4096)));
                //l_nbq.b_display_all();
                l_s = verify_contents(l_nbq, 4*4096, 0);
                REQUIRE(( l_s == NTRNT_STATUS_OK ));
                //l_nbq.b_display_all());
                //nbq_read(l_nbq, l_buf, BLOCK_SIZE);
                //REQUIRE(( l_nbq.read_avail() == 0 ));
                if(l_rbuf)
                {
                        free(l_rbuf);
                        l_rbuf = NULL;
                }
                if(l_buf)
                {
                        free(l_buf);
                        l_buf = NULL;
                }
        }
        SECTION("starts_with") {
                ns_ntrnt::nbq l_nbq(BLOCK_SIZE);
                char *l_buf = create_uniform_buf(8);
                nbq_write(l_nbq, l_buf, 8, 1);
                REQUIRE(( l_nbq.b_read_avail() == 8));
                //l_nbq.b_display_all();
#define _STARTS_WITH(_str) l_nbq.starts_with(_str, sizeof(_str)-1)
                REQUIRE(( _STARTS_WITH("0123") == true));
                REQUIRE(( _STARTS_WITH("01234") == true));
                REQUIRE(( _STARTS_WITH("01235") == false));
                REQUIRE(( _STARTS_WITH("01234567") == true));
                REQUIRE(( _STARTS_WITH("01234568") == false));
                REQUIRE(( _STARTS_WITH("012345678") == false));
                if(l_buf)
                {
                        free(l_buf);
                        l_buf = NULL;
                }
        }
}
