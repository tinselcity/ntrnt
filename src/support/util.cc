//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
// ---------------------------------------------------------
// sao
// ---------------------------------------------------------
#include "ntrnt/def.h"
#include "support/util.h"
#include "support/trace.h"
#include "support/ndebug.h"
// ---------------------------------------------------------
// openssl
// ---------------------------------------------------------
#include <openssl/bio.h>
#include <openssl/evp.h>
// ---------------------------------------------------------
// std libs
// ---------------------------------------------------------
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <math.h>
namespace ns_ntrnt
{
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t read_file(const char *a_file, char **a_buf, size_t *a_len)
{
        struct stat l_stat;
        int32_t l_status = NTRNT_STATUS_OK;
        l_status = stat(a_file, &l_stat);
        if(l_status != 0)
        {
                NTRNT_PERROR("error performing stat on file: %s.  Reason: %s", a_file, strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        if(!(l_stat.st_mode & S_IFREG))
        {
                NTRNT_PERROR("error opening file: %s.  Reason: is NOT a regular file", a_file);
                return NTRNT_STATUS_ERROR;
        }
        FILE * l_file;
        l_file = fopen(a_file,"r");
        if (NULL == l_file)
        {
                NTRNT_PERROR("error opening file: %s.  Reason: %s", a_file, strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        int32_t l_size = l_stat.st_size;
        char *l_buf;
        l_buf = (char *)malloc(sizeof(char)*l_size+1);
        int32_t l_read_size;
        l_read_size = fread(l_buf, 1, l_size, l_file);
        if(l_read_size != l_size)
        {
                NTRNT_PERROR("error performing fread.  Reason: %s [%d:%d]", strerror(errno), l_read_size, l_size);
                return NTRNT_STATUS_ERROR;
        }
        l_buf[l_size] = '\0';
        l_status = fclose(l_file);
        if (NTRNT_STATUS_OK != l_status)
        {
                NTRNT_PERROR("error performing fclose.  Reason: %s", strerror(errno));
                return -1;
        }
        *a_buf = l_buf;
        *a_len = l_size;
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Encodes a string to base64
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t b64_encode(char** ao_out, const unsigned char* a_in, size_t a_in_len)
{
        BIO *l_bio = nullptr;
        BIO *l_b64 = nullptr;
        FILE *l_stream = nullptr;
        int l_encodedSize = 0;
        // -------------------------------------------------
        // calculate encoded size
        // -------------------------------------------------
        l_encodedSize = 4 * ceil((double) a_in_len / 3);
        // -------------------------------------------------
        // make space
        // -------------------------------------------------
        *ao_out = (char*) malloc(l_encodedSize + 1);
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        l_stream = fmemopen(*ao_out, l_encodedSize + 1, "w");
        l_b64 = BIO_new(BIO_f_base64());
        l_bio = BIO_new_fp(l_stream, BIO_NOCLOSE);
        l_bio = BIO_push(l_b64, l_bio);
        // -------------------------------------------------
        // ignore newlines - write everything in one line
        // -------------------------------------------------
        BIO_set_flags(l_bio, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(l_bio, a_in, a_in_len);
        BIO_flush(l_bio);
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        BIO_free_all(l_bio);
        fclose(l_stream);
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Encodes a string to base64
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t b64_encode(std::string& ao_out, const unsigned char* a_in, size_t a_in_len)
{
        char* l_buf = nullptr;
        int32_t l_s;
        l_s = b64_encode(&l_buf, a_in, a_in_len);
        if (l_s != NTRNT_STATUS_OK)
        {
                if (l_buf) { free(l_buf); l_buf = nullptr; }
                return NTRNT_STATUS_ERROR;
        }
        ao_out.assign(l_buf);
        if (l_buf) { free(l_buf); l_buf = nullptr; }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t bin2hex(char** ao_out, const unsigned char *a_bin, size_t a_len)
{
        if ((a_bin == NULL) ||
            (a_len == 0))
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // alloc
        // -------------------------------------------------
        *ao_out = (char*)malloc(a_len*2+1);
        // -------------------------------------------------
        // set
        // -------------------------------------------------
        char* l_out = *ao_out;
        for (size_t i=0; i < a_len; ++i)
        {
                l_out[i*2]   = "0123456789abcdef"[a_bin[i] >> 4];
                l_out[i*2+1] = "0123456789abcdef"[a_bin[i] & 0x0F];
        }
        // -------------------------------------------------
        // terminate
        // -------------------------------------------------
        l_out[a_len*2] = '\0';
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
std::string rand_str(const size_t a_len)
{
        std::string l_result;
        size_t l_idx = 0;
        static const char s_char_set[] =
                "0123456789"
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        while (l_idx < a_len)
        {
                size_t i_rand = (((double)rand())/RAND_MAX) * (sizeof s_char_set - 1);
                char l_c = s_char_set[i_rand];
                l_result += l_c;
                ++l_idx;
        }
        return l_result;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
const std::string& get_peer_id(void)
{
        static std::string l_peer_id;
        if (!l_peer_id.empty())
        {
                return l_peer_id;
        }
        // -------------------------------------------------
        // peer_id is exactly 20 bytes (characters) long.
        // ref: https://wiki.theory.org/BitTorrentSpecification#peer_id
        // -------------------------------------------------
#define _PEER_ID_REFIX "-NT000Z-"
        l_peer_id = _PEER_ID_REFIX;
        l_peer_id += rand_str(20-strlen(_PEER_ID_REFIX));
        return l_peer_id;
}
}
