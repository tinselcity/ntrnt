//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
// ---------------------------------------------------------
// internal
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
#include <unistd.h>
#include <math.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
namespace ns_ntrnt
{
//! ----------------------------------------------------------------------------
//! \brief   write contents of buffer to the file
//! \details writes contents of a_buf to a_file
//! \return  0 on Success
//!          -1 on Failure
//! ----------------------------------------------------------------------------
int32_t write_file(const char *a_file, const char *a_buf, size_t a_len)
{
        // Open file...
        int32_t l_s;
        FILE * l_file;
        l_file = fopen(a_file,"w");
        if (l_file == NULL)
        {
                //ERROR("Error opening file: %s  Reason: %s",
                //      a_file,
                //      strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        int32_t l_write_size;
        l_write_size = fwrite(a_buf, 1, a_len, l_file);
        if(l_write_size <= 0)
        {
                fclose(l_file);
                return NTRNT_STATUS_ERROR;
        }
        if((size_t)l_write_size != a_len)
        {
                //ERROR("Error performing fwrite.  Reason: %s [%d:%lu]\n",
                //      strerror(errno),
                //      l_write_size,
                //      a_len);
                fclose(l_file);
                return NTRNT_STATUS_ERROR;
        }
        // Close file...
        l_s = fclose(l_file);
        if (l_s != 0)
        {
                //ERROR("Error performing fclose.  Reason: %s\n",
                //      strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
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
        if (l_status != 0)
        {
                NTRNT_PERROR("error performing stat on file: %s.  Reason: %s", a_file, strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        if (!(l_stat.st_mode & S_IFREG))
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
        if (l_read_size != l_size)
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
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t ensure_dir(const std::string& a_dir)
{
        // -------------------------------------------------
        // check for exists
        // -------------------------------------------------
        struct stat l_dir_info;
        int l_s;
        errno = 0;
        l_s = ::stat(a_dir.c_str(), &l_dir_info);
        if (l_s == 0)
        {
                // -----------------------------------------
                // check is dir
                // -----------------------------------------
                if (!(l_dir_info.st_mode & S_IFDIR))
                {
                        TRC_ERROR("path is not directory [DIR: %s]", a_dir.c_str());
                        return NTRNT_STATUS_ERROR;
                }
                return NTRNT_STATUS_OK;
        }
        if (errno != ENOENT)
        {
                TRC_ERROR("performing stat [DIR: %s].  Reason[%d]: %s",
                          a_dir.c_str(),
                          errno,
                          strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create directory
        // TODO -better way to set attr
        // -------------------------------------------------
        errno = 0;
        l_s = ::mkdir(a_dir.c_str(), 0755);
        if (l_s != 0)
        {
                TRC_ERROR("performing mkdir [DIR: %s].  Reason[%d]: %s",
                          a_dir.c_str(),
                          errno,
                          strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Encodes a string to base64
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t ntrnt_fallocate(int a_fd, size_t a_len)
{
        // -------------------------------------------------
        // OS X does not have posix_fallocate
        // use fcntl+ftruncate
        // -------------------------------------------------
#ifdef __MACH__
        off_t l_len = (off_t)a_len;
        fstore_t l_store = {F_ALLOCATECONTIG, F_PEOFPOSMODE, 0, l_len};
        int l_s;
        // -------------------------------------------------
        // try reserve continous chunk of disk space
        // -------------------------------------------------
        errno = 0;
        l_s = fcntl(a_fd, F_PREALLOCATE, &l_store);
        if(l_s == -1)
        {
                // -----------------------------------------
                // allocated non-continuous if too
                // fragmented
                // -----------------------------------------
                l_store.fst_flags = F_ALLOCATEALL;
                errno = 0;
                l_s = fcntl(a_fd, F_PREALLOCATE, &l_store);
                if(l_s == -1)
                {
                        TRC_ERROR("performing fallocate of size: %zu.  Reason: %s",
                                  a_len,
                                  strerror(errno));
                        return NTRNT_STATUS_ERROR;
                }
        }
        errno = 0;
        l_s = ftruncate(a_fd, a_len);
        if (l_s != 0)
        {
                TRC_ERROR("performing fallocate of size: %zu.  Reason: %s",
                          a_len,
                          strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
#else
        int32_t l_s;
        errno = 0;
        l_s = posix_fallocate(a_fd, 0, a_len);
        if(l_s != 0) {

                TRC_ERROR("performing fallocate of size: %zu.  Reason: %s",
                          a_len,
                          strerror(errno));
                return NTRNT_STATUS_ERROR;
        }
#endif
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
int32_t bin2hex(char** ao_out, const uint8_t* a_bin, size_t a_len)
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
        size_t j = 0;
        for (size_t i=0; i < a_len; ++i, j+=2)
        {
                l_out[j]   = "0123456789abcdef"[a_bin[i] >> 4];
                l_out[j+1] = "0123456789abcdef"[a_bin[i] & 0x0F];
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
int32_t bin2hex_str(std::string& ao_out, const uint8_t* a_bin, size_t a_len)
{
        char* l_buf = nullptr;
        int32_t l_s = 0;
        l_s = bin2hex(&l_buf, a_bin, a_len);
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
int32_t hex2bin(uint8_t* ao_bin,
                size_t& ao_bin_len,
                const char* a_hex,
                const size_t a_hex_len)
{
        if ((a_hex == NULL) ||
            (a_hex_len == 0))
        {
                return NTRNT_STATUS_ERROR;
        }
        // -------------------------------------------------
        // set
        // -------------------------------------------------
        uint8_t* l_bin = ao_bin;
        const char* l_hex = a_hex;
        ao_bin_len = 0;
#define _HEX_TO_INT(_c) ((_c & 0xf) + (_c >> 6) * 9);
        size_t j = 0;
        for (size_t i=0; i < a_hex_len; i+=2)
        {
                uint8_t l_hi = _HEX_TO_INT(l_hex[0]);
                uint8_t l_lo = _HEX_TO_INT(l_hex[1]);
                ((uint8_t*)l_bin)[j] = (l_hi << 4) | l_lo;
                ++j;
                l_hex += 2;
                ao_bin_len += 1;
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
std::string id2str(const id_t& a_id)
{
        std::string l_str;
        int32_t l_s_b2;
        l_s_b2 = bin2hex_str(l_str, a_id.m_data, sizeof(a_id));
        UNUSED(l_s_b2);
        return l_str;
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
        // assume rand seeded ie "srand" called
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
std::string epoch_to_str(uint64_t a_ts)
{
        std::string l_str;
        char l_buf[256];
        struct tm l_et;
        time_t l_es = a_ts;
        // prefer localtime_r ???
        memcpy(&l_et, localtime(&l_es), sizeof (struct tm));
        strftime(l_buf, sizeof(l_buf), "%a, %d %b %Y %H:%M:%S %Z", &l_et);
        l_str = l_buf;
        return l_str;
}
}
