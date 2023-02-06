//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <string>
#include <stdio.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
//  --------------------------------------------------------
// stl
//  --------------------------------------------------------
#include <vector>
// ---------------------------------------------------------
// externa ntrnt includes
// ---------------------------------------------------------
#include "ntrnt/def.h"
#include "ntrnt/ntrnt.h"
// ---------------------------------------------------------
// internal ntrnt includes
// ---------------------------------------------------------
#include "bencode/bencode.h"
#include "support/ndebug.h"
#include "support/util.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#ifndef STATUS_OK
#define STATUS_OK 0
#endif
#ifndef STATUS_ERROR
#define STATUS_ERROR -1
#endif
//! ----------------------------------------------------------------------------
//! \details: Print the version.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void print_version(FILE* a_stream, int a_exit_code)
{
        // print out the version information
        fprintf(a_stream, "bdecode bencoding decoder.\n");
        fprintf(a_stream, "    Version: %s\n", NTRNT_VERSION);
        exit(a_exit_code);
}
//! ----------------------------------------------------------------------------
//! \details: Print the command line help.
//! \return:  NA
//! \param:   a_stream FILE *
//! \param:   a_exit_code exit code
//! ----------------------------------------------------------------------------
static void print_usage(FILE* a_stream, int a_exit_code)
{
        fprintf(a_stream, "Usage: bdecode [options]\n");
        fprintf(a_stream, "Options:\n");
        fprintf(a_stream, "  -h, --help           display this help and exit.\n");
        fprintf(a_stream, "  -V, --version        display the version number and exit.\n");
        fprintf(a_stream, "  \n");
        exit(a_exit_code);
}
//! ----------------------------------------------------------------------------
//! \details main
//! \return  0 on success
//!          -1 on error
//! \param   argc/argv...
//! ----------------------------------------------------------------------------
int main(int argc, char** argv)
{
        // -------------------------------------------------
        // vars
        // -------------------------------------------------
        int l_s;
        bool l_input_flag = false;
        std::string l_be_file;
        // -------------------------------------------------
        // Get args...
        // -------------------------------------------------
        char l_opt = '\0';
        std::string l_arg;
        int l_opt_index = 0;
        static struct option l_long_opt[] = {
                { "help",     no_argument,       0, 'h' },
                { "version",  no_argument,       0, 'V' },
                // Sentinel
                { 0,          0,                 0,  0  }
        };
        // -------------------------------------------------
        // args...
        // -------------------------------------------------
        char l_short_arg_list[] = "hV";
        while(((unsigned char)l_opt != 255))
        {
                l_opt = getopt_long_only(argc, argv, l_short_arg_list, l_long_opt, &l_opt_index);
                if (optarg)
                {
                        l_arg = std::string(optarg);
                }
                else
                {
                        l_arg.clear();
                }
                switch (l_opt)
                {
                // -----------------------------------------
                // *****************************************
                // options
                // *****************************************
                // -----------------------------------------
                // -----------------------------------------
                // Help
                // -----------------------------------------
                case 'h':
                {
                        print_usage(stdout, 0);
                        break;
                }
                // -----------------------------------------
                // version
                // -----------------------------------------
                case 'V':
                {
                        print_version(stdout, 0);
                        break;
                }
                // -----------------------------------------
                // ?
                // -----------------------------------------
                case '?':
                {
                        // ---------------------------------
                        // Required argument was missing
                        // '?' is provided when the 3rd arg
                        // to getopt_long does not begin with
                        //':', and preceeded by an automatic
                        // error message.
                        // ---------------------------------
                        fprintf(stderr, "  Exiting.\n");
                        return STATUS_ERROR;
                }
                // -----------------------------------------
                // default
                // -----------------------------------------
                default:
                {
                        // ---------------------------------
                        // get the host...
                        // ---------------------------------
                        if (argv[optind])
                        {
                                l_be_file = argv[optind];
                        }
                        if (!l_be_file.empty())
                        {
                                l_input_flag = true;
                        }
                        break;
                }
                }
        }
        // -------------------------------------------------
        // if torrent file on cmd line
        // -------------------------------------------------
        ns_ntrnt::bdecode l_be;
        if (!l_be_file.empty())
        {
                l_s = l_be.init(l_be_file.c_str());
                if (l_s != NTRNT_STATUS_OK)
                {
                        fprintf(stderr,
                                "Error performing init(%s).  Reason: %s.\n",
                                l_be_file.c_str(),
                                ns_ntrnt::get_err_msg());
                        return STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // read from stdin til eol
        // -------------------------------------------------
        else
        {
                // -----------------------------------------
                // wacky stdin
                // copying isn't great
                // -----------------------------------------
#define _IN_BUF_CHUNK_SIZE 2048
                char l_inbuf[_IN_BUF_CHUNK_SIZE];
                std::vector<char> l_vbuf;
                FILE *l_fp = nullptr;
                l_fp = fopen("/dev/stdin","rb");
                size_t l_read;
                while( (l_read = fread(l_inbuf, 1, _IN_BUF_CHUNK_SIZE, l_fp)) > 0 )
                {
                        l_vbuf.insert(l_vbuf.end(), l_inbuf, l_inbuf+l_read);
                }
                // -----------------------------------------
                // parse
                // -----------------------------------------
                l_s = l_be.init(l_vbuf.data(), l_vbuf.size());
                if (l_s != NTRNT_STATUS_OK)
                {
                        fprintf(stderr,
                                "Error performing read from stdin.  Reason: %s.\n",
                                ns_ntrnt::get_err_msg());
                        return STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // display
        // -------------------------------------------------
        l_be.display();
        // -------------------------------------------------
        // cleanup...
        // -------------------------------------------------
        return STATUS_OK;
}
