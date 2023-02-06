#ifndef _NTRNT_CB_H
#define _NTRNT_CB_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "http_parser/http_parser.h"
#include <stdint.h>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! parser callbacks
//! ----------------------------------------------------------------------------
int hp_on_message_begin(http_parser* a_parser);
int hp_on_url(http_parser* a_parser, const char *a_at, size_t a_length);
int hp_on_status(http_parser* a_parser, const char *a_at, size_t a_length);
int hp_on_header_field(http_parser* a_parser, const char *a_at, size_t a_length);
int hp_on_header_value(http_parser* a_parser, const char *a_at, size_t a_length);
int hp_on_headers_complete(http_parser* a_parser);
int hp_on_body(http_parser* a_parser, const char *a_at, size_t a_length);
int hp_on_message_complete(http_parser* a_parser);
} // ns_ntrnt
#endif
