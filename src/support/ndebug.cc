//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "ndebug.h"
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
// support backtrace
#include <execinfo.h>
// support demangled symbols
#include <cxxabi.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int get_stack_string(char* ao_stack_str) {
  size_t l_stack_depth = 0;
  //Max depth == 20
  void* l_stack_addrs[NDBG_NUM_BACKTRACE_IN_TAG] = {(void*)0};
  char** l_stack_strings = NULL;
  int l_s = 0;
  l_stack_depth = backtrace(l_stack_addrs, NDBG_NUM_BACKTRACE_IN_TAG);
  l_stack_strings = backtrace_symbols(l_stack_addrs, l_stack_depth);
  ao_stack_str[0] = '\0';
  for (size_t i = 0; i < l_stack_depth; i++) {
    // for each frame in the backtrace, excluding the current one
    // parse symbol and demangle
    std::string l_current_entry(l_stack_strings[i]);
    char l_frame_str[64] = "";
    int l_open_paren = l_current_entry.find('(');
    char* l_pretty_name = abi::__cxa_demangle(
        l_current_entry
            .substr(l_open_paren + 1,
                    l_current_entry.find("+") - l_open_paren - 1)
            .c_str(),
        0, 0, &l_s);
    // Skip 0 -<this frame>
    if ((i != 0) && (i != 1)) {
      if (i == 2) {
        snprintf(l_frame_str, sizeof(l_frame_str), "%sFrm[%zd]:%s",
                 ANSI_COLOR_FG_RED, i - 2, ANSI_COLOR_FG_GREEN);
      } else {
        snprintf(l_frame_str, sizeof(l_frame_str), "%sFrm[%zd]:%s",
                 ANSI_COLOR_FG_BLUE, i - 2, ANSI_COLOR_FG_GREEN);
      }
      strcat(ao_stack_str, l_frame_str);
      if (l_pretty_name) {
        strncat(ao_stack_str, l_pretty_name, 256);
        free(l_pretty_name);
      } else {
        strncat(ao_stack_str, l_current_entry.c_str(), 256);
      }
      strcat(ao_stack_str, "\033[0m\n");
    }
  }
  free(l_stack_strings);
  return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void print_bt(const char* a_file, const char* a_func, const int a_line) {
  //char tag[MAX_BACKTRACE_TAG_SIZE];
  char func_str[NDBG_MAX_BACKTRACE_TAG_SIZE] = "";
  get_stack_string(func_str);
  //snNDBG_OUTPUT(tag, MAX_BACKTRACE_TAG_SIZE - 1, "%s || %s::%s::%d", func_str, a_file, a_func, a_line);
  NDBG_OUTPUT("%s=====>> B A C K T R A C E <<=====%s \n(%s%s::%s%s::%d)\n",
              ANSI_COLOR_BG_BLUE, ANSI_COLOR_OFF, ANSI_COLOR_FG_YELLOW, a_file,
              a_func, ANSI_COLOR_OFF, a_line);
  NDBG_OUTPUT("%s\n", func_str);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void mem_display(const uint8_t* a_buf, size_t a_len) {
  char l_display_line[256] = "";
  uint32_t l_bytes_displayed = 0;
  char l_byte_display[8] = "";
  char l_ascii_display[17] = "";
  while (l_bytes_displayed < a_len) {
    uint32_t l_col = 0;
    //NDBG_OUTPUT("%s.%d: Display length = %d\n", __FILE__,__LINE__,length);
    //Show offset
    snprintf(l_display_line, sizeof(l_display_line), "%s0x%08x %s",
             ANSI_COLOR_FG_BLUE, l_bytes_displayed, ANSI_COLOR_OFF);
    strcat(l_display_line, " ");
    strcat(l_display_line, ANSI_COLOR_FG_GREEN);
    while ((l_col < 16) && (l_bytes_displayed < a_len)) {
      snprintf(l_byte_display, sizeof(l_byte_display), "%02x",
               (unsigned char)a_buf[l_bytes_displayed]);
      strcat(l_display_line, l_byte_display);
      if (isprint(a_buf[l_bytes_displayed])) {
        l_ascii_display[l_col] = a_buf[l_bytes_displayed];
      } else {
        l_ascii_display[l_col] = '.';
      }
      l_col++;
      l_bytes_displayed++;
      if (!(l_col % 4)) {
        strcat(l_display_line, " ");
      }
    }
    if ((l_col < 16) && (l_bytes_displayed >= a_len)) {
      while (l_col < 16) {
        strcat(l_display_line, "..");
        l_ascii_display[l_col] = '.';
        l_col++;
        if (!(l_col % 4)) {
          strcat(l_display_line, " ");
        }
      }
    }
    l_ascii_display[l_col] = '\0';
    strcat(l_display_line, ANSI_COLOR_OFF);
    strcat(l_display_line, " ");
    strcat(l_display_line, l_ascii_display);
    NDBG_OUTPUT("%s\n", l_display_line);
  }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static const char* g_bit_rep[16] = {
    [0] = "0000",  [1] = "0001",  [2] = "0010",  [3] = "0011",
    [4] = "0100",  [5] = "0101",  [6] = "0110",  [7] = "0111",
    [8] = "1000",  [9] = "1001",  [10] = "1010", [11] = "1011",
    [12] = "1100", [13] = "1101", [14] = "1110", [15] = "1111",
};
void bin_display(const uint8_t* a_buf, size_t a_len) {
  for (size_t i_b = 0; i_b < a_len; ++i_b) {
    uint8_t l_b = a_buf[i_b];
    NDBG_OUTPUT("%s%s", g_bit_rep[l_b >> 4], g_bit_rep[l_b & 0x0F]);
  }
  NDBG_OUTPUT("\n");
}
}  // namespace ns_ntrnt
