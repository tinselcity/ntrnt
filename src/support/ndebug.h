#ifndef _NTRNT_NDEBUG_H
#define _NTRNT_NDEBUG_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include <stdio.h>
// For POD check
#include <stdarg.h>
//! ----------------------------------------------------------------------------
//! ANSI Color Code Strings
//!
//! Taken from:
//! http://pueblo.sourceforge.net/doc/manual/ansi_color_codes.html
//! ----------------------------------------------------------------------------
#define ANSI_COLOR_OFF          "\033[0m"
#define ANSI_COLOR_FG_BLACK     "\033[01;30m"
#define ANSI_COLOR_FG_RED       "\033[01;31m"
#define ANSI_COLOR_FG_GREEN     "\033[01;32m"
#define ANSI_COLOR_FG_YELLOW    "\033[01;33m"
#define ANSI_COLOR_FG_BLUE      "\033[01;34m"
#define ANSI_COLOR_FG_MAGENTA   "\033[01;35m"
#define ANSI_COLOR_FG_CYAN      "\033[01;36m"
#define ANSI_COLOR_FG_WHITE     "\033[01;37m"
#define ANSI_COLOR_FG_DEFAULT   "\033[01;39m"
#define ANSI_COLOR_BG_BLACK     "\033[01;40m"
#define ANSI_COLOR_BG_RED       "\033[01;41m"
#define ANSI_COLOR_BG_GREEN     "\033[01;42m"
#define ANSI_COLOR_BG_YELLOW    "\033[01;43m"
#define ANSI_COLOR_BG_BLUE      "\033[01;44m"
#define ANSI_COLOR_BG_MAGENTA   "\033[01;45m"
#define ANSI_COLOR_BG_CYAN      "\033[01;46m"
#define ANSI_COLOR_BG_WHITE     "\033[01;47m"
#define ANSI_COLOR_BG_DEFAULT   "\033[01;49m"
//! ----------------------------------------------------------------------------
//! Backtrace constants
//! ----------------------------------------------------------------------------
#define NDBG_NUM_BACKTRACE_IN_TAG 30
#define NDBG_MAX_BACKTRACE_TAG_SIZE 8192
//! ----------------------------------------------------------------------------
//! debug macros
//! ----------------------------------------------------------------------------
#ifndef NDBG_OUTPUT
#define NDBG_OUTPUT(...) \
        do { \
                fprintf(stdout, __VA_ARGS__); \
                fflush(stdout); \
        } while(0)
#endif
#ifndef NDBG_PRINT
#define NDBG_PRINT(...) \
        do { \
                fprintf(stdout, "%s:%s.%d: ", __FILE__, __FUNCTION__, __LINE__); \
                fprintf(stdout, __VA_ARGS__);               \
                fflush(stdout); \
        } while(0)
#endif
#ifndef NDBG_HEXDUMP
#define NDBG_HEXDUMP(buffer, len) \
        do { \
                ns_ntrnt::mem_display((const uint8_t*)buffer, len); \
                fflush(stdout); \
        } while(0)
#endif
#ifndef NDBG_BINDUMP
#define NDBG_BINDUMP(buffer, len) \
        do { \
                ns_ntrnt::bin_display((const uint8_t*)buffer, len); \
                fflush(stdout); \
        } while(0)
#endif
#ifndef NDBG_PRINT_BT
#define NDBG_PRINT_BT() print_bt(__FILE__,__FUNCTION__,__LINE__)
#endif
#ifndef NDBG_ERROR
#define NDBG_ERROR(...) \
        do { \
                fprintf(stderr, __VA_ARGS__); \
                fflush(stderr); \
        } while(0)
#endif
#ifndef NDBG_ERROR_AT
#define NDBG_ERROR_AT(...) \
        do { \
                fprintf(stderr, "%s:%s.%d: ", __FILE__, __FUNCTION__, __LINE__); \
                fprintf(stderr, __VA_ARGS__);               \
                fflush(stderr); \
        } while(0)
#endif
//! ----------------------------------------------------------------------------
//! POD
//! ----------------------------------------------------------------------------
#ifndef ENSURE_POD
#define ENSURE_POD(class_name)\
        void __do_check_pod_##class_name() const \
        { \
                if(0) { \
                        static_assert(std::is_pod <class_name>::value, #class_name "must be POD"); \
                }\
        }
#endif
#ifndef CHECK_FOR_POD
#define CHECK_FOR_POD(_class) \
    if(0){ \
        _class var; \
        check_for_pod(1, var); \
    }
#endif
//! ----------------------------------------------------------------------------
//! Macros
//! ----------------------------------------------------------------------------
#ifndef DISALLOW_ASSIGN
#define DISALLOW_ASSIGN(class_name)\
    class_name& operator=(const class_name &);
#endif
#ifndef DISALLOW_COPY
#define DISALLOW_COPY(class_name)\
    class_name(const class_name &);
#endif
#ifndef DISALLOW_COPY_AND_ASSIGN
#define DISALLOW_COPY_AND_ASSIGN(class_name)\
    DISALLOW_COPY(class_name)\
    DISALLOW_ASSIGN(class_name)
#endif
#ifndef DISALLOW_DEFAULT_CTOR
#define DISALLOW_DEFAULT_CTOR(class_name)\
    class_name();
#endif
#ifndef UNUSED
#define UNUSED(x) ( (void)(x) )
#endif
#ifndef FATAL
#define FATAL(fmt, x...)\
        do {\
                fprintf(stderr, fmt, ## x);\
                exit(1);\
        } while(0)
#endif
// Namespace ns_ntrnt
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! Forward Decls
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: Get the rdtsc value
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
__inline__ uint64_t rdtsc()
{
        uint32_t lo, hi;
        // We cannot use "=A", since this would use %rax on x86_64
        __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
        // output registers
        return (uint64_t) hi << 32 | lo;
}
//! ----------------------------------------------------------------------------
//! \details: Define the macro to ensure a class is POD
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
inline int check_for_pod(int count, ...)
{
    va_list ap;
    va_start(ap, count);
    va_end(ap);
    return 0;
}
//! ----------------------------------------------------------------------------
//! Prototypes
//! ----------------------------------------------------------------------------
void print_bt(const char * a_file, const char *a_func, const int a_line);
void mem_display(const uint8_t *a_mem_buf, size_t a_length);
void bin_display(const uint8_t *a_mem_buf, size_t a_length);
} // namespace ns_ntrnt {
#endif // NDEBUG_H_
