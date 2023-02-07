#ifndef _NTRNT_UPNP_H
#define _NTRNT_UPNP_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
// ---------------------------------------------------------
// upnp
// ---------------------------------------------------------
#include <miniupnpc/miniupnpc.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#ifndef NTRNT_STATUS_OK
#define NTRNT_STATUS_OK 0
#endif
#ifndef NTRNT_STATUS_ERROR
#define NTRNT_STATUS_ERROR -1
#endif
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
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \class: upnp
//! ----------------------------------------------------------------------------
class upnp {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        upnp(void);
        ~upnp(void);
        int32_t init(void);
        int32_t teardown(void);
        int32_t add_port_mapping(uint16_t a_port);
        int32_t delete_port_mapping(uint16_t a_port);
        const char* get_stat_ext_ip(void) { return m_stat_ext_ip; }
private:
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        struct UPNPUrls m_urls;
        struct IGDdatas m_datas;
        char m_lan_addr[16];
        // -------------------------------------------------
        // state
        // -------------------------------------------------
        char m_stat_status[64];
        uint32_t m_stat_uptime;
        char m_stat_last_conn_err[64];
        char m_stat_ext_ip[64];
        uint32_t m_stat_br_down;
        uint32_t m_stat_br_up;
};
}
//! ----------------------------------------------------------------------------
//! prototypes
//! ----------------------------------------------------------------------------
int32_t get_public_address(char* ao_ip_addr_str);
int32_t echo_server(uint16_t a_port);
#endif
