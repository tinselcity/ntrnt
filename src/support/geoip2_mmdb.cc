//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <maxminddb.h>
#include "ntrnt/def.h"
#include "support/geoip2_mmdb.h"
#include "support/ndebug.h"
#include "support/trace.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
namespace ns_ntrnt {
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
geoip2_mmdb::geoip2_mmdb():
        m_init(false),
        m_city_mmdb(NULL)
{}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
geoip2_mmdb::~geoip2_mmdb(void)
{
        //close mmdb
        if(m_city_mmdb != NULL)
        {
                MMDB_close(m_city_mmdb);
                free(m_city_mmdb);
                m_city_mmdb = NULL;
        }
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::init(const std::string& a_city_mmdb_path)
{
        MMDB_s *l_db = NULL;
        int32_t l_s;
        m_city_mmdb = NULL;
        // -------------------------------------------------
        // city db
        // -------------------------------------------------
        l_db = (MMDB_s *)malloc(sizeof(MMDB_s));
        l_s = MMDB_open(a_city_mmdb_path.c_str(), MMDB_MODE_MMAP, l_db);
        if(l_s != MMDB_SUCCESS)
        {
                TRC_ERROR("Can't open city mmdb file %s. Reason: %s",
                          a_city_mmdb_path.c_str(),
                          MMDB_strerror(l_s));
                if(l_db) { free(l_db); l_db = NULL; }
                goto done;
        }
        if(l_s == MMDB_IO_ERROR)
        {
                TRC_ERROR("IO error. Reason: %s", strerror(errno));
                if(l_db) { free(l_db); l_db = NULL; }
                return NTRNT_STATUS_ERROR;
        }
        m_city_mmdb = l_db;
done:
        // -------------------------------------------------
        // done
        // -------------------------------------------------
        m_init = true;
        return NTRNT_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Get the country name and city name from a mmdb record
//! \return  0 on success, -1 on error
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t geoip2_mmdb::get_geoip_data(const char **ao_cn_name,
                                    uint32_t &ao_cn_name_len,
                                    const char **ao_city_name,
                                    uint32_t &ao_city_name_len,
                                    double &ao_lat,
                                    double &ao_longit,
                                    const char *a_ip,
                                    uint32_t a_ip_len)
{
        if(!ao_cn_name ||
           !ao_city_name)
        {
                //TRC_ERROR("cn_name or city_name == NULL");
                return NTRNT_STATUS_ERROR;
        }
        *ao_cn_name = NULL;
        *ao_city_name = NULL;
        ao_cn_name_len = 0;
        ao_city_name_len = 0;
        if(!m_init)
        {
                //TRC_ERROR("not initialized");
                return NTRNT_STATUS_ERROR;
        }
        if(!m_city_mmdb)
        {
                //TRC_ERROR("city mmdb == null");
                return NTRNT_STATUS_ERROR;
        }
        ::MMDB_lookup_result_s l_ls;
        int32_t l_gai_err = 0;
        int32_t l_mmdb_err = MMDB_SUCCESS;
        l_ls = MMDB_lookup_string(m_city_mmdb, a_ip, &l_gai_err, &l_mmdb_err);
        if(l_gai_err != 0)
        {
                //TRC_DEBUG("MMDB_lookup_string[%.*s]: reason: %s.",
                //          a_ip_len,
                //          a_ip,
                //          gai_strerror(l_gai_err));
                return NTRNT_STATUS_ERROR;
        }
        if(l_mmdb_err != MMDB_SUCCESS)
        {
                //TRC_ERROR("libmaxminddb: %s", MMDB_strerror(l_mmdb_err));
                return NTRNT_STATUS_ERROR;
        }
        if(!l_ls.found_entry)
        {
                //TRC_ERROR("not found for ip: %.*s", (int)a_ip_len, a_ip);
                return NTRNT_STATUS_ERROR;
        }
        MMDB_entry_data_s l_e_dat;
        int32_t l_s;
        // -------------------------------------------------
        // *************************************************
        // extract country
        // *************************************************
        // -------------------------------------------------
        l_s = MMDB_get_value(&l_ls.entry,
                             &l_e_dat,
                             "country",
                             "names",
                             "en",
                             NULL);
        if(l_s != MMDB_SUCCESS)
        {
                //TRC_ERROR("looking up the entry for ip: %.*s: reason: %s", (int)a_ip_len, a_ip, MMDB_strerror(l_s));
                goto lookup_city;
        }
        if(!l_e_dat.has_data)
        {
                TRC_ERROR("data missing");
                goto lookup_city;
        }
        switch(l_e_dat.type) {
        case MMDB_DATA_TYPE_UTF8_STRING:
        {
                *ao_cn_name = l_e_dat.utf8_string;
                ao_cn_name_len = l_e_dat.data_size;
                break;
        }
        default:
        {
                //TRC_ERROR("wrong data type");
                goto lookup_city;
        }
        }
lookup_city:
        // -------------------------------------------------
        // *************************************************
        // extract city
        // *************************************************
        // -------------------------------------------------
        l_s = MMDB_get_value(&l_ls.entry,
                             &l_e_dat,
                             "city",
                             "names",
                             "en",
                             NULL);
        if(l_s != MMDB_SUCCESS)
        {
                //TRC_ERROR("looking up the entry data: reason: %s", MMDB_strerror(l_s));
                goto lookup_lat;
        }
        if(!l_e_dat.has_data)
        {
                //TRC_ERROR("data missing");
                goto lookup_lat;
        }
        switch(l_e_dat.type) {
        case MMDB_DATA_TYPE_UTF8_STRING:
        {
                *ao_city_name = l_e_dat.utf8_string;
                ao_city_name_len = l_e_dat.data_size;
                break;
        }
        default:
        {
                //TRC_ERROR("wrong data type");
                goto lookup_lat;
        }
        }
lookup_lat:
        // -------------------------------------------------
        // *************************************************
        // extract latitude
        // *************************************************
        // -------------------------------------------------
        l_s = MMDB_get_value(&l_ls.entry,
                             &l_e_dat,
                             "location",
                             "latitude",
                             NULL);
        if(l_s != MMDB_SUCCESS)
        {
                //TRC_ERROR("looking up the entry for ip: %.*s: reason: %s", (int)a_ip_len, a_ip, MMDB_strerror(l_s));
                goto lookup_lon;
        }
        if(!l_e_dat.has_data)
        {
                //TRC_ERROR("data missing");
                goto lookup_lon;
        }
        switch(l_e_dat.type) {
        case MMDB_DATA_TYPE_DOUBLE:
        {
                ao_lat = l_e_dat.double_value;
                break;
        }
        default:
        {
                //TRC_ERROR("wrong data type");
                goto lookup_lon;
        }
        }
lookup_lon:
        // -------------------------------------------------
        // *************************************************
        // extract longitude
        // *************************************************
        // -------------------------------------------------
        l_s = MMDB_get_value(&l_ls.entry,
                             &l_e_dat,
                             "location",
                             "longitude",
                             NULL);
        if(l_s != MMDB_SUCCESS)
        {
                //TRC_ERROR("looking up the entry for ip: %.*s: reason: %s", (int)a_ip_len, a_ip, MMDB_strerror(l_s));
                goto done;
        }
        if(!l_e_dat.has_data)
        {
                //TRC_ERROR("data missing");
                goto done;
        }
        switch(l_e_dat.type) {
        case MMDB_DATA_TYPE_DOUBLE:
        {
                ao_longit = l_e_dat.double_value;
                break;
        }
        default:
        {
                //TRC_ERROR("wrong data type");
                goto done;
        }
        }
done:
        return NTRNT_STATUS_OK;
}
}
