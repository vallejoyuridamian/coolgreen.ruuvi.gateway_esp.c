/**
 * @file gw_cfg_json.c
 * @author TheSomeMan
 * @date 2021-09-29
 * @copyright Ruuvi Innovations Ltd, license BSD-3-Clause.
 */

#include "gw_cfg_json_parse.h"
#include <string.h>
#include "gw_cfg_default.h"
#include "gw_cfg_log.h"

#if !defined(RUUVI_TESTS_HTTP_SERVER_CB)
#define RUUVI_TESTS_HTTP_SERVER_CB 0
#endif

#if !defined(RUUVI_TESTS_JSON_RUUVI)
#define RUUVI_TESTS_JSON_RUUVI 0
#endif

#if RUUVI_TESTS_HTTP_SERVER_CB || RUUVI_TESTS_JSON_RUUVI
#define LOG_LOCAL_LEVEL LOG_LEVEL_DEBUG
#else
#define LOG_LOCAL_LEVEL LOG_LEVEL_INFO
#endif
#include "log.h"

#if (LOG_LOCAL_LEVEL >= LOG_LEVEL_DEBUG) && !RUUVI_TESTS
#warning Debug log level prints out the passwords as a "plaintext".
#endif

static const char TAG[] = "gw_cfg";

GW_CFG_JSON_STATIC
bool
gw_cfg_json_copy_string_val(
    const cJSON* const p_json_root,
    const char* const  p_attr_name,
    char* const        p_buf,
    const size_t       buf_len)
{
    if (!json_wrap_copy_string_val(p_json_root, p_attr_name, p_buf, buf_len))
    {
        LOG_DBG("%s: not found", p_attr_name);
        return false;
    }
    LOG_DBG("%s: %s", p_attr_name, p_buf);
    return true;
}

GW_CFG_JSON_STATIC
bool
gw_cfg_json_get_bool_val(const cJSON* p_json_root, const char* p_attr_name, bool* p_val)
{
    if (!json_wrap_get_bool_val(p_json_root, p_attr_name, p_val))
    {
        LOG_DBG("%s: not found", p_attr_name);
        return false;
    }
    LOG_DBG("%s: %d", p_attr_name, *p_val);
    return true;
}

GW_CFG_JSON_STATIC
bool
gw_cfg_json_get_uint16_val(const cJSON* p_json_root, const char* p_attr_name, uint16_t* p_val)
{
    if (!json_wrap_get_uint16_val(p_json_root, p_attr_name, p_val))
    {
        LOG_DBG("%s: not found or invalid", p_attr_name);
        return false;
    }
    LOG_DBG("%s: %u", p_attr_name, *p_val);
    return true;
}

GW_CFG_JSON_STATIC
bool
gw_cfg_json_get_uint8_val(const cJSON* p_json_root, const char* p_attr_name, uint8_t* p_val)
{
    if (!json_wrap_get_uint8_val(p_json_root, p_attr_name, p_val))
    {
        LOG_DBG("%s: not found or invalid", p_attr_name);
        return false;
    }
    LOG_DBG("%s: %u", p_attr_name, *p_val);
    return true;
}

GW_CFG_JSON_STATIC
bool
gw_cfg_json_get_int8_val(const cJSON* p_json_root, const char* p_attr_name, int8_t* p_val)
{
    if (!json_wrap_get_int8_val(p_json_root, p_attr_name, p_val))
    {
        LOG_DBG("%s: not found or invalid", p_attr_name);
        return false;
    }
    LOG_DBG("%s: %d", p_attr_name, (printf_int_t)*p_val);
    return true;
}

static void
gw_cfg_json_parse_device_info(const cJSON* const p_json_root, gw_cfg_device_info_t* const p_gw_cfg_dev_info)
{
    memset(p_gw_cfg_dev_info, 0, sizeof(*p_gw_cfg_dev_info));

    gw_cfg_json_copy_string_val(
        p_json_root,
        "fw_ver",
        &p_gw_cfg_dev_info->esp32_fw_ver.buf[0],
        sizeof(p_gw_cfg_dev_info->esp32_fw_ver.buf));
    gw_cfg_json_copy_string_val(
        p_json_root,
        "nrf52_fw_ver",
        &p_gw_cfg_dev_info->nrf52_fw_ver.buf[0],
        sizeof(p_gw_cfg_dev_info->nrf52_fw_ver.buf));
    gw_cfg_json_copy_string_val(
        p_json_root,
        "gw_mac",
        &p_gw_cfg_dev_info->nrf52_mac_addr.str_buf[0],
        sizeof(p_gw_cfg_dev_info->nrf52_mac_addr.str_buf));
}

void
gw_cfg_json_parse_eth(const cJSON* const p_json_root, gw_cfg_eth_t* const p_gw_cfg_eth)
{
    if (!gw_cfg_json_get_bool_val(p_json_root, "use_eth", &p_gw_cfg_eth->use_eth))
    {
        LOG_WARN("Can't find key '%s' in config-json", "use_eth");
    }
    if (p_gw_cfg_eth->use_eth)
    {
        if (!gw_cfg_json_get_bool_val(p_json_root, "eth_dhcp", &p_gw_cfg_eth->eth_dhcp))
        {
            LOG_WARN("Can't find key '%s' in config-json", "eth_dhcp");
        }
        if (!p_gw_cfg_eth->eth_dhcp)
        {
            if (!gw_cfg_json_copy_string_val(
                    p_json_root,
                    "eth_static_ip",
                    &p_gw_cfg_eth->eth_static_ip.buf[0],
                    sizeof(p_gw_cfg_eth->eth_static_ip.buf)))
            {
                LOG_WARN("Can't find key '%s' in config-json", "eth_static_ip");
            }
            if (!gw_cfg_json_copy_string_val(
                    p_json_root,
                    "eth_netmask",
                    &p_gw_cfg_eth->eth_netmask.buf[0],
                    sizeof(p_gw_cfg_eth->eth_netmask.buf)))
            {
                LOG_WARN("Can't find key '%s' in config-json", "eth_netmask");
            }
            if (!gw_cfg_json_copy_string_val(
                    p_json_root,
                    "eth_gw",
                    &p_gw_cfg_eth->eth_gw.buf[0],
                    sizeof(p_gw_cfg_eth->eth_gw.buf)))
            {
                LOG_WARN("Can't find key '%s' in config-json", "eth_gw");
            }
            if (!gw_cfg_json_copy_string_val(
                    p_json_root,
                    "eth_dns1",
                    &p_gw_cfg_eth->eth_dns1.buf[0],
                    sizeof(p_gw_cfg_eth->eth_dns1.buf)))
            {
                LOG_WARN("Can't find key '%s' in config-json", "eth_dns1");
            }
            if (!gw_cfg_json_copy_string_val(
                    p_json_root,
                    "eth_dns2",
                    &p_gw_cfg_eth->eth_dns2.buf[0],
                    sizeof(p_gw_cfg_eth->eth_dns2.buf)))
            {
                LOG_WARN("Can't find key '%s' in config-json", "eth_dns2");
            }
        }
    }
}

static void
gw_cfg_json_parse_remote_auth_type_basic(const cJSON* const p_json_root, ruuvi_gw_cfg_remote_t* const p_gw_cfg_remote)
{
    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "remote_cfg_auth_basic_user",
            &p_gw_cfg_remote->auth.auth_basic.user.buf[0],
            sizeof(p_gw_cfg_remote->auth.auth_basic.user.buf)))
    {
        LOG_WARN("Can't find key '%s' in config-json", "remote_cfg_auth_basic_user");
    }
    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "remote_cfg_auth_basic_pass",
            &p_gw_cfg_remote->auth.auth_basic.password.buf[0],
            sizeof(p_gw_cfg_remote->auth.auth_basic.password.buf)))
    {
        LOG_INFO(
            "Can't find key '%s' in config-json, leave the previous value unchanged",
            "remote_cfg_auth_basic_pass");
    }
}

static void
gw_cfg_json_parse_remote_auth_type_bearer(const cJSON* const p_json_root, ruuvi_gw_cfg_remote_t* const p_gw_cfg_remote)
{
    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "remote_cfg_auth_bearer_token",
            &p_gw_cfg_remote->auth.auth_bearer.token.buf[0],
            sizeof(p_gw_cfg_remote->auth.auth_bearer.token.buf)))
    {
        LOG_INFO(
            "Can't find key '%s' in config-json, leave the previous value unchanged",
            "remote_cfg_auth_bearer_token");
    }
}

static void
gw_cfg_json_parse_remote(const cJSON* const p_json_root, ruuvi_gw_cfg_remote_t* const p_gw_cfg_remote)
{
    if (!gw_cfg_json_get_bool_val(p_json_root, "remote_cfg_use", &p_gw_cfg_remote->use_remote_cfg))
    {
        LOG_WARN("Can't find key '%s' in config-json", "remote_cfg_use");
    }
    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "remote_cfg_url",
            &p_gw_cfg_remote->url.buf[0],
            sizeof(p_gw_cfg_remote->url.buf)))
    {
        LOG_WARN("Can't find key '%s' in config-json", "remote_cfg_url");
    }

    char auth_type_str[GW_CFG_HTTP_AUTH_TYPE_STR_SIZE];
    if (!gw_cfg_json_copy_string_val(p_json_root, "remote_cfg_auth_type", &auth_type_str[0], sizeof(auth_type_str)))
    {
        LOG_WARN("Can't find key '%s' in config-json", "remote_cfg_auth_type");
    }
    else
    {
        gw_cfg_http_auth_type_e auth_type = GW_CFG_HTTP_AUTH_TYPE_NONE;
        if (0 == strcmp(GW_CFG_HTTP_AUTH_TYPE_STR_NONE, auth_type_str))
        {
            auth_type = GW_CFG_HTTP_AUTH_TYPE_NONE;
        }
        else if (0 == strcmp(GW_CFG_HTTP_AUTH_TYPE_STR_NO, auth_type_str))
        {
            auth_type = GW_CFG_HTTP_AUTH_TYPE_NONE;
        }
        else if (0 == strcmp(GW_CFG_HTTP_AUTH_TYPE_STR_BASIC, auth_type_str))
        {
            auth_type = GW_CFG_HTTP_AUTH_TYPE_BASIC;
        }
        else if (0 == strcmp(GW_CFG_HTTP_AUTH_TYPE_STR_BEARER, auth_type_str))
        {
            auth_type = GW_CFG_HTTP_AUTH_TYPE_BEARER;
        }
        else
        {
            LOG_WARN("Unknown remote_cfg_auth_type='%s', use NONE", auth_type_str);
            auth_type = GW_CFG_HTTP_AUTH_TYPE_NONE;
        }
        if (p_gw_cfg_remote->auth_type != auth_type)
        {
            memset(&p_gw_cfg_remote->auth, 0, sizeof(p_gw_cfg_remote->auth));
            p_gw_cfg_remote->auth_type = auth_type;
            LOG_INFO("Key 'remote_cfg_auth_type' was changed, clear saved auth info");
        }
        switch (auth_type)
        {
            case GW_CFG_HTTP_AUTH_TYPE_NONE:
                break;

            case GW_CFG_HTTP_AUTH_TYPE_BASIC:
                gw_cfg_json_parse_remote_auth_type_basic(p_json_root, p_gw_cfg_remote);
                break;

            case GW_CFG_HTTP_AUTH_TYPE_BEARER:
                gw_cfg_json_parse_remote_auth_type_bearer(p_json_root, p_gw_cfg_remote);
                break;

            case GW_CFG_HTTP_AUTH_TYPE_TOKEN:
                LOG_ERR("Unsupported auth_type=token for remote_cfg");
                break;
        }
    }
    if (!gw_cfg_json_get_bool_val(p_json_root, "remote_cfg_use_ssl_client_cert", &p_gw_cfg_remote->use_ssl_client_cert))
    {
        LOG_WARN("Can't find key '%s' in config-json", "remote_cfg_use_ssl_client_cert");
    }
    if (!gw_cfg_json_get_bool_val(p_json_root, "remote_cfg_use_ssl_server_cert", &p_gw_cfg_remote->use_ssl_server_cert))
    {
        LOG_WARN("Can't find key '%s' in config-json", "remote_cfg_use_ssl_server_cert");
    }
    if (!gw_cfg_json_get_uint16_val(
            p_json_root,
            "remote_cfg_refresh_interval_minutes",
            &p_gw_cfg_remote->refresh_interval_minutes))
    {
        LOG_WARN("Can't find key '%s' in config-json", "remote_cfg_refresh_interval_minutes");
    }
}

static gw_cfg_http_data_format_e
gw_cfg_json_parse_http_data_format(const cJSON* const p_json_root)
{
    char data_format_str[GW_CFG_HTTP_DATA_FORMAT_STR_SIZE];
    if (!gw_cfg_json_copy_string_val(p_json_root, "http_data_format", &data_format_str[0], sizeof(data_format_str)))
    {
        LOG_WARN("Can't find key '%s' in config-json", "http_data_format");
        return GW_CFG_HTTP_DATA_FORMAT_RUUVI;
    }
    if (0 == strcmp(GW_CFG_HTTP_DATA_FORMAT_STR_RUUVI, data_format_str))
    {
        return GW_CFG_HTTP_DATA_FORMAT_RUUVI;
    }
    LOG_WARN("Unknown http_data_format='%s', use 'ruuvi'", data_format_str);
    return GW_CFG_HTTP_DATA_FORMAT_RUUVI;
}

static gw_cfg_http_auth_type_e
gw_cfg_json_parse_http_auth_type(const cJSON* const p_json_root)
{
    char auth_type_str[GW_CFG_HTTP_AUTH_TYPE_STR_SIZE];
    if (!gw_cfg_json_copy_string_val(p_json_root, "http_auth", &auth_type_str[0], sizeof(auth_type_str)))
    {
        LOG_WARN("Can't find key '%s' in config-json", "http_auth");
        return GW_CFG_HTTP_AUTH_TYPE_NONE;
    }
    if (0 == strcmp(GW_CFG_HTTP_AUTH_TYPE_STR_NONE, auth_type_str))
    {
        return GW_CFG_HTTP_AUTH_TYPE_NONE;
    }
    if (0 == strcmp(GW_CFG_HTTP_AUTH_TYPE_STR_BASIC, auth_type_str))
    {
        return GW_CFG_HTTP_AUTH_TYPE_BASIC;
    }
    if (0 == strcmp(GW_CFG_HTTP_AUTH_TYPE_STR_BEARER, auth_type_str))
    {
        return GW_CFG_HTTP_AUTH_TYPE_BEARER;
    }
    if (0 == strcmp(GW_CFG_HTTP_AUTH_TYPE_STR_TOKEN, auth_type_str))
    {
        return GW_CFG_HTTP_AUTH_TYPE_TOKEN;
    }
    LOG_WARN("Unknown http_auth='%s', use 'ruuvi'", auth_type_str);
    return GW_CFG_HTTP_AUTH_TYPE_NONE;
}

static void
gw_cfg_json_parse_http(const cJSON* const p_json_root, ruuvi_gw_cfg_http_t* const p_gw_cfg_http)
{
    if (!gw_cfg_json_get_bool_val(p_json_root, "use_http_ruuvi", &p_gw_cfg_http->use_http_ruuvi))
    {
        LOG_WARN("Can't find key '%s' in config-json", "use_http_ruuvi");
    }
    if (!gw_cfg_json_get_bool_val(p_json_root, "use_http", &p_gw_cfg_http->use_http))
    {
        LOG_WARN("Can't find key '%s' in config-json", "use_http");
    }

    if (p_gw_cfg_http->use_http)
    {
        p_gw_cfg_http->data_format = gw_cfg_json_parse_http_data_format(p_json_root);
        p_gw_cfg_http->auth_type   = gw_cfg_json_parse_http_auth_type(p_json_root);

        if (!gw_cfg_json_copy_string_val(
                p_json_root,
                "http_url",
                &p_gw_cfg_http->http_url.buf[0],
                sizeof(p_gw_cfg_http->http_url.buf)))
        {
            LOG_WARN("Can't find key '%s' in config-json", "http_url");
        }
        switch (p_gw_cfg_http->auth_type)
        {
            case GW_CFG_HTTP_AUTH_TYPE_NONE:
                break;
            case GW_CFG_HTTP_AUTH_TYPE_BASIC:
                if (!gw_cfg_json_copy_string_val(
                        p_json_root,
                        "http_user",
                        &p_gw_cfg_http->auth.auth_basic.user.buf[0],
                        sizeof(p_gw_cfg_http->auth.auth_basic.user.buf)))
                {
                    LOG_WARN("Can't find key '%s' in config-json", "http_user");
                }
                if (!gw_cfg_json_copy_string_val(
                        p_json_root,
                        "http_pass",
                        &p_gw_cfg_http->auth.auth_basic.password.buf[0],
                        sizeof(p_gw_cfg_http->auth.auth_basic.password.buf)))
                {
                    LOG_INFO("Can't find key '%s' in config-json, leave the previous value unchanged", "http_pass");
                }
                break;
            case GW_CFG_HTTP_AUTH_TYPE_BEARER:
                if (!gw_cfg_json_copy_string_val(
                        p_json_root,
                        "http_bearer_token",
                        &p_gw_cfg_http->auth.auth_bearer.token.buf[0],
                        sizeof(p_gw_cfg_http->auth.auth_bearer.token.buf)))
                {
                    LOG_WARN("Can't find key '%s' in config-json", "http_bearer_token");
                }
                break;
            case GW_CFG_HTTP_AUTH_TYPE_TOKEN:
                if (!gw_cfg_json_copy_string_val(
                        p_json_root,
                        "http_api_key",
                        &p_gw_cfg_http->auth.auth_token.token.buf[0],
                        sizeof(p_gw_cfg_http->auth.auth_token.token.buf)))
                {
                    LOG_WARN("Can't find key '%s' in config-json", "http_api_key");
                }
                break;
        }
        if ((GW_CFG_HTTP_DATA_FORMAT_RUUVI == p_gw_cfg_http->data_format)
            && (GW_CFG_HTTP_AUTH_TYPE_NONE == p_gw_cfg_http->auth_type)
            && (0 == strcmp(RUUVI_GATEWAY_HTTP_DEFAULT_URL, p_gw_cfg_http->http_url.buf)))
        {
            // 'use_http_ruuvi' was added in v1.14, so we need to patch configuration
            // to ensure compatibility between configuration versions when upgrading firmware to a new version
            // or rolling back to an old one
            p_gw_cfg_http->use_http_ruuvi = true;
            p_gw_cfg_http->use_http       = false;
        }
        if (p_gw_cfg_http->use_http)
        {
            if (!gw_cfg_json_get_bool_val(
                    p_json_root,
                    "http_use_ssl_client_cert",
                    &p_gw_cfg_http->http_use_ssl_client_cert))
            {
                LOG_WARN("Can't find key '%s' in config-json", "http_use_ssl_client_cert");
            }
            if (!gw_cfg_json_get_bool_val(
                    p_json_root,
                    "http_use_ssl_server_cert",
                    &p_gw_cfg_http->http_use_ssl_server_cert))
            {
                LOG_WARN("Can't find key '%s' in config-json", "http_use_ssl_server_cert");
            }
        }
    }
}

static void
gw_cfg_json_parse_http_stat(const cJSON* const p_json_root, ruuvi_gw_cfg_http_stat_t* const p_gw_cfg_http_stat)
{
    if (!gw_cfg_json_get_bool_val(p_json_root, "use_http_stat", &p_gw_cfg_http_stat->use_http_stat))
    {
        LOG_WARN("Can't find key '%s' in config-json", "use_http_stat");
    }
    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "http_stat_url",
            &p_gw_cfg_http_stat->http_stat_url.buf[0],
            sizeof(p_gw_cfg_http_stat->http_stat_url.buf)))
    {
        LOG_WARN("Can't find key '%s' in config-json", "http_stat_url");
    }
    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "http_stat_user",
            &p_gw_cfg_http_stat->http_stat_user.buf[0],
            sizeof(p_gw_cfg_http_stat->http_stat_user.buf)))
    {
        LOG_WARN("Can't find key '%s' in config-json", "http_stat_user");
    }
    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "http_stat_pass",
            &p_gw_cfg_http_stat->http_stat_pass.buf[0],
            sizeof(p_gw_cfg_http_stat->http_stat_pass.buf)))
    {
        LOG_INFO("Can't find key '%s' in config-json, leave the previous value unchanged", "http_stat_pass");
    }
    if (p_gw_cfg_http_stat->use_http_stat)
    {
        if (!gw_cfg_json_get_bool_val(
                p_json_root,
                "http_stat_use_ssl_client_cert",
                &p_gw_cfg_http_stat->http_stat_use_ssl_client_cert))
        {
            LOG_WARN("Can't find key '%s' in config-json", "http_stat_use_ssl_client_cert");
        }
        if (!gw_cfg_json_get_bool_val(
                p_json_root,
                "http_stat_use_ssl_server_cert",
                &p_gw_cfg_http_stat->http_stat_use_ssl_server_cert))
        {
            LOG_WARN("Can't find key '%s' in config-json", "http_stat_use_ssl_server_cert");
        }
    }
}

static void
gw_cfg_json_parse_mqtt(const cJSON* const p_json_root, ruuvi_gw_cfg_mqtt_t* const p_gw_cfg_mqtt)
{
    if (!gw_cfg_json_get_bool_val(p_json_root, "use_mqtt", &p_gw_cfg_mqtt->use_mqtt))
    {
        LOG_WARN("Can't find key '%s' in config-json", "use_mqtt");
    }
    if (!gw_cfg_json_get_bool_val(
            p_json_root,
            "mqtt_disable_retained_messages",
            &p_gw_cfg_mqtt->mqtt_disable_retained_messages))
    {
        LOG_WARN("Can't find key '%s' in config-json", "mqtt_disable_retained_messages");
    }
    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "mqtt_transport",
            &p_gw_cfg_mqtt->mqtt_transport.buf[0],
            sizeof(p_gw_cfg_mqtt->mqtt_transport.buf)))
    {
        LOG_WARN("Can't find key '%s' in config-json", "mqtt_transport");
    }
    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "mqtt_server",
            &p_gw_cfg_mqtt->mqtt_server.buf[0],
            sizeof(p_gw_cfg_mqtt->mqtt_server.buf)))
    {
        LOG_WARN("Can't find key '%s' in config-json", "mqtt_server");
    }
    if (!gw_cfg_json_get_uint16_val(p_json_root, "mqtt_port", &p_gw_cfg_mqtt->mqtt_port))
    {
        LOG_WARN("Can't find key '%s' in config-json", "mqtt_port");
    }
    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "mqtt_prefix",
            &p_gw_cfg_mqtt->mqtt_prefix.buf[0],
            sizeof(p_gw_cfg_mqtt->mqtt_prefix.buf)))
    {
        const ruuvi_gw_cfg_mqtt_t* const p_default_mqtt = gw_cfg_default_get_mqtt();
        p_gw_cfg_mqtt->mqtt_prefix                      = p_default_mqtt->mqtt_prefix;
        LOG_WARN(
            "Can't find key '%s' in config-json, use default value: %s",
            "mqtt_prefix",
            p_gw_cfg_mqtt->mqtt_prefix.buf);
    }
    if ('\0' == p_gw_cfg_mqtt->mqtt_prefix.buf[0])
    {
        const ruuvi_gw_cfg_mqtt_t* const p_default_mqtt = gw_cfg_default_get_mqtt();
        p_gw_cfg_mqtt->mqtt_prefix                      = p_default_mqtt->mqtt_prefix;
        LOG_WARN(
            "Key '%s' is empty in config-json, use default value: %s",
            "mqtt_prefix",
            p_gw_cfg_mqtt->mqtt_prefix.buf);
    }
    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "mqtt_client_id",
            &p_gw_cfg_mqtt->mqtt_client_id.buf[0],
            sizeof(p_gw_cfg_mqtt->mqtt_client_id.buf)))
    {
        const ruuvi_gw_cfg_mqtt_t* const p_default_mqtt = gw_cfg_default_get_mqtt();
        p_gw_cfg_mqtt->mqtt_client_id                   = p_default_mqtt->mqtt_client_id;
        LOG_WARN(
            "Can't find key '%s' in config-json, use default value: %s",
            "mqtt_client_id",
            p_gw_cfg_mqtt->mqtt_client_id.buf);
    }
    if ('\0' == p_gw_cfg_mqtt->mqtt_client_id.buf[0])
    {
        const ruuvi_gw_cfg_mqtt_t* const p_default_mqtt = gw_cfg_default_get_mqtt();
        p_gw_cfg_mqtt->mqtt_client_id                   = p_default_mqtt->mqtt_client_id;
        LOG_WARN(
            "Key '%s' is empty in config-json, use default value: %s",
            "mqtt_client_id",
            p_gw_cfg_mqtt->mqtt_client_id.buf);
    }
    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "mqtt_user",
            &p_gw_cfg_mqtt->mqtt_user.buf[0],
            sizeof(p_gw_cfg_mqtt->mqtt_user.buf)))
    {
        LOG_WARN("Can't find key '%s' in config-json", "mqtt_user");
    }
    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "mqtt_pass",
            &p_gw_cfg_mqtt->mqtt_pass.buf[0],
            sizeof(p_gw_cfg_mqtt->mqtt_pass.buf)))
    {
        LOG_INFO("Can't find key '%s' in config-json, leave the previous value unchanged", "mqtt_pass");
    }
    if (p_gw_cfg_mqtt->use_mqtt)
    {
        if (!gw_cfg_json_get_bool_val(p_json_root, "mqtt_use_ssl_client_cert", &p_gw_cfg_mqtt->use_ssl_client_cert))
        {
            LOG_WARN("Can't find key '%s' in config-json", "mqtt_use_ssl_client_cert");
        }
        if (!gw_cfg_json_get_bool_val(p_json_root, "mqtt_use_ssl_server_cert", &p_gw_cfg_mqtt->use_ssl_server_cert))
        {
            LOG_WARN("Can't find key '%s' in config-json", "mqtt_use_ssl_server_cert");
        }
    }
}

static void
gw_cfg_json_parse_lan_auth_user_password(
    const cJSON* const             p_json_root,
    ruuvi_gw_cfg_lan_auth_t* const p_gw_cfg_lan_auth)
{
    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "lan_auth_user",
            &p_gw_cfg_lan_auth->lan_auth_user.buf[0],
            sizeof(p_gw_cfg_lan_auth->lan_auth_user.buf)))
    {
        LOG_WARN("Can't find key '%s' in config-json", "lan_auth_user");
    }
    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "lan_auth_pass",
            &p_gw_cfg_lan_auth->lan_auth_pass.buf[0],
            sizeof(p_gw_cfg_lan_auth->lan_auth_pass.buf)))
    {
        LOG_INFO("Can't find key '%s' in config-json, leave the previous value unchanged", "lan_auth_pass");
    }
}

static void
gw_cfg_json_parse_lan_auth(const cJSON* const p_json_root, ruuvi_gw_cfg_lan_auth_t* const p_gw_cfg_lan_auth)
{
    http_server_auth_type_str_t lan_auth_type_str = { 0 };
    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "lan_auth_type",
            lan_auth_type_str.buf,
            sizeof(lan_auth_type_str.buf)))
    {
        LOG_INFO("Can't find key '%s' in config-json, leave the previous value unchanged", "lan_auth_type");
    }
    else
    {
        const ruuvi_gw_cfg_lan_auth_t* const p_default_lan_auth = gw_cfg_default_get_lan_auth();
        p_gw_cfg_lan_auth->lan_auth_type                        = http_server_auth_type_from_str(lan_auth_type_str.buf);
        switch (p_gw_cfg_lan_auth->lan_auth_type)
        {
            case HTTP_SERVER_AUTH_TYPE_BASIC:
            case HTTP_SERVER_AUTH_TYPE_DIGEST:
            case HTTP_SERVER_AUTH_TYPE_RUUVI:
                gw_cfg_json_parse_lan_auth_user_password(p_json_root, p_gw_cfg_lan_auth);
                break;

            case HTTP_SERVER_AUTH_TYPE_DEFAULT:
                p_gw_cfg_lan_auth->lan_auth_user = p_default_lan_auth->lan_auth_user;
                p_gw_cfg_lan_auth->lan_auth_pass = p_default_lan_auth->lan_auth_pass;
                break;

            case HTTP_SERVER_AUTH_TYPE_ALLOW:
            case HTTP_SERVER_AUTH_TYPE_DENY:
            case HTTP_SERVER_AUTH_TYPE_BEARER:
                p_gw_cfg_lan_auth->lan_auth_user.buf[0] = '\0';
                p_gw_cfg_lan_auth->lan_auth_pass.buf[0] = '\0';
                break;
        }
        if ((HTTP_SERVER_AUTH_TYPE_RUUVI == p_gw_cfg_lan_auth->lan_auth_type)
            && (0 == strcmp(p_default_lan_auth->lan_auth_user.buf, p_gw_cfg_lan_auth->lan_auth_user.buf))
            && (0 == strcmp(p_default_lan_auth->lan_auth_pass.buf, p_gw_cfg_lan_auth->lan_auth_pass.buf)))
        {
            p_gw_cfg_lan_auth->lan_auth_type = HTTP_SERVER_AUTH_TYPE_DEFAULT;
        }
    }

    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "lan_auth_api_key",
            &p_gw_cfg_lan_auth->lan_auth_api_key.buf[0],
            sizeof(p_gw_cfg_lan_auth->lan_auth_api_key)))
    {
        LOG_INFO("Can't find key '%s' in config-json, leave the previous value unchanged", "lan_auth_api_key");
    }

    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "lan_auth_api_key_rw",
            &p_gw_cfg_lan_auth->lan_auth_api_key_rw.buf[0],
            sizeof(p_gw_cfg_lan_auth->lan_auth_api_key_rw)))
    {
        LOG_INFO("Can't find key '%s' in config-json, leave the previous value unchanged", "lan_auth_api_key_rw");
    }
}

static void
gw_cfg_json_parse_auto_update(const cJSON* const p_json_root, ruuvi_gw_cfg_auto_update_t* const p_gw_cfg_auto_update)
{
    char auto_update_cycle_str[AUTO_UPDATE_CYCLE_TYPE_STR_MAX_LEN];
    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "auto_update_cycle",
            &auto_update_cycle_str[0],
            sizeof(auto_update_cycle_str)))
    {
        LOG_WARN("Can't find key '%s' in config-json, leave the previous value unchanged", "auto_update_cycle");
    }
    else
    {
        if (0 == strcmp(AUTO_UPDATE_CYCLE_TYPE_STR_REGULAR, auto_update_cycle_str))
        {
            p_gw_cfg_auto_update->auto_update_cycle = AUTO_UPDATE_CYCLE_TYPE_REGULAR;
        }
        else if (0 == strcmp(AUTO_UPDATE_CYCLE_TYPE_STR_BETA_TESTER, auto_update_cycle_str))
        {
            p_gw_cfg_auto_update->auto_update_cycle = AUTO_UPDATE_CYCLE_TYPE_BETA_TESTER;
        }
        else if (0 == strcmp(AUTO_UPDATE_CYCLE_TYPE_STR_MANUAL, auto_update_cycle_str))
        {
            p_gw_cfg_auto_update->auto_update_cycle = AUTO_UPDATE_CYCLE_TYPE_MANUAL;
        }
        else
        {
            p_gw_cfg_auto_update->auto_update_cycle = AUTO_UPDATE_CYCLE_TYPE_REGULAR;
            LOG_WARN("Unknown auto_update_cycle='%s', use REGULAR", auto_update_cycle_str);
        }
    }

    if (!gw_cfg_json_get_uint8_val(
            p_json_root,
            "auto_update_weekdays_bitmask",
            &p_gw_cfg_auto_update->auto_update_weekdays_bitmask))
    {
        LOG_WARN("Can't find key '%s' in config-json", "auto_update_weekdays_bitmask");
    }
    if (!gw_cfg_json_get_uint8_val(
            p_json_root,
            "auto_update_interval_from",
            &p_gw_cfg_auto_update->auto_update_interval_from))
    {
        LOG_WARN("Can't find key '%s' in config-json", "auto_update_interval_from");
    }
    if (!gw_cfg_json_get_uint8_val(
            p_json_root,
            "auto_update_interval_to",
            &p_gw_cfg_auto_update->auto_update_interval_to))
    {
        LOG_WARN("Can't find key '%s' in config-json", "auto_update_interval_to");
    }
    if (!gw_cfg_json_get_int8_val(
            p_json_root,
            "auto_update_tz_offset_hours",
            &p_gw_cfg_auto_update->auto_update_tz_offset_hours))
    {
        LOG_WARN("Can't find key '%s' in config-json", "auto_update_tz_offset_hours");
    }
}

static void
gw_cfg_json_parse_ntp(const cJSON* const p_json_root, ruuvi_gw_cfg_ntp_t* const p_gw_cfg_ntp)
{
    if (!gw_cfg_json_get_bool_val(p_json_root, "ntp_use", &p_gw_cfg_ntp->ntp_use))
    {
        LOG_WARN("Can't find key '%s' in config-json", "ntp_use");
    }
    if (p_gw_cfg_ntp->ntp_use)
    {
        if (!gw_cfg_json_get_bool_val(p_json_root, "ntp_use_dhcp", &p_gw_cfg_ntp->ntp_use_dhcp))
        {
            LOG_WARN("Can't find key '%s' in config-json", "ntp_use_dhcp");
        }
        if (!p_gw_cfg_ntp->ntp_use_dhcp)
        {
            if (!gw_cfg_json_copy_string_val(
                    p_json_root,
                    "ntp_server1",
                    &p_gw_cfg_ntp->ntp_server1.buf[0],
                    sizeof(p_gw_cfg_ntp->ntp_server1.buf)))
            {
                LOG_WARN("Can't find key '%s' in config-json", "ntp_server1");
            }
            if (!gw_cfg_json_copy_string_val(
                    p_json_root,
                    "ntp_server2",
                    &p_gw_cfg_ntp->ntp_server2.buf[0],
                    sizeof(p_gw_cfg_ntp->ntp_server2.buf)))
            {
                LOG_WARN("Can't find key '%s' in config-json", "ntp_server2");
            }
            if (!gw_cfg_json_copy_string_val(
                    p_json_root,
                    "ntp_server3",
                    &p_gw_cfg_ntp->ntp_server3.buf[0],
                    sizeof(p_gw_cfg_ntp->ntp_server3.buf)))
            {
                LOG_WARN("Can't find key '%s' in config-json", "ntp_server3");
            }
            if (!gw_cfg_json_copy_string_val(
                    p_json_root,
                    "ntp_server4",
                    &p_gw_cfg_ntp->ntp_server4.buf[0],
                    sizeof(p_gw_cfg_ntp->ntp_server4.buf)))
            {
                LOG_WARN("Can't find key '%s' in config-json", "ntp_server4");
            }
        }
    }
    else
    {
        p_gw_cfg_ntp->ntp_use_dhcp = false;
    }
}

void
gw_cfg_json_parse_filter(const cJSON* const p_json_root, ruuvi_gw_cfg_filter_t* const p_gw_cfg_filter)
{
    if (!gw_cfg_json_get_uint16_val(p_json_root, "company_id", &p_gw_cfg_filter->company_id))
    {
        LOG_WARN("Can't find key '%s' in config-json", "company_id");
    }
    if (!gw_cfg_json_get_bool_val(p_json_root, "company_use_filtering", &p_gw_cfg_filter->company_use_filtering))
    {
        LOG_WARN("Can't find key '%s' in config-json", "company_use_filtering");
    }
}

void
gw_cfg_json_parse_scan(const cJSON* const p_json_root, ruuvi_gw_cfg_scan_t* const p_gw_cfg_scan)
{
    if (!gw_cfg_json_get_bool_val(p_json_root, "scan_coded_phy", &p_gw_cfg_scan->scan_coded_phy))
    {
        LOG_WARN("Can't find key '%s' in config-json", "scan_coded_phy");
    }
    if (!gw_cfg_json_get_bool_val(p_json_root, "scan_1mbit_phy", &p_gw_cfg_scan->scan_1mbit_phy))
    {
        LOG_WARN("Can't find key '%s' in config-json", "scan_1mbit_phy");
    }
    if (!gw_cfg_json_get_bool_val(p_json_root, "scan_extended_payload", &p_gw_cfg_scan->scan_extended_payload))
    {
        LOG_WARN("Can't find key '%s' in config-json", "scan_extended_payload");
    }
    if (!gw_cfg_json_get_bool_val(p_json_root, "scan_channel_37", &p_gw_cfg_scan->scan_channel_37))
    {
        LOG_WARN("Can't find key '%s' in config-json", "scan_channel_37");
    }
    if (!gw_cfg_json_get_bool_val(p_json_root, "scan_channel_38", &p_gw_cfg_scan->scan_channel_38))
    {
        LOG_WARN("Can't find key '%s' in config-json", "scan_channel_38");
    }
    if (!gw_cfg_json_get_bool_val(p_json_root, "scan_channel_39", &p_gw_cfg_scan->scan_channel_39))
    {
        LOG_WARN("Can't find key '%s' in config-json", "scan_channel_39");
    }
}

static void
gw_cfg_json_parse_scan_filter(const cJSON* const p_json_root, ruuvi_gw_cfg_scan_filter_t* const p_gw_cfg_scan_filter)
{
    if (!gw_cfg_json_get_bool_val(
            p_json_root,
            "scan_filter_allow_listed",
            &p_gw_cfg_scan_filter->scan_filter_allow_listed))
    {
        LOG_WARN("Can't find key '%s' in config-json", "scan_filter_allow_listed");
    }
    const cJSON* const p_json_scan_filter_list = cJSON_GetObjectItem(p_json_root, "scan_filter_list");
    if (NULL == p_json_scan_filter_list)
    {
        LOG_WARN("Can't find key '%s' in config-json", "scan_filter_list");
    }
    else
    {
        const int32_t scan_filter_length = cJSON_GetArraySize(p_json_scan_filter_list);
        uint32_t      arr_idx            = 0;
        for (int32_t i = 0; i < scan_filter_length; ++i)
        {
            cJSON* const      p_filter_item = cJSON_GetArrayItem(p_json_scan_filter_list, i);
            const char* const p_str         = cJSON_GetStringValue(p_filter_item);
            if (!mac_addr_from_str(p_str, &p_gw_cfg_scan_filter->scan_filter_list[arr_idx]))
            {
                LOG_ERR("Can't parse MAC address in scan_filter_list: %s", p_str);
            }
            arr_idx += 1;
        }
        p_gw_cfg_scan_filter->scan_filter_length = arr_idx;
    }
}

static void
gw_cfg_json_parse_cjson_wifi_sta_config(const cJSON* const p_json_wifi_sta_cfg, wifi_sta_config_t* const p_wifi_sta_cfg)
{
    if (!json_wrap_copy_string_val(
            p_json_wifi_sta_cfg,
            "ssid",
            (char*)p_wifi_sta_cfg->ssid,
            sizeof(p_wifi_sta_cfg->ssid)))
    {
        LOG_WARN("Can't find key '%s' in config-json", "wifi_sta_config/ssid");
    }
    if (!json_wrap_copy_string_val(
            p_json_wifi_sta_cfg,
            "password",
            (char*)p_wifi_sta_cfg->password,
            sizeof(p_wifi_sta_cfg->password)))
    {
        LOG_WARN("Can't find key '%s' in config-json", "wifi_sta_config/password");
    }
}

static void
gw_cfg_json_parse_cjson_wifi_sta_settings(
    const cJSON* const         p_json_wifi_sta_cfg,
    wifi_settings_sta_t* const p_wifi_sta_settings)
{
    (void)p_json_wifi_sta_cfg;
    (void)p_wifi_sta_settings;
    // Storing wifi_sta_settings settings in json is not currently supported.

    (void)p_wifi_sta_settings->sta_power_save;
    (void)p_wifi_sta_settings->sta_static_ip;
    (void)p_wifi_sta_settings->sta_static_ip_config;
}

static void
gw_cfg_json_parse_cjson_wifi_ap_config(const cJSON* const p_json_wifi_ap_cfg, wifi_ap_config_t* const p_wifi_ap_cfg)
{
    if (!json_wrap_copy_string_val(
            p_json_wifi_ap_cfg,
            "password",
            (char*)p_wifi_ap_cfg->password,
            sizeof(p_wifi_ap_cfg->password)))
    {
        LOG_WARN("Can't find key '%s' in config-json", "wifi_ap_config/password");
    }
    if (!gw_cfg_json_get_uint8_val(p_json_wifi_ap_cfg, "channel", &p_wifi_ap_cfg->channel))
    {
        LOG_WARN("Can't find key '%s' in config-json", "wifi_ap_config/channel");
    }
    if (0 == p_wifi_ap_cfg->channel)
    {
        p_wifi_ap_cfg->channel = 1;
        LOG_WARN(
            "Key '%s' in config-json is zero, use default value: %d",
            "wifi_ap_config/channel",
            (printf_int_t)p_wifi_ap_cfg->channel);
    }
}

static void
gw_cfg_json_parse_cjson_wifi_ap_settings(
    const cJSON* const        p_json_wifi_ap_cfg,
    wifi_settings_ap_t* const p_wifi_ap_settings)
{
    (void)p_json_wifi_ap_cfg;
    (void)p_wifi_ap_settings;
    // Storing wifi_settings_ap in json is not currently supported.

    (void)p_wifi_ap_settings->ap_bandwidth;
    (void)p_wifi_ap_settings->ap_ip;
    (void)p_wifi_ap_settings->ap_gw;
    (void)p_wifi_ap_settings->ap_netmask;
}

static void
gw_cfg_json_parse_cjson_ruuvi_cfg(const cJSON* const p_json_root, gw_cfg_ruuvi_t* const p_ruuvi_cfg)
{
    gw_cfg_json_parse_remote(p_json_root, &p_ruuvi_cfg->remote);
    gw_cfg_json_parse_http(p_json_root, &p_ruuvi_cfg->http);
    gw_cfg_json_parse_http_stat(p_json_root, &p_ruuvi_cfg->http_stat);
    gw_cfg_json_parse_mqtt(p_json_root, &p_ruuvi_cfg->mqtt);
    gw_cfg_json_parse_lan_auth(p_json_root, &p_ruuvi_cfg->lan_auth);
    gw_cfg_json_parse_auto_update(p_json_root, &p_ruuvi_cfg->auto_update);
    gw_cfg_json_parse_ntp(p_json_root, &p_ruuvi_cfg->ntp);
    gw_cfg_json_parse_filter(p_json_root, &p_ruuvi_cfg->filter);
    gw_cfg_json_parse_scan(p_json_root, &p_ruuvi_cfg->scan);
    gw_cfg_json_parse_scan_filter(p_json_root, &p_ruuvi_cfg->scan_filter);
    if (!gw_cfg_json_copy_string_val(
            p_json_root,
            "coordinates",
            &p_ruuvi_cfg->coordinates.buf[0],
            sizeof(p_ruuvi_cfg->coordinates.buf)))
    {
        LOG_WARN("Can't find key '%s' in config-json", "coordinates");
    }
}

void
gw_cfg_json_parse_cjson(
    const cJSON* const          p_json_root,
    const char* const           p_log_title,
    gw_cfg_device_info_t* const p_dev_info,
    gw_cfg_ruuvi_t* const       p_ruuvi_cfg,
    gw_cfg_eth_t* const         p_eth_cfg,
    wifiman_config_ap_t* const  p_wifi_cfg_ap,
    wifiman_config_sta_t* const p_wifi_cfg_sta)
{
    if (NULL != p_log_title)
    {
        LOG_INFO("%s", p_log_title);
    }
    if (NULL != p_dev_info)
    {
        gw_cfg_json_parse_device_info(p_json_root, p_dev_info);
        if (NULL != p_log_title)
        {
            gw_cfg_log_device_info(p_dev_info, NULL);
        }
    }
    if (NULL != p_ruuvi_cfg)
    {
        gw_cfg_json_parse_cjson_ruuvi_cfg(p_json_root, p_ruuvi_cfg);
        if (NULL != p_log_title)
        {
            gw_cfg_log_ruuvi_cfg(p_ruuvi_cfg, NULL);
        }
    }
    if (NULL != p_eth_cfg)
    {
        gw_cfg_json_parse_eth(p_json_root, p_eth_cfg);
        if (NULL != p_log_title)
        {
            gw_cfg_log_eth_cfg(p_eth_cfg, NULL);
        }
    }

    if (NULL != p_wifi_cfg_ap)
    {
        const cJSON* const p_json_wifi_ap_cfg = cJSON_GetObjectItem(p_json_root, "wifi_ap_config");
        if (NULL == p_json_wifi_ap_cfg)
        {
            LOG_WARN("Can't find key '%s' in config-json", "wifi_ap_config");
        }
        else
        {
            gw_cfg_json_parse_cjson_wifi_ap_config(p_json_wifi_ap_cfg, &p_wifi_cfg_ap->wifi_config_ap);
            gw_cfg_json_parse_cjson_wifi_ap_settings(p_json_wifi_ap_cfg, &p_wifi_cfg_ap->wifi_settings_ap);
        }

        if (NULL != p_log_title)
        {
            gw_cfg_log_wifi_cfg_ap(p_wifi_cfg_ap, NULL);
        }
    }

    if (NULL != p_wifi_cfg_sta)
    {
        const cJSON* const p_json_wifi_sta_cfg = cJSON_GetObjectItem(p_json_root, "wifi_sta_config");
        if (NULL == p_json_wifi_sta_cfg)
        {
            LOG_WARN("Can't find key '%s' in config-json", "wifi_sta_config");
        }
        else
        {
            gw_cfg_json_parse_cjson_wifi_sta_config(p_json_wifi_sta_cfg, &p_wifi_cfg_sta->wifi_config_sta);
            gw_cfg_json_parse_cjson_wifi_sta_settings(p_json_wifi_sta_cfg, &p_wifi_cfg_sta->wifi_settings_sta);
        }

        if (NULL != p_log_title)
        {
            gw_cfg_log_wifi_cfg_sta(p_wifi_cfg_sta, NULL);
        }
    }
}

void
gw_cfg_json_parse_cjson_ruuvi(
    const cJSON* const    p_json_root,
    const char* const     p_log_title,
    gw_cfg_ruuvi_t* const p_ruuvi_cfg)
{
    gw_cfg_json_parse_cjson(p_json_root, p_log_title, NULL, p_ruuvi_cfg, NULL, NULL, NULL);
}

void
gw_cfg_json_parse_cjson_eth(
    const cJSON* const  p_json_root,
    const char* const   p_log_title,
    gw_cfg_eth_t* const p_eth_cfg)
{
    gw_cfg_json_parse_cjson(p_json_root, p_log_title, NULL, NULL, p_eth_cfg, NULL, NULL);
}

void
gw_cfg_json_parse_cjson_wifi_ap(
    const cJSON* const         p_json_root,
    const char* const          p_log_title,
    gw_cfg_eth_t* const        p_eth_cfg,
    wifiman_config_ap_t* const p_wifi_cfg_ap)
{
    gw_cfg_json_parse_cjson(p_json_root, p_log_title, NULL, NULL, p_eth_cfg, p_wifi_cfg_ap, NULL);
}

void
gw_cfg_json_parse_cjson_wifi_sta(
    const cJSON* const          p_json_root,
    const char* const           p_log_title,
    wifiman_config_sta_t* const p_wifi_cfg_sta)
{
    gw_cfg_json_parse_cjson(p_json_root, p_log_title, NULL, NULL, NULL, NULL, p_wifi_cfg_sta);
}

bool
gw_cfg_json_parse(
    const char* const p_json_name,
    const char* const p_log_title,
    const char* const p_json_str,
    gw_cfg_t* const   p_gw_cfg)
{
    if ('\0' == p_json_str[0])
    {
        LOG_WARN("%s is empty", p_json_name);
        return false;
    }

    cJSON* p_json_root = cJSON_Parse(p_json_str);
    if (NULL == p_json_root)
    {
        LOG_ERR("Failed to parse %s: %s", p_json_name, p_json_str);
        return false;
    }

    gw_cfg_json_parse_cjson(
        p_json_root,
        p_log_title,
        NULL,
        &p_gw_cfg->ruuvi_cfg,
        &p_gw_cfg->eth_cfg,
        &p_gw_cfg->wifi_cfg.ap,
        &p_gw_cfg->wifi_cfg.sta);

    cJSON_Delete(p_json_root);
    return true;
}
