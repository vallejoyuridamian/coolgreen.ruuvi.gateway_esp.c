/**
 * @file gw_cfg.h
 * @author TheSomeMan
 * @date 2020-10-31
 * @copyright Ruuvi Innovations Ltd, license BSD-3-Clause.
 */

#include "gw_cfg.h"
#include "gw_cfg_default.h"
#include <string.h>
#include <stdio.h>
#include "http_server_auth_type.h"
#include "nrf52fw.h"

#define LOG_LOCAL_LEVEL LOG_LEVEL_DEBUG
#include "log.h"

ruuvi_gateway_config_t g_gateway_config  = RUUVI_GATEWAY_DEFAULT_CONFIGURATION;
mac_address_bin_t      g_gw_mac_eth      = { 0 };
mac_address_str_t      g_gw_mac_eth_str  = { 0 };
mac_address_bin_t      g_gw_mac_wifi     = { 0 };
mac_address_str_t      g_gw_mac_wifi_str = { 0 };
mac_address_bin_t      g_gw_mac_sta      = { 0 };
mac_address_str_t      g_gw_mac_sta_str  = { 0 };
wifi_ssid_t            g_gw_wifi_ssid    = {
    .ssid_buf = DEFAULT_AP_SSID, // RuuviGatewayXXXX where XXXX - last 4 digits of the MAC-address
};

static const char TAG[] = "gw_cfg";

void
gw_cfg_init(void)
{
    g_gateway_config = g_gateway_config_default;
    memset(&g_gw_mac_eth, 0, sizeof(g_gw_mac_eth));
    memset(&g_gw_mac_eth_str, 0, sizeof(g_gw_mac_eth_str));
    memset(&g_gw_mac_wifi, 0, sizeof(g_gw_mac_wifi));
    memset(&g_gw_mac_wifi_str, 0, sizeof(g_gw_mac_wifi_str));
    memset(&g_gw_mac_sta, 0, sizeof(g_gw_mac_sta));
    memset(&g_gw_mac_sta_str, 0, sizeof(g_gw_mac_sta_str));
    memset(&g_gw_wifi_ssid, 0, sizeof(g_gw_wifi_ssid));
    snprintf(&g_gw_wifi_ssid.ssid_buf[0], sizeof(g_gw_wifi_ssid.ssid_buf), "%s", DEFAULT_AP_SSID);
}

void
gw_cfg_print_to_log(const ruuvi_gateway_config_t *p_config)
{
    LOG_INFO("Gateway SETTINGS:");
    LOG_INFO("config: use eth: %d", p_config->eth.use_eth);
    LOG_INFO("config: use eth dhcp: %d", p_config->eth.eth_dhcp);
    LOG_INFO("config: eth static ip: %s", p_config->eth.eth_static_ip);
    LOG_INFO("config: eth netmask: %s", p_config->eth.eth_netmask);
    LOG_INFO("config: eth gw: %s", p_config->eth.eth_gw);
    LOG_INFO("config: eth dns1: %s", p_config->eth.eth_dns1);
    LOG_INFO("config: eth dns2: %s", p_config->eth.eth_dns2);
    LOG_INFO("config: use mqtt: %d", p_config->mqtt.use_mqtt);
    LOG_INFO("config: mqtt server: %s", p_config->mqtt.mqtt_server);
    LOG_INFO("config: mqtt port: %u", p_config->mqtt.mqtt_port);
    LOG_INFO("config: mqtt prefix: %s", p_config->mqtt.mqtt_prefix);
    LOG_INFO("config: mqtt client id: %s", p_config->mqtt.mqtt_client_id);
    LOG_INFO("config: mqtt user: %s", p_config->mqtt.mqtt_user);
    LOG_INFO("config: mqtt password: %s", "********");
    LOG_INFO("config: use http: %d", p_config->http.use_http);
    LOG_INFO("config: http url: %s", p_config->http.http_url);
    LOG_INFO("config: http user: %s", p_config->http.http_user);
    LOG_INFO("config: http pass: %s", "********");
    LOG_INFO("config: LAN auth type: %s", p_config->lan_auth.lan_auth_type);
    LOG_INFO("config: LAN auth user: %s", p_config->lan_auth.lan_auth_user);
    LOG_INFO("config: LAN auth pass: %s", "********");

    switch (p_config->auto_update.auto_update_cycle)
    {
        case AUTO_UPDATE_CYCLE_TYPE_REGULAR:
            LOG_INFO("config: Auto update cycle: %s", AUTO_UPDATE_CYCLE_TYPE_STR_REGULAR);
            break;
        case AUTO_UPDATE_CYCLE_TYPE_BETA_TESTER:
            LOG_INFO("config: Auto update cycle: %s", AUTO_UPDATE_CYCLE_TYPE_STR_BETA_TESTER);
            break;
        case AUTO_UPDATE_CYCLE_TYPE_MANUAL:
            LOG_INFO("config: Auto update cycle: %s", AUTO_UPDATE_CYCLE_TYPE_STR_MANUAL);
            break;
        default:
            LOG_INFO(
                "config: Auto update cycle: %s (%d)",
                AUTO_UPDATE_CYCLE_TYPE_STR_MANUAL,
                p_config->auto_update.auto_update_cycle);
            break;
    }
    LOG_INFO("config: Auto update weekdays_bitmask: 0x%02x", p_config->auto_update.auto_update_weekdays_bitmask);
    LOG_INFO(
        "config: Auto update interval: %02u:00..%02u:00",
        p_config->auto_update.auto_update_interval_from,
        p_config->auto_update.auto_update_interval_to);
    LOG_INFO(
        "config: Auto update TZ: UTC%s%d",
        ((p_config->auto_update.auto_update_tz_offset_hours < 0) ? "" : "+"),
        (printf_int_t)p_config->auto_update.auto_update_tz_offset_hours);

    LOG_INFO("config: coordinates: %s", p_config->coordinates);
    LOG_INFO("config: use company id filter: %d", p_config->filter.company_filter);
    LOG_INFO("config: company id: 0x%04x", p_config->filter.company_id);
    LOG_INFO("config: use scan coded phy: %d", p_config->scan.scan_coded_phy);
    LOG_INFO("config: use scan 1mbit/phy: %d", p_config->scan.scan_1mbit_phy);
    LOG_INFO("config: use scan extended payload: %d", p_config->scan.scan_extended_payload);
    LOG_INFO("config: use scan channel 37: %d", p_config->scan.scan_channel_37);
    LOG_INFO("config: use scan channel 38: %d", p_config->scan.scan_channel_38);
    LOG_INFO("config: use scan channel 39: %d", p_config->scan.scan_channel_39);
}

static bool
gw_cfg_json_add_bool(cJSON *p_json_root, const char *p_item_name, const bool val)
{
    if (NULL == cJSON_AddBoolToObject(p_json_root, p_item_name, val))
    {
        LOG_ERR("Can't add json item: %s", p_item_name);
        return false;
    }
    return true;
}

static bool
gw_cfg_json_add_string(cJSON *p_json_root, const char *p_item_name, const char *p_val)
{
    if (NULL == cJSON_AddStringToObject(p_json_root, p_item_name, p_val))
    {
        LOG_ERR("Can't add json item: %s", p_item_name);
        return false;
    }
    return true;
}

static bool
gw_cfg_json_add_number(cJSON *p_json_root, const char *p_item_name, const cjson_number_t val)
{
    if (NULL == cJSON_AddNumberToObject(p_json_root, p_item_name, val))
    {
        LOG_ERR("Can't add json item: %s", p_item_name);
        return false;
    }
    return true;
}

static bool
gw_cfg_json_add_items_fw_version(cJSON *p_json_root, const char *const p_fw_ver, const char *const p_nrf52_fw_ver)
{
    if (!gw_cfg_json_add_string(p_json_root, "fw_ver", p_fw_ver))
    {
        return false;
    }
    if (!gw_cfg_json_add_string(p_json_root, "nrf52_fw_ver", p_nrf52_fw_ver))
    {
        return false;
    }
    return true;
}

static bool
gw_cfg_json_add_items_eth(cJSON *p_json_root, const ruuvi_gateway_config_t *p_cfg)
{
    if (!gw_cfg_json_add_bool(p_json_root, "use_eth", p_cfg->eth.use_eth))
    {
        return false;
    }
    if (!gw_cfg_json_add_bool(p_json_root, "eth_dhcp", p_cfg->eth.eth_dhcp))
    {
        return false;
    }
    if (!gw_cfg_json_add_string(p_json_root, "eth_static_ip", p_cfg->eth.eth_static_ip))
    {
        return false;
    }
    if (!gw_cfg_json_add_string(p_json_root, "eth_netmask", p_cfg->eth.eth_netmask))
    {
        return false;
    }
    if (!gw_cfg_json_add_string(p_json_root, "eth_gw", p_cfg->eth.eth_gw))
    {
        return false;
    }
    if (!gw_cfg_json_add_string(p_json_root, "eth_dns1", p_cfg->eth.eth_dns1))
    {
        return false;
    }
    if (!gw_cfg_json_add_string(p_json_root, "eth_dns2", p_cfg->eth.eth_dns2))
    {
        return false;
    }
    return true;
}

static bool
gw_cfg_json_add_items_http(cJSON *p_json_root, const ruuvi_gateway_config_t *p_cfg)
{
    if (!gw_cfg_json_add_bool(p_json_root, "use_http", p_cfg->http.use_http))
    {
        return false;
    }
    if (!gw_cfg_json_add_string(p_json_root, "http_url", p_cfg->http.http_url))
    {
        return false;
    }
    if (!gw_cfg_json_add_string(p_json_root, "http_user", p_cfg->http.http_user))
    {
        return false;
    }
    return true;
}

static bool
gw_cfg_json_add_items_lan_auth(cJSON *p_json_root, const ruuvi_gateway_config_t *p_cfg)
{
    if (!gw_cfg_json_add_string(p_json_root, "lan_auth_type", p_cfg->lan_auth.lan_auth_type))
    {
        return false;
    }
    if (!gw_cfg_json_add_string(p_json_root, "lan_auth_user", p_cfg->lan_auth.lan_auth_user))
    {
        return false;
    }
    return true;
}

static bool
gw_cfg_json_add_items_auto_update(cJSON *p_json_root, const ruuvi_gateway_config_t *p_cfg)
{
    const char *p_auto_update_cycle_str = AUTO_UPDATE_CYCLE_TYPE_STR_MANUAL;
    switch (p_cfg->auto_update.auto_update_cycle)
    {
        case AUTO_UPDATE_CYCLE_TYPE_REGULAR:
            p_auto_update_cycle_str = AUTO_UPDATE_CYCLE_TYPE_STR_REGULAR;
            break;
        case AUTO_UPDATE_CYCLE_TYPE_BETA_TESTER:
            p_auto_update_cycle_str = AUTO_UPDATE_CYCLE_TYPE_STR_BETA_TESTER;
            break;
        case AUTO_UPDATE_CYCLE_TYPE_MANUAL:
            p_auto_update_cycle_str = AUTO_UPDATE_CYCLE_TYPE_STR_MANUAL;
            break;
    }
    if (!gw_cfg_json_add_string(p_json_root, "auto_update_cycle", p_auto_update_cycle_str))
    {
        return false;
    }
    if (!gw_cfg_json_add_number(
            p_json_root,
            "auto_update_weekdays_bitmask",
            p_cfg->auto_update.auto_update_weekdays_bitmask))
    {
        return false;
    }
    if (!gw_cfg_json_add_number(p_json_root, "auto_update_interval_from", p_cfg->auto_update.auto_update_interval_from))
    {
        return false;
    }
    if (!gw_cfg_json_add_number(p_json_root, "auto_update_interval_to", p_cfg->auto_update.auto_update_interval_to))
    {
        return false;
    }
    if (!gw_cfg_json_add_number(
            p_json_root,
            "auto_update_tz_offset_hours",
            p_cfg->auto_update.auto_update_tz_offset_hours))
    {
        return false;
    }
    return true;
}

static bool
gw_cfg_json_add_items_mqtt(cJSON *p_json_root, const ruuvi_gateway_config_t *p_cfg)
{
    if (!gw_cfg_json_add_bool(p_json_root, "use_mqtt", p_cfg->mqtt.use_mqtt))
    {
        return false;
    }
    if (!gw_cfg_json_add_string(p_json_root, "mqtt_server", p_cfg->mqtt.mqtt_server))
    {
        return false;
    }
    if (!gw_cfg_json_add_number(p_json_root, "mqtt_port", p_cfg->mqtt.mqtt_port))
    {
        return false;
    }
    if (!gw_cfg_json_add_string(p_json_root, "mqtt_prefix", p_cfg->mqtt.mqtt_prefix))
    {
        return false;
    }
    if (!gw_cfg_json_add_string(p_json_root, "mqtt_client_id", p_cfg->mqtt.mqtt_client_id))
    {
        return false;
    }
    if (!gw_cfg_json_add_string(p_json_root, "mqtt_user", p_cfg->mqtt.mqtt_user))
    {
        return false;
    }
#if 0
    // Don't send to browser because of security
    if (!gw_cfg_json_add_string(p_json_root, "mqtt_pass", p_cfg->mqtt_pass))
    {
        return false;
    }
#endif
    return true;
}

static bool
gw_cfg_json_add_items_filter(cJSON *p_json_root, const ruuvi_gateway_config_t *p_cfg)
{
    if (!gw_cfg_json_add_bool(p_json_root, "use_filtering", p_cfg->filter.company_filter))
    {
        return false;
    }
    char company_id[10];
    snprintf(company_id, sizeof(company_id), "0x%04x", p_cfg->filter.company_id);
    if (!gw_cfg_json_add_string(p_json_root, "company_id", company_id))
    {
        return false;
    }
    return true;
}

static bool
gw_cfg_json_add_items_scan(cJSON *p_json_root, const ruuvi_gateway_config_t *p_cfg)
{
    if (!gw_cfg_json_add_bool(p_json_root, "use_coded_phy", p_cfg->scan.scan_coded_phy))
    {
        return false;
    }
    if (!gw_cfg_json_add_bool(p_json_root, "use_1mbit_phy", p_cfg->scan.scan_1mbit_phy))
    {
        return false;
    }
    if (!gw_cfg_json_add_bool(p_json_root, "use_extended_payload", p_cfg->scan.scan_extended_payload))
    {
        return false;
    }
    if (!gw_cfg_json_add_bool(p_json_root, "use_channel_37", p_cfg->scan.scan_channel_37))
    {
        return false;
    }
    if (!gw_cfg_json_add_bool(p_json_root, "use_channel_38", p_cfg->scan.scan_channel_38))
    {
        return false;
    }
    if (!gw_cfg_json_add_bool(p_json_root, "use_channel_39", p_cfg->scan.scan_channel_39))
    {
        return false;
    }
    return true;
}

static bool
gw_cfg_json_add_items(
    cJSON *                       p_json_root,
    const ruuvi_gateway_config_t *p_cfg,
    const mac_address_str_t *     p_mac_sta,
    const char *const             p_fw_ver,
    const char *const             p_nrf52_fw_ver)
{
    if (!gw_cfg_json_add_items_fw_version(p_json_root, p_fw_ver, p_nrf52_fw_ver))
    {
        return false;
    }
    if (!gw_cfg_json_add_items_eth(p_json_root, p_cfg))
    {
        return false;
    }
    if (!gw_cfg_json_add_items_http(p_json_root, p_cfg))
    {
        return false;
    }
    if (!gw_cfg_json_add_items_mqtt(p_json_root, p_cfg))
    {
        return false;
    }
    if (!gw_cfg_json_add_items_lan_auth(p_json_root, p_cfg))
    {
        return false;
    }
    if (!gw_cfg_json_add_items_auto_update(p_json_root, p_cfg))
    {
        return false;
    }
    if (!gw_cfg_json_add_string(p_json_root, "gw_mac", p_mac_sta->str_buf))
    {
        return false;
    }
    if (!gw_cfg_json_add_items_filter(p_json_root, p_cfg))
    {
        return false;
    }
    if (!gw_cfg_json_add_string(p_json_root, "coordinates", p_cfg->coordinates))
    {
        return false;
    }
    if (!gw_cfg_json_add_items_scan(p_json_root, p_cfg))
    {
        return false;
    }
    return true;
}

bool
gw_cfg_generate_json_str(cjson_wrap_str_t *p_json_str, const char *const p_fw_ver, const char *const p_nrf52_fw_ver)
{
    const ruuvi_gateway_config_t *p_cfg     = &g_gateway_config;
    const mac_address_str_t *     p_mac_sta = &g_gw_mac_sta_str;

    p_json_str->p_str = NULL;

    cJSON *p_json_root = cJSON_CreateObject();
    if (NULL == p_json_root)
    {
        LOG_ERR("Can't create json object");
        return false;
    }
    if (!gw_cfg_json_add_items(p_json_root, p_cfg, p_mac_sta, p_fw_ver, p_nrf52_fw_ver))
    {
        cjson_wrap_delete(&p_json_root);
        return false;
    }

    *p_json_str = cjson_wrap_print_and_delete(&p_json_root);
    if (NULL == p_json_str->p_str)
    {
        LOG_ERR("Can't create json string");
        return false;
    }
    return true;
}
