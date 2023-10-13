/**
 * @file mqtt.c
 * @author Jukka Saari
 * @date 2019-11-27
 * @copyright Ruuvi Innovations Ltd, license BSD-3-Clause.
 */

#include "mqtt.h"
#include <esp_task_wdt.h>
#include "esp_err.h"
#include "cJSON.h"
#include "cjson_wrap.h"
#include "mqtt_client.h"
#include "ruuvi_gateway.h"
#include "mqtt_json.h"
#include "leds.h"
#include "fw_update.h"
#include "os_mutex.h"
#include "gw_mac.h"
#include "esp_crt_bundle.h"
#include "gw_status.h"
#include "os_malloc.h"
#include "esp_tls.h"
#include "snprintf_with_esp_err_desc.h"
#include "gw_cfg_storage.h"
// coolgreen terminal communication addition
#include "terminal.h"
#include "api.h"
//#include "ruuvi_endpoint_ca_uart.h"

#define LOG_LOCAL_LEVEL LOG_LEVEL_INFO
#include "log.h"

#if (LOG_LOCAL_LEVEL >= LOG_LEVEL_DEBUG)
#warning Debug log level prints out the passwords as a "plaintext".
#endif

#define TOPIC_LEN 512

// COOLGREEN MODIFICATION //
#define MESSAGE_LEN 512

#define MQTT_NETWORK_TIMEOUT_MS (10U * 1000U)

#define MQTT_TASK_STACK_SIZE (4352U)

typedef int mqtt_message_id_t;

typedef int esp_mqtt_client_data_len_t;

typedef struct mqtt_topic_buf_t
{
    char buf[TOPIC_LEN];
} mqtt_topic_buf_t;

#define MQTT_PROTECTED_DATA_ERR_MSG_SIZE 120

typedef struct mqtt_protected_data_t
{
    esp_mqtt_client_handle_t   p_mqtt_client;
    mqtt_topic_buf_t           mqtt_topic;
    ruuvi_gw_cfg_mqtt_prefix_t mqtt_prefix;
    bool                       mqtt_disable_retained_messages;
    char                       err_msg[MQTT_PROTECTED_DATA_ERR_MSG_SIZE];
    str_buf_t                  str_buf_server_cert_mqtt;
    str_buf_t                  str_buf_client_cert;
    str_buf_t                  str_buf_client_key;
} mqtt_protected_data_t;

static bool                  g_mqtt_mutex_initialized = false;
static os_mutex_t            g_mqtt_mutex;
static os_mutex_static_t     g_mqtt_mutex_mem;
static mqtt_protected_data_t g_mqtt_data;

static const char* TAG = "MQTT";

static mqtt_protected_data_t*
mqtt_mutex_lock(void)
{
    if (!g_mqtt_mutex_initialized)
    {
        g_mqtt_mutex             = os_mutex_create_static(&g_mqtt_mutex_mem);
        g_mqtt_mutex_initialized = true;
    }
    os_mutex_lock(g_mqtt_mutex);
    return &g_mqtt_data;
}

static void
mqtt_mutex_unlock(mqtt_protected_data_t** const p_p_data)
{
    *p_p_data = NULL;
    os_mutex_unlock(g_mqtt_mutex);
}

static void
mqtt_create_full_topic(
    mqtt_topic_buf_t* const p_full_topic,
    const char* const       p_prefix_str,
    const char* const       p_topic_str)
{
    if ((NULL == p_full_topic) || (NULL == p_topic_str))
    {
        LOG_ERR("null arguments");
        return;
    }

    if ((NULL != p_prefix_str) && ('\0' != p_prefix_str[0]))
    {
        snprintf(p_full_topic->buf, sizeof(p_full_topic->buf), "%s%s", p_prefix_str, p_topic_str);
    }
    else
    {
        snprintf(p_full_topic->buf, sizeof(p_full_topic->buf), "%s", p_topic_str);
    }
}

// coolgreen addition THIS FUNCTION WILL NOT BE USED 
/*void
sendMessageToCoprocessor(char *topic_event , char *message)
{
  // coolgreen fill in here
  //topic_event ruuvi/DD:F0:9C:43:09:16/commands/F2:F5:0E:C4:1E:28
  //message LED_ON
  
  // coolgreen here
  //re_ca_uart_encode(buffer, buf_len, payload);
  LOG_INFO("Sending data to coprocessor");
  //uint8_t data[] = {0x01, 0x02, 0x03};
  uint8_t data[] = {0xCA, 0x15, 0x21, 0xF2, 0xF5, 0x0E, 0xC4, 0x1E, 0x28, 0x2C, 0x0B, 0x2C, 0x2C, 0x02, 0x01, 0x04, 0x05,0x06, 0x07,
      0x08, 0x09, 0xFF, 0x0B, 0x2C, 0x3D, 0xD1, 0x0A};

  // OK, so the LED control should make the data 0xCA, whatever the length is, the LED command
  // then I should make the function to get the MACID

  // So CA is the command intiation
  // 0x15 is the length (needs to be recalculated, didn't change it, so it is still 21)
  // The command is send to nus, 0x21
  // MACID = F2:F5:0E:C4:1E:28
  // 2C is separator
  // MSG_LEN = 11 (0x0B)
  // 2C is separator
  // 2C is command again (hopefully not interpreted as separator)
  // MSG = 0x02,0x01, 0x04,0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0x0B (not 0x0A because it is end of line)
  // 2C is separator
  // CRC
  // EOL 0x0A    

  char dummy_buffer[17];
  char *macid_str = strrchr(topic_event, '/') + 1; // Get last subtopic
  // Convert MACID from string to hex values and store in uart_payload.params.adv.adv
  for (int i = 0; i < 6; i++) {
      char hex_pair[3]; // To hold each pair of hex characters
      hex_pair[0] = macid_str[i * 3];
      hex_pair[1] = macid_str[i * 3 + 1];
      hex_pair[2] = '\0'; // Null-terminate the string
      dummy_buffer[i] = (uint8_t)strtol(hex_pair, NULL, 16);
  }
  // OK, so I have the MACID (whose length is always 6) and now I need
  // to get in the message length (that is at least 11) and the message itself
  // which all together cannot be longer than 31, so the maximum message length is 24 bytes
  // I will convert
  // So the message will not be LED_ON, it will be 0x2CFF010000000000000000
  // So that I can get the length, command, and payload from it
  // so maybe the length is always 11, source, destination, command, 8 bytes of payload
  // so if it is a LED command (2C) I will only check the first byte of the payload
  // turn on if it is 01, off if it is 00
  // So I will not even ask for the length, it will be 0x0B
  // then the string 2CFF010000000000000000 will be decoded into the rest of the adv
  // so let's assume we got that string, length 11, and we will put it nex to the mac
  // with another for
  for (int i = 0; i < 11; i++) {
      char hex_pair[3]; // To hold each pair of hex characters
      hex_pair[0] = message[i * 2];
      hex_pair[1] = message[i * 2 + 1];
      hex_pair[2] = '\0'; // Null-terminate the string
      dummy_buffer[i + 6] = (uint8_t)strtol(hex_pair, NULL, 16);
  }
 
  char values_str[3 * 17 + 1]; // Assuming each byte takes up to 3 characters (2 characters + space)
  // Store values in the string
  int index = 0;
  for (int i = 0; i < 17; i++) {
      index += snprintf(values_str + index, sizeof(values_str) - index, "%02X ", (unsigned int)dummy_buffer[i]);
  }

  // Print the values string
  LOG_INFO("Contents of dummy_buffer: %s\n", values_str);

  LOG_INFO("Contents of dummy_buffer:");
    for (int i = 0; i < 17; i++) {
      LOG_INFO("%02X ", (unsigned int)dummy_buffer[i]);
  }
 
  //uint8_t size = sizeof(data);
  
  //int res = terminal_send_msg(data,size);
  // coolgreen fill in here
  // OK so here in the dummy_buffer I have the MACID (6 bytes) and the message (11 bytes)
  // I need to make the rest of the message then
  // So I need a function, like the encode nus or something like that
  // So I cannot use re_ca_uart_encode_send_msg_to_nus because it is static
  // I need to tall the encode that will call it
  re_status_t res;
  // so here I have to make the payload and the encode will put it into the buffer
  // coolgreen come back here

  re_ca_uart_payload_t uart_payload = { 0 };
  uint8_t              data[BUFFER_PAYLOAD_SIZE];
  uint8_t              data_length;

  print_dbgmsgnoarg("Enter\n");

  uart_payload.cmd = (re_ca_uart_cmd_t)cmd;

  res =  re_ca_uart_encode (buffer, buf_len, payload)


  LOG_INFO("Sent data, got response res=%d",res);
    
}
*/


bool
mqtt_publish_adv(const adv_report_t* const p_adv, const bool flag_use_timestamps, const time_t timestamp)
{
    cjson_wrap_str_t json_str = cjson_wrap_str_null();
    const gw_cfg_t*  p_gw_cfg = gw_cfg_lock_ro();
    const bool       res      = mqtt_create_json_str(
        p_adv,
        flag_use_timestamps,
        timestamp,
        gw_cfg_get_nrf52_mac_addr(),
        p_gw_cfg->ruuvi_cfg.coordinates.buf,
        &json_str);
    gw_cfg_unlock_ro(&p_gw_cfg);
    if (!res)
    {
        LOG_ERR("%s failed", "mqtt_create_json_str");
        return false;
    }

    const mac_address_str_t tag_mac_str = mac_address_to_str(&p_adv->tag_mac);

    mqtt_protected_data_t* p_mqtt_data = mqtt_mutex_lock();
    if (NULL == p_mqtt_data->p_mqtt_client)
    {
        LOG_ERR("Can't send advs - MQTT was stopped");
        mqtt_mutex_unlock(&p_mqtt_data);
        cjson_wrap_free_json_str(&json_str);
        return false;
    }
    mqtt_create_full_topic(&p_mqtt_data->mqtt_topic, p_mqtt_data->mqtt_prefix.buf, tag_mac_str.str_buf);

    LOG_DBG("publish: topic: %s, data: %s", p_mqtt_data->mqtt_topic.buf, json_str.p_str);
    const int32_t mqtt_len              = 0;
    const int32_t mqtt_qos              = 1;
    const int32_t mqtt_flag_retain      = 0;
    bool          is_publish_successful = false;

    if (esp_mqtt_client_publish(
            p_mqtt_data->p_mqtt_client,
            p_mqtt_data->mqtt_topic.buf,
            json_str.p_str,
            mqtt_len,
            mqtt_qos,
            mqtt_flag_retain)
        >= 0)
    {
        is_publish_successful = true;
    }
    mqtt_mutex_unlock(&p_mqtt_data);

    cjson_wrap_free_json_str(&json_str);
    return is_publish_successful;
}

void
mqtt_publish_connect(void)
{
    char* p_message = "{\"state\": \"online\"}";

    mqtt_protected_data_t* p_mqtt_data = mqtt_mutex_lock();
    mqtt_create_full_topic(&p_mqtt_data->mqtt_topic, p_mqtt_data->mqtt_prefix.buf, "gw_status");
    LOG_INFO("esp_mqtt_client_publish: topic:'%s', message:'%s'", p_mqtt_data->mqtt_topic.buf, p_message);
    const int32_t mqtt_qos         = 1;
    const int32_t mqtt_flag_retain = !p_mqtt_data->mqtt_disable_retained_messages;

    const mqtt_message_id_t message_id = esp_mqtt_client_publish(
        p_mqtt_data->p_mqtt_client,
        p_mqtt_data->mqtt_topic.buf,
        p_message,
        (esp_mqtt_client_data_len_t)strlen(p_message),
        mqtt_qos,
        mqtt_flag_retain);

    mqtt_mutex_unlock(&p_mqtt_data);

    if (-1 == message_id)
    {
        LOG_ERR("esp_mqtt_client_publish failed");
    }
    else
    {
        LOG_INFO("esp_mqtt_client_publish: message_id=%d", message_id);
    }
}

static void
mqtt_publish_state_offline(mqtt_protected_data_t* const p_mqtt_data)
{
    char* p_message = "{\"state\": \"offline\"}";

    mqtt_create_full_topic(&p_mqtt_data->mqtt_topic, p_mqtt_data->mqtt_prefix.buf, "gw_status");
    LOG_INFO("esp_mqtt_client_publish: topic:'%s', message:'%s'", p_mqtt_data->mqtt_topic.buf, p_message);
    const int32_t mqtt_qos         = 1;
    const int32_t mqtt_flag_retain = !p_mqtt_data->mqtt_disable_retained_messages;

    const mqtt_message_id_t message_id = esp_mqtt_client_publish(
        p_mqtt_data->p_mqtt_client,
        p_mqtt_data->mqtt_topic.buf,
        p_message,
        (esp_mqtt_client_data_len_t)strlen(p_message),
        mqtt_qos,
        mqtt_flag_retain);

    if (-1 == message_id)
    {
        LOG_ERR("esp_mqtt_client_publish failed");
    }
    else
    {
        LOG_INFO("esp_mqtt_client_publish: message_id=%d", message_id);
    }
}

static const char*
mqtt_connect_return_code_to_str(const esp_mqtt_connect_return_code_t connect_return_code)
{
    switch (connect_return_code)
    {
        case MQTT_CONNECTION_ACCEPTED:
            return "MQTT_CONNECTION_ACCEPTED";
        case MQTT_CONNECTION_REFUSE_PROTOCOL:
            return "MQTT_CONNECTION_REFUSE_PROTOCOL";
        case MQTT_CONNECTION_REFUSE_ID_REJECTED:
            return "MQTT_CONNECTION_REFUSE_ID_REJECTED";
        case MQTT_CONNECTION_REFUSE_SERVER_UNAVAILABLE:
            return "MQTT_CONNECTION_REFUSE_SERVER_UNAVAILABLE";
        case MQTT_CONNECTION_REFUSE_BAD_USERNAME:
            return "MQTT_CONNECTION_REFUSE_BAD_USERNAME";
        case MQTT_CONNECTION_REFUSE_NOT_AUTHORIZED:
            return "MQTT_CONNECTION_REFUSE_NOT_AUTHORIZED";
    }
    return "Unknown";
}

static void
mqtt_event_handler_on_error(
    mqtt_protected_data_t* const        p_mqtt_protected_data,
    const esp_mqtt_error_codes_t* const p_error_handle)
{
    p_mqtt_protected_data->err_msg[0] = '\0';

    mqtt_error_e                         mqtt_error               = MQTT_ERROR_NONE;
    const esp_err_t                      esp_tls_last_esp_err     = p_error_handle->esp_tls_last_esp_err;
    const esp_mqtt_error_type_t          error_type               = p_error_handle->error_type;
    const int                            esp_transport_sock_errno = p_error_handle->esp_transport_sock_errno;
    const esp_mqtt_connect_return_code_t connect_return_code      = p_error_handle->connect_return_code;
    const char* const                    p_connect_ret_code_desc = mqtt_connect_return_code_to_str(connect_return_code);
    if (MQTT_ERROR_TYPE_TCP_TRANSPORT == error_type)
    {
        if (ESP_ERR_ESP_TLS_CANNOT_RESOLVE_HOSTNAME == esp_tls_last_esp_err)
        {
            LOG_ERR("MQTT_EVENT_ERROR (MQTT_ERROR_TYPE_TCP_TRANSPORT): ESP_ERR_ESP_TLS_CANNOT_RESOLVE_HOSTNAME");
            mqtt_error = MQTT_ERROR_DNS;
            (void)snprintf(
                p_mqtt_protected_data->err_msg,
                sizeof(p_mqtt_protected_data->err_msg),
                "Failed to resolve hostname");
        }
        else if (ESP_ERR_ESP_TLS_FAILED_CONNECT_TO_HOST == esp_tls_last_esp_err)
        {
            LOG_ERR("MQTT_EVENT_ERROR (MQTT_ERROR_TYPE_TCP_TRANSPORT): ESP_ERR_ESP_TLS_FAILED_CONNECT_TO_HOST");
            mqtt_error = MQTT_ERROR_CONNECT;
            (void)snprintf_with_esp_err_desc(
                esp_transport_sock_errno,
                p_mqtt_protected_data->err_msg,
                sizeof(p_mqtt_protected_data->err_msg),
                "Failed to connect to host");
        }
        else
        {
            if (0 != esp_tls_last_esp_err)
            {
                str_buf_t err_desc = esp_err_to_name_with_alloc_str_buf(esp_tls_last_esp_err);
                LOG_ERR(
                    "MQTT_EVENT_ERROR (MQTT_ERROR_TYPE_TCP_TRANSPORT): %d (%s)",
                    esp_tls_last_esp_err,
                    (NULL != err_desc.buf) ? err_desc.buf : "");
                (void)snprintf(
                    p_mqtt_protected_data->err_msg,
                    sizeof(p_mqtt_protected_data->err_msg),
                    "Error %d (%s)",
                    esp_tls_last_esp_err,
                    (NULL != err_desc.buf) ? err_desc.buf : "");
                str_buf_free_buf(&err_desc);
            }
            else if (0 != esp_transport_sock_errno)
            {
                str_buf_t err_desc = esp_err_to_name_with_alloc_str_buf(esp_transport_sock_errno);
                LOG_ERR(
                    "MQTT_EVENT_ERROR (MQTT_ERROR_TYPE_TCP_TRANSPORT): %d (%s)",
                    esp_transport_sock_errno,
                    (NULL != err_desc.buf) ? err_desc.buf : "");
                (void)snprintf(
                    p_mqtt_protected_data->err_msg,
                    sizeof(p_mqtt_protected_data->err_msg),
                    "%s",
                    (NULL != err_desc.buf) ? err_desc.buf : "");
                str_buf_free_buf(&err_desc);
            }
            else
            {
                LOG_ERR("MQTT_EVENT_ERROR (MQTT_ERROR_TYPE_TCP_TRANSPORT): Unknown error");
                (void)snprintf(p_mqtt_protected_data->err_msg, sizeof(p_mqtt_protected_data->err_msg), "Unknown error");
            }
            mqtt_error = MQTT_ERROR_CONNECT;
        }
    }
    else if (MQTT_ERROR_TYPE_CONNECTION_REFUSED == error_type)
    {
        LOG_ERR(
            "MQTT_EVENT_ERROR (MQTT_ERROR_TYPE_CONNECTION_REFUSED): connect_return_code=%d (%s)",
            connect_return_code,
            p_connect_ret_code_desc);
        if ((MQTT_CONNECTION_REFUSE_BAD_USERNAME == connect_return_code)
            || (MQTT_CONNECTION_REFUSE_NOT_AUTHORIZED == connect_return_code))
        {
            mqtt_error = MQTT_ERROR_AUTH;
        }
        else
        {
            mqtt_error = MQTT_ERROR_CONNECT;
        }
        (void)snprintf(
            p_mqtt_protected_data->err_msg,
            sizeof(p_mqtt_protected_data->err_msg),
            "Refusal to connect: %s",
            p_connect_ret_code_desc);
    }
    else
    {
        LOG_ERR(
            "MQTT_EVENT_ERROR (unknown error_type=%d): connect_return_code=%d (%s), "
            "esp_transport_sock_errno=%d, esp_tls_last_esp_err=%d",
            error_type,
            connect_return_code,
            p_connect_ret_code_desc,
            esp_transport_sock_errno,
            esp_tls_last_esp_err);
        mqtt_error = MQTT_ERROR_CONNECT;
        (void)snprintf(
            p_mqtt_protected_data->err_msg,
            sizeof(p_mqtt_protected_data->err_msg),
            "Failed to connect (Unknown error type)");
    }
    gw_status_set_mqtt_error(mqtt_error);
}

static esp_err_t
mqtt_event_handler(esp_mqtt_event_handle_t h_event)
{
    mqtt_protected_data_t* const p_mqtt_protected_data = h_event->user_context;
    switch (h_event->event_id)
    {
        case MQTT_EVENT_CONNECTED:
            LOG_INFO("MQTT_EVENT_CONNECTED");
            gw_status_set_mqtt_connected();
            main_task_send_sig_mqtt_publish_connect();
            leds_notify_mqtt1_connected();

            // COOLGREEN MODIFICATION //
            /* Here we subscribe to all the subjects that are 
            ruuvi/GW_MACID/commands/ (under this there will be
            the CONTROLLER_ID) */
            char topic[50];
            const mac_address_str_t *mac_address = gw_cfg_get_nrf52_mac_addr();
            sprintf(topic, "ruuvi/%s/commands/#", mac_address->str_buf);
            LOG_INFO("Subscribing to topics: %s", topic);
            esp_mqtt_client_subscribe(p_mqtt_protected_data->p_mqtt_client, topic, 1);

            if (!fw_update_mark_app_valid_cancel_rollback())
            {
                LOG_ERR("%s failed", "fw_update_mark_app_valid_cancel_rollback");
            }
            break;

        case MQTT_EVENT_DISCONNECTED:
            LOG_INFO("MQTT_EVENT_DISCONNECTED");
            gw_status_clear_mqtt_connected();
            leds_notify_mqtt1_disconnected();
            break;

        case MQTT_EVENT_SUBSCRIBED:
            LOG_INFO("MQTT_EVENT_SUBSCRIBED, msg_id=%d", h_event->msg_id);
            break;

        case MQTT_EVENT_UNSUBSCRIBED:
            LOG_INFO("MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", h_event->msg_id);
            break;

        case MQTT_EVENT_PUBLISHED:
            LOG_DBG("MQTT_EVENT_PUBLISHED, msg_id=%d", h_event->msg_id);
            break;

        case MQTT_EVENT_DATA:
            LOG_INFO("MQTT_EVENT_DATA");

            // COOLGREEN MODIFICATION //
            /* Here we should parse the message info and send it to the controller */
            /* So next step here is to print out the message's content */
            char topic_event[TOPIC_LEN];
            char message[MESSAGE_LEN];
            memcpy(topic_event, h_event->topic, h_event->topic_len);
            memcpy(message, h_event->data, h_event->data_len);
            topic_event[h_event->topic_len] = '\0';
            message[h_event->data_len] = '\0';

            // Extract the controller string from the topic
            char* controller_str = strrchr(topic_event, '/');
            if (controller_str != NULL) {
                controller_str++;  // Skip the '/'
                LOG_INFO("Controller: %s", controller_str);
            }

            // Log topic and message content
            LOG_INFO("Received message on topic: %s", topic_event);
            LOG_INFO("Message content: %s", message);

            // OK, so here I will write to the console asking to turn on the LED in case the
            // message is that of course
            //sendMessageToCoprocessor(topic_event,message);
            int res = api_send_to_nus(topic_event, message);
            LOG_INFO("Got res from API: %d", res);
            break;

        case MQTT_EVENT_ERROR:
            mqtt_event_handler_on_error(p_mqtt_protected_data, h_event->error_handle);
            break;

        case MQTT_EVENT_BEFORE_CONNECT:
            LOG_INFO("MQTT_EVENT_BEFORE_CONNECT");
            break;

        default:
            LOG_INFO("Other event id:%d", h_event->event_id);
            break;
    }
    return ESP_OK;
}

static esp_mqtt_transport_t
mqtt_transport_name_to_code(const char* const p_mqtt_transport_name)
{
    esp_mqtt_transport_t mqtt_transport = MQTT_TRANSPORT_OVER_TCP;
    if (0 == strcmp(p_mqtt_transport_name, MQTT_TRANSPORT_TCP))
    {
        mqtt_transport = MQTT_TRANSPORT_OVER_TCP;
    }
    else if (0 == strcmp(p_mqtt_transport_name, MQTT_TRANSPORT_SSL))
    {
        mqtt_transport = MQTT_TRANSPORT_OVER_SSL;
    }
    else if (0 == strcmp(p_mqtt_transport_name, MQTT_TRANSPORT_WS))
    {
        mqtt_transport = MQTT_TRANSPORT_OVER_WS;
    }
    else if (0 == strcmp(p_mqtt_transport_name, MQTT_TRANSPORT_WSS))
    {
        mqtt_transport = MQTT_TRANSPORT_OVER_WSS;
    }
    else
    {
        LOG_WARN("Unknown MQTT transport='%s', use TCP", p_mqtt_transport_name);
    }
    return mqtt_transport;
}

static void
mqtt_generate_client_config(
    esp_mqtt_client_config_t* const  p_cli_cfg,
    const ruuvi_gw_cfg_mqtt_t* const p_mqtt_cfg,
    const mqtt_topic_buf_t* const    p_mqtt_topic,
    const char* const                p_lwt_message,
    const char* const                p_cert_pem,
    const char* const                p_client_cert_pem,
    const char* const                p_client_key_pem,
    void* const                      p_user_context)
{
    p_cli_cfg->event_handle                = &mqtt_event_handler;
    p_cli_cfg->event_loop_handle           = NULL;
    p_cli_cfg->host                        = p_mqtt_cfg->mqtt_server.buf;
    p_cli_cfg->uri                         = NULL;
    p_cli_cfg->port                        = p_mqtt_cfg->mqtt_port;
    p_cli_cfg->client_id                   = p_mqtt_cfg->mqtt_client_id.buf;
    p_cli_cfg->username                    = p_mqtt_cfg->mqtt_user.buf;
    p_cli_cfg->password                    = p_mqtt_cfg->mqtt_pass.buf;
    p_cli_cfg->lwt_topic                   = p_mqtt_cfg->mqtt_disable_retained_messages ? NULL : p_mqtt_topic->buf;
    p_cli_cfg->lwt_msg                     = p_mqtt_cfg->mqtt_disable_retained_messages ? NULL : p_lwt_message;
    p_cli_cfg->lwt_qos                     = 1;
    p_cli_cfg->lwt_retain                  = !p_mqtt_cfg->mqtt_disable_retained_messages;
    p_cli_cfg->lwt_msg_len                 = 0;
    p_cli_cfg->disable_clean_session       = 0;
    p_cli_cfg->keepalive                   = 0;
    p_cli_cfg->disable_auto_reconnect      = false;
    p_cli_cfg->user_context                = p_user_context;
    p_cli_cfg->task_prio                   = 0;
    p_cli_cfg->task_stack                  = MQTT_TASK_STACK_SIZE;
    p_cli_cfg->buffer_size                 = 0;
    p_cli_cfg->cert_pem                    = p_cert_pem;
    p_cli_cfg->cert_len                    = 0;
    p_cli_cfg->client_cert_pem             = p_client_cert_pem;
    p_cli_cfg->client_cert_len             = 0;
    p_cli_cfg->client_key_pem              = p_client_key_pem;
    p_cli_cfg->client_key_len              = 0;
    p_cli_cfg->transport                   = mqtt_transport_name_to_code(p_mqtt_cfg->mqtt_transport.buf);
    p_cli_cfg->refresh_connection_after_ms = 0;
    p_cli_cfg->psk_hint_key                = NULL;
    p_cli_cfg->use_global_ca_store         = false;
    p_cli_cfg->crt_bundle_attach           = &esp_crt_bundle_attach;
    p_cli_cfg->reconnect_timeout_ms        = 0;
    p_cli_cfg->alpn_protos                 = NULL;
    p_cli_cfg->clientkey_password          = NULL;
    p_cli_cfg->clientkey_password_len      = 0;
    p_cli_cfg->protocol_ver                = MQTT_PROTOCOL_UNDEFINED;
    p_cli_cfg->out_buffer_size             = 0;
    p_cli_cfg->skip_cert_common_name_check = false;
    p_cli_cfg->use_secure_element          = false;
    p_cli_cfg->ds_data                     = NULL;
    p_cli_cfg->network_timeout_ms          = MQTT_NETWORK_TIMEOUT_MS;
    p_cli_cfg->disable_keepalive           = false;
    p_cli_cfg->path                        = NULL;
}

static esp_mqtt_client_config_t*
mqtt_create_client_config(mqtt_protected_data_t* p_mqtt_data, const ruuvi_gw_cfg_mqtt_t* const p_mqtt_cfg)
{
    esp_mqtt_client_config_t* const p_cli_cfg = os_calloc(1, sizeof(*p_cli_cfg));
    if (NULL == p_cli_cfg)
    {
        LOG_ERR("Can't allocate memory");
        return NULL;
    }
    mqtt_create_full_topic(&p_mqtt_data->mqtt_topic, p_mqtt_cfg->mqtt_prefix.buf, "gw_status");
    p_mqtt_data->mqtt_prefix                    = p_mqtt_cfg->mqtt_prefix;
    p_mqtt_data->mqtt_disable_retained_messages = p_mqtt_cfg->mqtt_disable_retained_messages;
    const char* const p_lwt_message             = "{\"state\": \"offline\"}";

    LOG_INFO(
        "Using server: %s, client id: '%s', topic prefix: '%s', port: %u",
        p_mqtt_cfg->mqtt_server.buf,
        p_mqtt_cfg->mqtt_client_id.buf,
        p_mqtt_cfg->mqtt_prefix.buf,
        p_mqtt_cfg->mqtt_port);
    LOG_INFO(
        "Authentication: user: '%s', password: '%s'",
        p_mqtt_cfg->mqtt_user.buf,
        (LOG_LOCAL_LEVEL >= LOG_LEVEL_DEBUG) ? p_mqtt_cfg->mqtt_pass.buf : "******");
    LOG_INFO(
        "Certificates: use_ssl_client_cert=%d, use_ssl_server_cert=%d",
        p_mqtt_cfg->use_ssl_client_cert,
        p_mqtt_cfg->use_ssl_server_cert);
    LOG_DBG(
        "server_cert_mqtt: %s",
        p_mqtt_data->str_buf_server_cert_mqtt.buf ? p_mqtt_data->str_buf_server_cert_mqtt.buf : "NULL");
    LOG_DBG(
        "client_cert_mqtt: %s",
        p_mqtt_data->str_buf_client_cert.buf ? p_mqtt_data->str_buf_client_cert.buf : "NULL");
    LOG_DBG("client_key_mqtt: %s", p_mqtt_data->str_buf_client_key.buf ? p_mqtt_data->str_buf_client_key.buf : "NULL");

    mqtt_generate_client_config(
        p_cli_cfg,
        p_mqtt_cfg,
        p_mqtt_data->mqtt_disable_retained_messages ? NULL : &p_mqtt_data->mqtt_topic,
        p_mqtt_data->mqtt_disable_retained_messages ? NULL : p_lwt_message,
        p_mqtt_data->str_buf_server_cert_mqtt.buf,
        p_mqtt_data->str_buf_client_cert.buf,
        p_mqtt_data->str_buf_client_key.buf,
        p_mqtt_data);

    return p_cli_cfg;
}

static bool
mqtt_app_start_internal2(const esp_mqtt_client_config_t* const p_mqtt_cfg, mqtt_protected_data_t* const p_mqtt_data)
{
    p_mqtt_data->p_mqtt_client = esp_mqtt_client_init(p_mqtt_cfg);
    if (NULL == p_mqtt_data->p_mqtt_client)
    {
        LOG_ERR("%s failed", "esp_mqtt_client_init");
        return false;
    }
    const esp_err_t err = esp_mqtt_client_start(p_mqtt_data->p_mqtt_client);
    if (ESP_OK != err)
    {
        esp_mqtt_client_destroy(p_mqtt_data->p_mqtt_client);
        p_mqtt_data->p_mqtt_client = NULL;
        return false;
    }
    return true;
}

void
mqtt_app_start_internal(mqtt_protected_data_t* p_mqtt_data, const ruuvi_gw_cfg_mqtt_t* const p_mqtt_cfg)
{
    gw_status_clear_mqtt_connected_and_error();
    p_mqtt_data->err_msg[0] = '\0';

    p_mqtt_data->str_buf_server_cert_mqtt = str_buf_init_null();
    p_mqtt_data->str_buf_client_cert      = str_buf_init_null();
    p_mqtt_data->str_buf_client_key       = str_buf_init_null();
    if (p_mqtt_cfg->use_ssl_client_cert)
    {
        p_mqtt_data->str_buf_client_cert = gw_cfg_storage_read_file(GW_CFG_STORAGE_SSL_MQTT_CLI_CERT);
        p_mqtt_data->str_buf_client_key  = gw_cfg_storage_read_file(GW_CFG_STORAGE_SSL_MQTT_CLI_KEY);
    }
    if (p_mqtt_cfg->use_ssl_server_cert)
    {
        p_mqtt_data->str_buf_server_cert_mqtt = gw_cfg_storage_read_file(GW_CFG_STORAGE_SSL_MQTT_SRV_CERT);
    }

    if (('\0' == p_mqtt_cfg->mqtt_server.buf[0]) || (0 == p_mqtt_cfg->mqtt_port))
    {
        LOG_ERR(
            "Invalid MQTT parameters: server: %s, topic prefix: '%s', port: %u, user: '%s', password: '%s'",
            p_mqtt_cfg->mqtt_server.buf,
            p_mqtt_cfg->mqtt_prefix.buf,
            p_mqtt_cfg->mqtt_port,
            p_mqtt_cfg->mqtt_user.buf,
            "******");
        gw_status_set_mqtt_error(MQTT_ERROR_CONNECT);
        return;
    }
    const esp_mqtt_client_config_t* p_mqtt_cli_cfg = mqtt_create_client_config(p_mqtt_data, p_mqtt_cfg);
    if (NULL == p_mqtt_cfg)
    {
        LOG_ERR("Can't create MQTT client config");
        return;
    }

    if (mqtt_app_start_internal2(p_mqtt_cli_cfg, p_mqtt_data))
    {
        gw_status_set_mqtt_started();
    }
    os_free(p_mqtt_cli_cfg);
}

void
mqtt_app_start(const ruuvi_gw_cfg_mqtt_t* const p_mqtt_cfg)
{
    LOG_INFO("%s", __func__);

    mqtt_protected_data_t* p_mqtt_data = mqtt_mutex_lock();
    if (NULL != p_mqtt_data->p_mqtt_client)
    {
        LOG_INFO("MQTT client is already running");
    }
    else
    {
        mqtt_app_start_internal(p_mqtt_data, p_mqtt_cfg);
    }
    mqtt_mutex_unlock(&p_mqtt_data);
}

void
mqtt_app_start_with_gw_cfg(void)
{
    ruuvi_gw_cfg_mqtt_t* p_mqtt_cfg = gw_cfg_get_mqtt_copy();
    if (NULL == p_mqtt_cfg)
    {
        LOG_ERR("Can't allocate memory for MQTT config");
        gw_status_set_mqtt_error(MQTT_ERROR_CONNECT);
        return;
    }

    mqtt_app_start(p_mqtt_cfg);

    os_free(p_mqtt_cfg);
}

void
mqtt_app_stop(void)
{
    LOG_INFO("%s", __func__);
    mqtt_protected_data_t* p_mqtt_data = mqtt_mutex_lock();
    if (NULL != p_mqtt_data->p_mqtt_client)
    {
        if (gw_status_is_mqtt_connected())
        {
            mqtt_publish_state_offline(p_mqtt_data);
            vTaskDelay(pdMS_TO_TICKS(500));
        }
        LOG_INFO("TaskWatchdog: Unregister current thread");
        const bool flag_task_wdt_used = (esp_task_wdt_delete(xTaskGetCurrentTaskHandle()) == ESP_OK) ? true : false;

        LOG_INFO("MQTT destroy");

        // Calling esp_mqtt_client_destroy can take quite a long time (more than 5 seconds),
        // depending on how quickly the server responds (it seems that esp_mqtt_client_stop takes most of the time).
        // So, the only way to prevent the task watchdog from triggering is to disable it.
        // If esp_mqtt_client_destroy is refactored in the future in an asynchronous manner,
        // then this will allow us to opt out of disabling the task watchdog.

        // TODO: Need to refactor esp_mqtt_client_destroy in an asynchronous manner, see issue:
        // https://github.com/ruuvi/ruuvi.gateway_esp.c/issues/577

        esp_mqtt_client_destroy(p_mqtt_data->p_mqtt_client);

        LOG_INFO("MQTT destroyed");

        if (flag_task_wdt_used)
        {
            LOG_INFO("TaskWatchdog: Register current thread");
            esp_task_wdt_add(xTaskGetCurrentTaskHandle());
        }

        p_mqtt_data->p_mqtt_client = NULL;
    }
    gw_status_clear_mqtt_connected_and_error();
    gw_status_clear_mqtt_started();
    LOG_INFO("Free memory, allocated for certificates");
    str_buf_free_buf(&p_mqtt_data->str_buf_server_cert_mqtt);
    str_buf_free_buf(&p_mqtt_data->str_buf_client_cert);
    str_buf_free_buf(&p_mqtt_data->str_buf_client_key);
    mqtt_mutex_unlock(&p_mqtt_data);
}

bool
mqtt_app_is_working(void)
{
    mqtt_protected_data_t* p_mqtt_data = mqtt_mutex_lock();
    const bool             is_working  = (NULL != p_mqtt_data->p_mqtt_client) ? true : false;
    mqtt_mutex_unlock(&p_mqtt_data);
    return is_working;
}

str_buf_t
mqtt_app_get_error_message(void)
{
    str_buf_t              str_buf     = str_buf_init_null();
    mqtt_protected_data_t* p_mqtt_data = mqtt_mutex_lock();
    if (NULL != p_mqtt_data->p_mqtt_client)
    {
        str_buf = str_buf_printf_with_alloc("%s", p_mqtt_data->err_msg);
    }
    mqtt_mutex_unlock(&p_mqtt_data);
    return str_buf;
}

