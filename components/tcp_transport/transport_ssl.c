// Copyright 2015-2018 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <string.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_tls.h"
#define LOG_LOCAL_LEVEL 3
#include "esp_log.h"
#include "esp_system.h"

#include "esp_transport.h"
#include "esp_transport_ssl.h"
#include "esp_transport_utils.h"
#include "esp_transport_ssl_internal.h"
#include "esp_transport_internal.h"
#include "esp_crt_bundle.h"
#include "snprintf_with_esp_err_desc.h"

static const char *TAG = "TRANS_SSL";

typedef enum {
    TRANS_SSL_INIT = 0,
    TRANS_SSL_CONNECTING,
} transport_ssl_conn_state_t;

/**
 *  mbedtls specific transport data
 */
typedef struct {
    esp_tls_t                *tls;
    esp_tls_cfg_t            cfg;
    bool                     ssl_initialized;
    transport_ssl_conn_state_t conn_state;
    TickType_t timer_start;
    int timer_read_initialized;
    int timer_write_initialized;
} transport_ssl_t;

static int ssl_close(esp_transport_handle_t t);

static int ssl_connect_async(esp_transport_handle_t t, const char *host, int port, int timeout_ms)
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    if (ssl->conn_state == TRANS_SSL_INIT) {
        ssl->cfg.timeout_ms = timeout_ms;
        ssl->cfg.non_block = true;
        ssl->ssl_initialized = true;
        ssl->tls = esp_tls_init();
        ESP_LOGD(TAG, "%s: esp_tls_init, tls=%p, tls->error_handle=%p", __func__, ssl->tls, ssl->tls->error_handle);
        if (!ssl->tls) {
            return -1;
        }
        ssl->conn_state = TRANS_SSL_CONNECTING;
    }
    if (ssl->conn_state == TRANS_SSL_CONNECTING) {
        ESP_LOGD(TAG, "%s: esp_tls_conn_new_async", __func__);
        const int ret = esp_tls_conn_new_async(host, strlen(host), port, &ssl->cfg, ssl->tls);
        if (ret < 0) {
            ESP_LOGD(TAG, "%s: esp_tls_conn_new_async failed", __func__);
            ESP_LOGD(TAG, "%s: esp_transport_set_errors", __func__);
            esp_transport_set_errors(t, ssl->tls->error_handle);
        }
        return ret;
    }
    return 0;
}

static int ssl_connect(esp_transport_handle_t t, const char *host, int port, int timeout_ms)
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);

    ssl->cfg.timeout_ms = timeout_ms;
    ssl->ssl_initialized = true;
    ssl->tls = esp_tls_init();
    ESP_LOGD(TAG, "%s: esp_tls_init, tls=%p, tls->error_handle=%p", __func__, ssl->tls, ssl->tls->error_handle);
    if (ssl->tls == NULL) {
        ESP_LOGE(TAG, "Failed to initialize new connection object");
        return -1;
    }
    if (esp_tls_conn_new_sync(host, strlen(host), port, &ssl->cfg, ssl->tls) <= 0) {
        ESP_LOGE(TAG, "Failed to open a new connection");
        esp_transport_set_errors(t, ssl->tls->error_handle);
        esp_tls_conn_destroy(ssl->tls);
        ssl->tls = NULL;
        return -1;
    }

    return 0;
}

static int ssl_poll_read(esp_transport_handle_t t, int timeout_ms)
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    int ret = -1;
    int remain = 0;
    struct timeval timeout;
    fd_set readset;
    fd_set errset;
    FD_ZERO(&readset);
    FD_ZERO(&errset);
    FD_SET(ssl->tls->sockfd, &readset);
    FD_SET(ssl->tls->sockfd, &errset);

    if ((remain = esp_tls_get_bytes_avail(ssl->tls)) > 0) {
        ESP_LOGD(TAG, "remain data in cache, need to read again");
        return remain;
    }
    ret = select(ssl->tls->sockfd + 1, &readset, NULL, &errset, esp_transport_utils_ms_to_timeval(timeout_ms, &timeout));
    if (ret > 0 && FD_ISSET(ssl->tls->sockfd, &errset)) {
        int sock_errno = 0;
        uint32_t optlen = sizeof(sock_errno);
        getsockopt(ssl->tls->sockfd, SOL_SOCKET, SO_ERROR, &sock_errno, &optlen);
        esp_transport_capture_errno(t, sock_errno);
        str_buf_t err_desc = esp_err_to_name_with_alloc_str_buf(sock_errno);
        ESP_LOGE(
            TAG,
            "ssl_poll_read select error %d (%s), fd = %d",
            sock_errno,
            (NULL != err_desc.buf) ? err_desc.buf : "",
            ssl->tls->sockfd);
        str_buf_free_buf(&err_desc);
        ret = -1;
    }
    return ret;
}

static int ssl_poll_write(esp_transport_handle_t t, int timeout_ms)
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    int ret = -1;
    struct timeval timeout;
    fd_set writeset;
    fd_set errset;
    FD_ZERO(&writeset);
    FD_ZERO(&errset);
    FD_SET(ssl->tls->sockfd, &writeset);
    FD_SET(ssl->tls->sockfd, &errset);
    ret = select(ssl->tls->sockfd + 1, NULL, &writeset, &errset, esp_transport_utils_ms_to_timeval(timeout_ms, &timeout));
    if (ret > 0 && FD_ISSET(ssl->tls->sockfd, &errset)) {
        int sock_errno = 0;
        uint32_t optlen = sizeof(sock_errno);
        getsockopt(ssl->tls->sockfd, SOL_SOCKET, SO_ERROR, &sock_errno, &optlen);
        esp_transport_capture_errno(t, sock_errno);
        str_buf_t err_desc = esp_err_to_name_with_alloc_str_buf(sock_errno);
        ESP_LOGE(
            TAG,
            "ssl_poll_write select error %d (%s), fd = %d",
            sock_errno,
            (NULL != err_desc.buf) ? err_desc.buf : "",
            ssl->tls->sockfd);
        str_buf_free_buf(&err_desc);
        ret = -1;
    }
    return ret;
}

static int ssl_write(esp_transport_handle_t t, const char *buffer, int len, int timeout_ms)
{
    int poll, ret;
    transport_ssl_t *ssl = esp_transport_get_context_data(t);

    if (!ssl->cfg.non_block) {
        if ((poll = esp_transport_poll_write(t, timeout_ms)) <= 0) {
            str_buf_t err_desc = esp_err_to_name_with_alloc_str_buf(errno);
            ESP_LOGW(
                TAG,
                "Poll timeout or error, errno=%d (%s), fd=%d, timeout_ms=%d",
                errno,
                (NULL != err_desc.buf) ? err_desc.buf : "",
                ssl->tls->sockfd,
                timeout_ms);
            str_buf_free_buf(&err_desc);
            return poll;
        }
    } else {
        ssl->timer_read_initialized = false;
        if (!ssl->timer_write_initialized) {
            ESP_LOGD(TAG, "%s: start timer", __func__);
            ssl->timer_start = xTaskGetTickCount();
            ssl->timer_write_initialized = true;
        }
    }
    ret = esp_tls_conn_write(ssl->tls, (const unsigned char *) buffer, len);
    if (ret <= 0) {
        if (ssl->cfg.non_block) {
            if (((errno == EAGAIN) || (errno == EWOULDBLOCK))) {
                str_buf_t err_desc = esp_err_to_name_with_alloc_str_buf(errno);
                ESP_LOGD(
                    TAG,
                    "esp_tls_conn_write error, errno=%d (%s)",
                    errno,
                    (NULL != err_desc.buf) ? err_desc.buf : "");
                str_buf_free_buf(&err_desc);
                const TickType_t delta_ticks = xTaskGetTickCount() - ssl->timer_start;
                if (delta_ticks > pdMS_TO_TICKS(timeout_ms)) {
                    ESP_LOGE(TAG, "%s: timeout", __func__);
                    errno = -1;
                    ssl->timer_write_initialized = false;
                    return -1;
                }
            } else {
                str_buf_t err_desc = esp_err_to_name_with_alloc_str_buf(errno);
                ESP_LOGE(
                    TAG,
                    "esp_tls_conn_write error, errno=%d (%s)",
                    errno,
                    (NULL != err_desc.buf) ? err_desc.buf : "");
                str_buf_free_buf(&err_desc);
                ssl->timer_write_initialized = false;
            }
        } else {
            str_buf_t err_desc = esp_err_to_name_with_alloc_str_buf(errno);
            ESP_LOGE(TAG, "esp_tls_conn_write error, errno=%d (%s)", errno, (NULL != err_desc.buf) ? err_desc.buf : "");
            str_buf_free_buf(&err_desc);
            esp_transport_capture_errno(t, errno);
        }
    } else {
        if (ssl->cfg.non_block) {
            ESP_LOGD(TAG, "%s: restart timer", __func__);
            ssl->timer_start = xTaskGetTickCount();
        }
    }
    return ret;
}

static int ssl_read(esp_transport_handle_t t, char *buffer, int len, int timeout_ms)
{
    int poll, ret;
    transport_ssl_t *ssl = esp_transport_get_context_data(t);

    if (!ssl->cfg.non_block) {
        if ((poll = esp_transport_poll_read(t, timeout_ms)) <= 0) {
            return poll;
        }
    } else {
        ssl->timer_write_initialized = false;
        if (!ssl->timer_read_initialized) {
            ESP_LOGD(TAG, "%s: start timer", __func__);
            ssl->timer_start = xTaskGetTickCount();
            ssl->timer_read_initialized = true;
        }
    }
    ret = esp_tls_conn_read(ssl->tls, (unsigned char *)buffer, len);
    if (ret <= 0) {
        if (ssl->cfg.non_block) {
            if (((errno == EAGAIN) || (errno == EWOULDBLOCK))) {
                str_buf_t err_desc = esp_err_to_name_with_alloc_str_buf(errno);
                ESP_LOGD(
                    TAG,
                    "esp_tls_conn_read error, errno=%d (%s)",
                    errno,
                    (NULL != err_desc.buf) ? err_desc.buf : "");
                str_buf_free_buf(&err_desc);
                const TickType_t delta_ticks = xTaskGetTickCount() - ssl->timer_start;
                if (delta_ticks > pdMS_TO_TICKS(timeout_ms)) {
                    ESP_LOGE(TAG, "%s: timeout", __func__);
                    errno = -1;
                    ssl->timer_read_initialized = false;
                    return -1;
                }
            } else {
                str_buf_t err_desc = esp_err_to_name_with_alloc_str_buf(errno);
                ESP_LOGE(
                    TAG,
                    "esp_tls_conn_read error, errno=%d (%s)",
                    errno,
                    (NULL != err_desc.buf) ? err_desc.buf : "");
                str_buf_free_buf(&err_desc);
                esp_transport_capture_errno(t, errno);

                ssl->timer_read_initialized = false;
            }
        } else {
            str_buf_t err_desc = esp_err_to_name_with_alloc_str_buf(errno);
            ESP_LOGE(TAG, "esp_tls_conn_read error, errno=%d (%s)", errno, (NULL != err_desc.buf) ? err_desc.buf : "");
            str_buf_free_buf(&err_desc);
            esp_transport_capture_errno(t, errno);
        }
    } else {
        if (ssl->cfg.non_block) {
            ESP_LOGD(TAG, "%s: restart timer", __func__);
            ssl->timer_start = xTaskGetTickCount();
        }
    }
    if (ret == 0) {
        ret = -1;
    }
    return ret;
}

static int ssl_close(esp_transport_handle_t t)
{
    int ret = -1;
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    if (ssl->ssl_initialized) {
        if (NULL == ssl->tls)
        {
            ESP_LOGW(TAG, "[%s] %s: tls=NULL", pcTaskGetTaskName(NULL) ? pcTaskGetTaskName(NULL) : "???", __func__);
        }
        else
        {
            ESP_LOGI(
                TAG,
                "[%s] %s: tls=%p",
                pcTaskGetTaskName(NULL) ? pcTaskGetTaskName(NULL) : "???",
                __func__,
                ssl->tls);
        }
        ret = esp_tls_conn_destroy(ssl->tls);
        ssl->conn_state = TRANS_SSL_INIT;
        ssl->ssl_initialized = false;
    }
    return ret;
}

static int ssl_destroy(esp_transport_handle_t t)
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    esp_transport_close(t);
    free(ssl);
    return 0;
}

void esp_transport_ssl_enable_global_ca_store(esp_transport_handle_t t)
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    if (t && ssl) {
        ssl->cfg.use_global_ca_store = true;
    }
}

void esp_transport_ssl_crt_bundle_attach(esp_transport_handle_t t, esp_err_t (*crt_bundle_attach)(void *conf))
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    if (t && ssl) {
        ssl->cfg.crt_bundle_attach = crt_bundle_attach;
    }
}

#ifdef CONFIG_ESP_TLS_PSK_VERIFICATION
void esp_transport_ssl_set_psk_key_hint(esp_transport_handle_t t, const psk_hint_key_t* psk_hint_key)
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    if (t && ssl) {
        ssl->cfg.psk_hint_key =  psk_hint_key;
    }
}
#endif

void esp_transport_ssl_set_cert_data(esp_transport_handle_t t, const char *data, int len)
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    if (t && ssl) {
        ssl->cfg.cacert_pem_buf = (void *)data;
        ssl->cfg.cacert_pem_bytes = len + 1;
    }
}

void esp_transport_ssl_set_cert_data_der(esp_transport_handle_t t, const char *data, int len)
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    if (t && ssl) {
        ssl->cfg.cacert_buf = (void *)data;
        ssl->cfg.cacert_bytes = len;
    }
}

void esp_transport_ssl_set_client_cert_data(esp_transport_handle_t t, const char *data, int len)
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    if (t && ssl) {
        ssl->cfg.clientcert_pem_buf = (void *)data;
        ssl->cfg.clientcert_pem_bytes = len + 1;
    }
}

void esp_transport_ssl_set_client_cert_data_der(esp_transport_handle_t t, const char *data, int len)
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    if (t && ssl) {
        ssl->cfg.clientcert_buf = (void *)data;
        ssl->cfg.clientcert_bytes = len;
    }
}

void esp_transport_ssl_set_client_key_data(esp_transport_handle_t t, const char *data, int len)
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    if (t && ssl) {
        ssl->cfg.clientkey_pem_buf = (void *)data;
        ssl->cfg.clientkey_pem_bytes = len + 1;
    }
}

void esp_transport_ssl_set_client_key_password(esp_transport_handle_t t, const char *password, int password_len)
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    if (t && ssl) {
        ssl->cfg.clientkey_password = (void *)password;
        ssl->cfg.clientkey_password_len = password_len;
    }
}

void esp_transport_ssl_set_client_key_data_der(esp_transport_handle_t t, const char *data, int len)
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    if (t && ssl) {
        ssl->cfg.clientkey_buf = (void *)data;
        ssl->cfg.clientkey_bytes = len;
    }
}

#if defined(CONFIG_MBEDTLS_SSL_ALPN) || defined(CONFIG_WOLFSSL_HAVE_ALPN)
void esp_transport_ssl_set_alpn_protocol(esp_transport_handle_t t, const char **alpn_protos)
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    if (t && ssl) {
        ssl->cfg.alpn_protos = alpn_protos;
    }
}
#endif

void esp_transport_ssl_skip_common_name_check(esp_transport_handle_t t)
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    if (t && ssl) {
        ssl->cfg.skip_common_name = true;
    }
}

#ifdef CONFIG_ESP_TLS_USE_SECURE_ELEMENT
void esp_transport_ssl_use_secure_element(esp_transport_handle_t t)
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    if (t && ssl) {
        ssl->cfg.use_secure_element = true;
    }
}
#endif

static int ssl_get_socket(esp_transport_handle_t t)
{
    if (t) {
        transport_ssl_t *ssl = t->data;
        if (ssl && ssl->tls) {
            return ssl->tls->sockfd;
        }
    }
    return -1;
}

#ifdef CONFIG_ESP_TLS_USE_DS_PERIPHERAL
void esp_transport_ssl_set_ds_data(esp_transport_handle_t t, void *ds_data)
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    if (t && ssl) {
        ssl->cfg.ds_data = ds_data;
    }
}
#endif

void esp_transport_ssl_set_keep_alive(esp_transport_handle_t t, esp_transport_keep_alive_t *keep_alive_cfg)
{
    transport_ssl_t *ssl = esp_transport_get_context_data(t);
    if (t && ssl) {
        ssl->cfg.keep_alive_cfg = (tls_keep_alive_cfg_t *)keep_alive_cfg;
    }
}

esp_transport_handle_t esp_transport_ssl_init(void)
{
    esp_transport_handle_t t = esp_transport_init();
    transport_ssl_t *ssl = calloc(1, sizeof(transport_ssl_t));
    ESP_TRANSPORT_MEM_CHECK(TAG, ssl, {
        esp_transport_destroy(t);
        return NULL;
    });
    esp_transport_set_context_data(t, ssl);
    esp_transport_set_func(t, ssl_connect, ssl_read, ssl_write, ssl_close, ssl_poll_read, ssl_poll_write, ssl_destroy);
    esp_transport_set_async_connect_func(t, ssl_connect_async);
    t->_get_socket = ssl_get_socket;
    return t;
}
