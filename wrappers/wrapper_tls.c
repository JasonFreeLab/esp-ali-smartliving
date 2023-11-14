/*
 * JasonFreeLab
 *
 */

#include <stdio.h>
#include <string.h>

#include "esp_tls.h"
#include "esp_system.h"
#include "esp_log.h"

#include "lwip/sockets.h"

#include "iot_import.h"

static const char *TAG = "wrapper_tls";

/**
 * @brief Set malloc/free function.
 *
 * @param [in] hooks: @n Specify malloc/free function you want to use
 *
 * @retval DTLS_SUCCESS : Success.
   @retval        other : Fail.
 * @see None.
 * @note None.
 */
DLL_HAL_API int HAL_DTLSHooks_set(dtls_hooks_t *hooks)
{
    return (int)1;
}

/**
 * @brief Establish a DSSL connection.
 *
 * @param [in] p_options: @n Specify paramter of DTLS
   @verbatim
           p_host : @n Specify the hostname(IP) of the DSSL server
             port : @n Specify the DSSL port of DSSL server
    p_ca_cert_pem : @n Specify the root certificate which is PEM format.
   @endverbatim
 * @return DSSL handle.
 * @see None.
 * @note None.
 */
DLL_HAL_API DTLSContext *HAL_DTLSSession_create(coap_dtls_options_t  *p_options)
{
    return (DTLSContext *)1;
}

/**
 * @brief Destroy the specific DSSL connection.
 *
 * @param[in] context: @n Handle of the specific connection.
 *
 * @return The result of free dtls session
 * @retval DTLS_SUCCESS : Read success.
 * @retval DTLS_INVALID_PARAM : Invalid parameter.
 * @retval DTLS_INVALID_CA_CERTIFICATE : Invalid CA Certificate.
 * @retval DTLS_HANDSHAKE_IN_PROGRESS : Handshake in progress.
 * @retval DTLS_HANDSHAKE_FAILED : Handshake failed.
 * @retval DTLS_FATAL_ALERT_MESSAGE : Recv peer fatal alert message.
 * @retval DTLS_PEER_CLOSE_NOTIFY : The DTLS session was closed by peer.
 * @retval DTLS_SESSION_CREATE_FAILED : Create session fail.
 * @retval DTLS_READ_DATA_FAILED : Read data fail.
 */
DLL_HAL_API unsigned int HAL_DTLSSession_free(DTLSContext *context)
{
    return (unsigned)1;
}

/**
 * @brief Read data from the specific DSSL connection with timeout parameter.
 *        The API will return immediately if len be received from the specific DSSL connection.
 *
 * @param [in] context @n A descriptor identifying a DSSL connection.
 * @param [in] p_data @n A pointer to a buffer to receive incoming data.
 * @param [in] p_datalen @n The length, in bytes, of the data pointed to by the 'p_data' parameter.
 * @param [in] timeout_ms @n Specify the timeout value in millisecond. In other words, the API block 'timeout_ms' millisecond maximumly.
 * @return The result of read data from DSSL connection
 * @retval DTLS_SUCCESS : Read success.
 * @retval DTLS_FATAL_ALERT_MESSAGE : Recv peer fatal alert message.
 * @retval DTLS_PEER_CLOSE_NOTIFY : The DTLS session was closed by peer.
 * @retval DTLS_READ_DATA_FAILED : Read data fail.
 * @see None.
 */
DLL_HAL_API unsigned int HAL_DTLSSession_read(DTLSContext *context,
        unsigned char *p_data,
        unsigned int *p_datalen,
        unsigned int timeout_ms)
{
    return (unsigned)1;
}

/**
 * @brief Write data into the specific DSSL connection.
 *
 * @param [in] context @n A descriptor identifying a connection.
 * @param [in] p_data @n A pointer to a buffer containing the data to be transmitted.
 * @param [in] p_datalen @n The length, in bytes, of the data pointed to by the 'p_data' parameter.
 * @retval DTLS_SUCCESS : Success.
   @retval        other : Fail.
 * @see None.
 */
DLL_HAL_API unsigned int HAL_DTLSSession_write(DTLSContext *context,
        const unsigned char *p_data,
        unsigned int *p_datalen)
{
    return (unsigned)1;
}

extern void *HAL_Malloc(uint32_t size);
extern void HAL_Free(void *ptr);

static ssl_hooks_t g_ssl_hooks = { HAL_Malloc, HAL_Free};

int32_t HAL_SSL_Destroy(uintptr_t handle)
{
    struct esp_tls_t *tls = (struct esp_tls_t *)handle;

    if (!tls) {
        return ESP_FAIL;
    }

    #ifdef CONFIG_IDF_TARGET_ESP8266
    esp_tls_conn_delete((esp_tls_t *)tls);
    #else
    esp_tls_conn_destroy((esp_tls_t *)tls);
    #endif

    return ESP_OK;
}

uintptr_t HAL_SSL_Establish(const char *host, uint16_t port, const char *ca_crt, size_t ca_crt_len)
{
    esp_tls_cfg_t cfg = {
        .cacert_pem_buf  = (const unsigned char *)ca_crt,
        .cacert_pem_bytes = ca_crt_len,
        .timeout_ms = CONFIG_TLS_ESTABLISH_TIMEOUT_MS,
    };

#ifdef CONFIG_IDF_TARGET_ESP8266
#if ESP_IDF_VERSION >= 0x30300
    esp_set_cpu_freq(ESP_CPU_FREQ_160M);
#else
    rtc_clk_cpu_freq_set(RTC_CPU_FREQ_160M);
#endif
#endif
    struct esp_tls_t *tls = (struct esp_tls_t *)esp_tls_init();
    esp_tls_conn_new_sync(host, strlen(host), port, &cfg, (esp_tls_t *)tls);

#ifdef CONFIG_IDF_TARGET_ESP8266
#if ESP_IDF_VERSION >= 0x30300
    esp_set_cpu_freq(ESP_CPU_FREQ_80M);
#else
    rtc_clk_cpu_freq_set(RTC_CPU_FREQ_80M);
#endif
#endif

    return (uintptr_t)tls;
}

int HAL_SSLHooks_set(ssl_hooks_t *hooks)
{
    if (hooks == NULL || hooks->malloc == NULL || hooks->free == NULL) {
        return ESP_FAIL;
    }

    g_ssl_hooks.malloc = hooks->malloc;
    g_ssl_hooks.free = hooks->free;

    return ESP_OK;
}

static void HAL_utils_ms_to_timeval(int timeout_ms, struct timeval *tv)
{
    tv->tv_sec = timeout_ms / 1000;
    tv->tv_usec = (timeout_ms - (tv->tv_sec * 1000)) * 1000;
}

static int ssl_poll_read(esp_tls_t *tls, int timeout_ms)
{
    esp_err_t ret;

    fd_set readset;
    fd_set errset;
    
    int sockfd = -1;
    ret = esp_tls_get_conn_sockfd(tls, &sockfd);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Error in obtaining the sockfd from tls context");
        return ret;
    }
    
    FD_ZERO(&readset);
    FD_ZERO(&errset);
    FD_SET(sockfd, &readset);
    FD_SET(sockfd, &errset);
    struct timeval timeout;
    HAL_utils_ms_to_timeval(timeout_ms, &timeout);
    ret = select(sockfd + 1, &readset, NULL, &errset, &timeout);
    if (ret > 0 && FD_ISSET(sockfd, &errset)) {
        int sock_errno = 0;
        uint32_t optlen = sizeof(sock_errno);
        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &sock_errno, &optlen);
        ESP_LOGE(TAG, "ssl_poll_read select error %d, errno = %s, fd = %d", sock_errno, strerror(sock_errno), sockfd);
        ret = ESP_FAIL;
    }
    
    return ret;
}

int32_t HAL_SSL_Read(uintptr_t handle, char *buf, int len, int timeout_ms)
{
    esp_err_t ret;
    int poll_ret;
    struct esp_tls_t *tls = (struct esp_tls_t *)handle;

    if (tls == NULL) {
        ESP_LOGE(TAG, "HAL_SSL_Read, handle == NULL");
        return NULL_VALUE_ERROR;
    }

    if (esp_tls_get_bytes_avail((esp_tls_t *)tls) <= 0) {
        if ((poll_ret = ssl_poll_read((esp_tls_t *)tls, timeout_ms)) <= 0) {
            return poll_ret;
        }
    }

    ret = esp_tls_conn_read((esp_tls_t *)tls, (void *)buf, len);

    if (ret < 0) {
        ESP_LOGE(TAG, "esp_tls_conn_read error, errno:%s", strerror(errno));
    }

    return ret;
}

static int ssl_poll_write(esp_tls_t *tls, int timeout_ms)
{
    esp_err_t ret;

    fd_set writeset;
    fd_set errset;

    FD_ZERO(&writeset);
    FD_ZERO(&errset);

    int sockfd = -1;
    ret = esp_tls_get_conn_sockfd(tls, &sockfd);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Error in obtaining the sockfd from tls context");
        return ret;
    }

    FD_SET(sockfd, &writeset);
    FD_SET(sockfd, &errset);
    struct timeval timeout;
    HAL_utils_ms_to_timeval(timeout_ms, &timeout);
    ret = select(sockfd + 1, NULL, &writeset, &errset, &timeout);
    if (ret > 0 && FD_ISSET(sockfd, &errset)) {
        int sock_errno = 0;
        uint32_t optlen = sizeof(sock_errno);
        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &sock_errno, &optlen);
        ESP_LOGE(TAG, "ssl_poll_write select error %d, errno = %s, fd = %d", sock_errno, strerror(sock_errno), sockfd);
        ret = ESP_FAIL;
    }

    return ret;
}

int32_t HAL_SSL_Write(uintptr_t handle, const char *buf, int len, int timeout_ms)
{
    esp_err_t ret;
    int poll_ret;
    struct esp_tls_t *tls = (struct esp_tls_t *)handle;

    if (tls == NULL) {
        ESP_LOGE(TAG, "HAL_SSL_Write, handle == NULL");
        return NULL_VALUE_ERROR;
    }

    if ((poll_ret = ssl_poll_write((esp_tls_t *)tls, timeout_ms)) <= 0) {
        ESP_LOGE(TAG, "ssl_poll_write return %d, timeout is %d", poll_ret, timeout_ms);
        return poll_ret;
    }

    ret = esp_tls_conn_write((esp_tls_t *)tls, (const void *) buf, len);

    if (ret < 0) {
        ESP_LOGE(TAG, "esp_tls_conn_write error, errno=%s", strerror(errno));
    }

    return ret;
}
