/*
 * JasonFreeLab
 *
 */

#pragma once

#include "esp_err.h"
#include "esp_event.h"
#include "esp_wifi.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HOTSPOT_AP "aha"
#define ROUTER_AP "adha"
#define STA_SSID_KEY             "stassid"
#define STA_PASSWORD_KEY         "pswd"
#define AP_SSID_KEY              CONFIG_AP_SSID_KEY
#define SC_MODE                  "scmode"

typedef enum {
    CONN_SC_ZERO_MODE = 1,
    CONN_SOFTAP_MODE  = 2,
} conn_sc_mode_t;

/**
 * @brief register wifi event handler
 *
 * @param cb wifi event handler
 *
 * @return none
 */
void conn_mgr_register_wifi_event(esp_event_handler_t cb);

/**
 * @brief reset the stored router info, include ssid & password
 * 
 * @return
 *     - ESP_OK : OK
 *     - others : fail
 */
esp_err_t conn_mgr_reset_wifi_config(void);

/**
 * @brief connect wifi with configure information 
 * 
 * This will initiate connection to the given Wi-Fi configure information
 * 
 * @param ssid Pointer to the target network SSID string
 * @param ssid_len Length of the above SSID
 * @param password Pointer to the targer network Password string. Can be NULL for open networks.
 * @param password_len Length of the password
 * 
 * @return
 *     - ESP_OK : OK
 *     - others : fail
 */
esp_err_t conn_mgr_set_wifi_config_ext(const uint8_t *ssid, size_t ssid_len, const uint8_t *password, size_t password_len);

/**
 * @brief get wifi configure information
 * 
 * @return
 *     - ESP_OK : OK
 *     - others : fail
 */
esp_err_t conn_mgr_get_wifi_config(wifi_config_t *wifi_cfg);

/**
 * @brief init the connection management kv module
 * 
 * @return
 *     - ESP_OK : OK
 *     - others : fail
 */
esp_err_t conn_mgr_Kv_init(void);

/**
 * @brief init the connection management module
 * 
 * @return
 *     - ESP_OK : OK
 *     - others : fail
 */
esp_err_t conn_mgr_init(void);

/**
 * @brief start the connection management module
 * 
 * If the device is configured, the device will connect to the router which is configured.
 * If the device is not configured, the device will start awss service.
 * 
 * @param awss_mode awss mode
 * 
 * @return
 *     - ESP_OK : OK
 *     - others : fail
 */
esp_err_t conn_mgr_start(conn_sc_mode_t awss_mode);

/**
 * @brief stop the connection management module
 * 
 * If the device is configured, the device keep connect to the router which is configured.
 * If the device is not configured, the device will stop awss service.
 * 
 * @return
 *     - ESP_OK : OK
 *     - others : fail
 */
esp_err_t conn_mgr_stop(void);

/**
 * @brief set softap ssid to KV
 *
 * @param ssid Pointer to the softap SSID string
 * @param len Length of the above SSID
 *
 * @return
 *     - ESP_OK : OK
 *     - others : fail
 */
esp_err_t conn_mgr_set_ap_ssid(uint8_t *ssid, int len);

/**
 * @brief set wifi distribution network mode to KV
 *
 * If mode is 1, means support smartconfig and zero-config
 * If mode is 2, means support softap config
 * @param mode Value of the sc mode
 *
 * @return
 *     - ESP_OK : OK
 *     - others : fail
 */
esp_err_t conn_mgr_set_sc_mode(conn_sc_mode_t mode);
#ifdef __cplusplus
}
#endif
