/*
 * JasonFreeLab
 *
 */

#include <stdlib.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_netif.h"

#include "lwip/apps/sntp.h"

#include "iot_import.h"

#include "conn_mgr.h"

static const char *TAG = "conn_mgr";

static esp_event_handler_t hal_wifi_system_cb;

//连接到WiFi
static esp_err_t conn_mgr_wifi_connect(void)
{
    wifi_config_t wifi_config = {0};
    int ssid_len = sizeof(wifi_config.sta.ssid);
    int password_len = sizeof(wifi_config.sta.password);

    int ret = HAL_Kv_Get(STA_SSID_KEY, wifi_config.sta.ssid, &ssid_len);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get stored SSID");
        return ESP_FAIL;
    }

    /* Even if the password is not found, it is not an error, as it could be an open network */
    ret = HAL_Kv_Get(STA_PASSWORD_KEY, wifi_config.sta.password, &password_len);

    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to get stored Password");
        password_len = 0;
    }

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config);
    esp_wifi_start();
    esp_wifi_connect();

    return ESP_OK;
}

//保存SSID & PASSWORD 到 flash
static esp_err_t conn_mgr_save_wifi_config(void)
{
    wifi_config_t wifi_config = {0};

    esp_wifi_get_config(ESP_IF_WIFI_STA, &wifi_config);

    /* Do not save hotspot or router APs. */
    if (strcmp((char *)(wifi_config.sta.ssid), HOTSPOT_AP) == 0 ||
        strcmp((char *)(wifi_config.sta.ssid), ROUTER_AP) == 0) {
        ESP_LOGI(TAG, "Do not save hotspot or router APs: %s", wifi_config.sta.ssid);
        return ESP_FAIL;
    }

    int ret = HAL_Kv_Set(STA_SSID_KEY, wifi_config.sta.ssid, sizeof(wifi_config.sta.ssid), 0);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "%s key store failed with %d", STA_SSID_KEY, ret);
        return ESP_FAIL;
    }

    /* Password may be NULL. Save, only if it is given */
    if (wifi_config.sta.password[0] != 0) {
        ret = HAL_Kv_Set(STA_PASSWORD_KEY, wifi_config.sta.password, sizeof(wifi_config.sta.password), 0);

        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "%s key store failed with %d", STA_PASSWORD_KEY, ret);
            return ESP_FAIL;
        }
    }

    return ESP_OK;
}

//通过SNTP同步网络时间
static esp_err_t conn_mgr_obtain_time(void)
{
    static bool get_time_flag = false;
    if (get_time_flag) {
        return ESP_OK;
    }

    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, "ntp.aliyun.com");
    sntp_setservername(1, "ntp.ntsc.ac.cn");
    sntp_setservername(2, "cn.ntp.org.cn");
    sntp_setservername(3, "cn.pool.ntp.org");
    sntp_setservername(4, "ntp.tencent.com");
    sntp_init();
    // Set timezone to China Standard Time
    setenv("TZ", "CST-8", 1);
    tzset();

    time_t now = 0;
    struct tm timeinfo = { 0 };
    int sntp_retry_cnt = 0;
    int sntp_retry_time = CONFIG_SNTP_RETRY_TIMEOUT;

    while (1) {
        time(&now);
        localtime_r(&now, &timeinfo);
        if (timeinfo.tm_year < (2019 - 1900)) {
            if (sntp_retry_cnt < CONFIG_SNTP_RETRY_MAX) {
                ESP_LOGI(TAG, "SNTP get time failed (%d), retry after %d ms\n", sntp_retry_cnt, sntp_retry_time);
                vTaskDelay(sntp_retry_time / portTICK_PERIOD_MS);
            } else {
                ESP_LOGI(TAG, "SNTP get %d time failed, break\n", sntp_retry_cnt);
                break;
            }
            sntp_retry_cnt ++;
        } else {
            ESP_LOGI(TAG,"SNTP get time success\n");
            break;
        }
    }

    get_time_flag = true;

    return ESP_OK;
}

// //WiFi事件回调函数
static void event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        conn_mgr_save_wifi_config();
        conn_mgr_obtain_time();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t* disconnected = (wifi_event_sta_disconnected_t*) event_data;
        ESP_LOGE(TAG, "Disconnect reason : %d", disconnected->reason);
#ifdef CONFIG_IDF_TARGET_ESP8266
        if (disconnected->reason == WIFI_REASON_BASIC_RATE_NOT_SUPPORT) {
            /*Switch to 802.11 bgn mode */
            esp_wifi_set_protocol(ESP_IF_WIFI_STA, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N);
        }
#endif
        esp_wifi_connect();
    }

        /** The application loop event handle */
    if (hal_wifi_system_cb) {
        hal_wifi_system_cb(arg, event_base, event_id, event_data);
    }
}

//WiFi事件句柄
void conn_mgr_register_wifi_event(esp_event_handler_t cb)
{
    hal_wifi_system_cb = cb;
}

//清除WiFi配置
esp_err_t conn_mgr_reset_wifi_config(void)
{
    HAL_Kv_Del(STA_SSID_KEY);
    HAL_Kv_Del(STA_PASSWORD_KEY);

    return ESP_OK;
}

//检查是否已经完成配网
static esp_err_t conn_mgr_is_configured(bool *configured)
{
    if (!configured) {
        return ESP_ERR_INVALID_ARG;
    }

    *configured = false;

    int ssid_len = 32;
    uint8_t ssid[32];

    int ret = HAL_Kv_Get(STA_SSID_KEY, ssid, &ssid_len);

    if (ret == ESP_OK && ssid_len) {
        *configured = true;
        ESP_LOGI(TAG, "Found ssid %s", ssid);
    }

    return ESP_OK;
}

//保存WiFi配置
esp_err_t conn_mgr_set_wifi_config_ext(const uint8_t *ssid, size_t ssid_len, const uint8_t *password, size_t password_len)
{
    wifi_config_t wifi_config = {0};

    if (!ssid || ssid_len > sizeof(wifi_config.sta.ssid) || password_len > sizeof(wifi_config.sta.password))
        return ESP_ERR_INVALID_ARG;
    
    memcpy(wifi_config.sta.ssid, ssid, ssid_len); 
    if (password) {
        memcpy(wifi_config.sta.password, password, password_len); 
    }
    esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config);

    conn_mgr_save_wifi_config();

    return ESP_OK;
}

//获取WiFi配置
esp_err_t conn_mgr_get_wifi_config(wifi_config_t *wifi_cfg)
{
    return esp_wifi_get_config(ESP_IF_WIFI_STA, wifi_cfg);
}

//conn_mgr初始化
esp_err_t conn_mgr_init(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
#ifndef CONFIG_IDF_TARGET_ESP8266
    esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();
    assert(sta_netif);
#endif
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
    ESP_ERROR_CHECK( esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &event_handler, NULL) );
    ESP_ERROR_CHECK( esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL) );
    ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK( esp_wifi_start() );

    return ESP_OK;
}

//conn_mgr开始
esp_err_t conn_mgr_start(conn_sc_mode_t awss_mode)
{
    bool ret = true;
    bool configured = false;
    uint8_t mode_kv = 0;
    int mode_len = sizeof(uint8_t);

    // Let's find out if the device is configured.
    if (conn_mgr_is_configured(&configured) != ESP_OK) {
        return ESP_FAIL;
    }

    // Get SC mode and decide to start which awss service
    HAL_Kv_Get(SC_MODE, &mode_kv, &mode_len);
    if (mode_len && mode_kv == CONN_SOFTAP_MODE) {
        awss_mode = CONN_SOFTAP_MODE;
    }
    else if (mode_len && mode_kv == CONN_SC_ZERO_MODE)
    {
        awss_mode = CONN_SC_ZERO_MODE;
    }
    else {
        conn_mgr_set_sc_mode(awss_mode);
    }

    // If the device is not yet configured, start awss service.
    if (!configured) {
        do {
            if (awss_config_press() != 0) {
                ret = false;
                break;
            }
            if (awss_mode == CONN_SOFTAP_MODE) {
                if (awss_dev_ap_start() != 0) {
                    ret = false;
                    break;
                }
            } else if (awss_mode == CONN_SC_ZERO_MODE) {
                if (awss_start() != 0) {
                    ret = false;
                    break;
                }
            } else {
                if (awss_dev_ap_start() != 0) {
                    ret = false;
                    break;
                }
            }
        } while (0);
    } else {
        if (conn_mgr_wifi_connect() != ESP_OK) {
            ret = false;
        }
    }

    return ret == true ? ESP_OK : ESP_FAIL;
}

//conn_mgr结束
esp_err_t conn_mgr_stop(void)
{
    bool ret = true;
    bool configured = false;
    uint8_t mode = 0;
    int mode_len = sizeof(uint8_t);
    conn_sc_mode_t awss_mode = CONN_SOFTAP_MODE;

    // Let's find out if the device is configured.
    if (conn_mgr_is_configured(&configured) != ESP_OK) {
        return ESP_FAIL;
    }

    // Get SC mode and decide to start which awss service
    HAL_Kv_Get(SC_MODE, &mode, &mode_len);
    if (mode_len && mode == CONN_SC_ZERO_MODE) {
        awss_mode = CONN_SC_ZERO_MODE;
    }

    // If the device is not yet configured, stop awss service.
    if (!configured) {
        if (awss_mode == CONN_SC_ZERO_MODE) {
            if (awss_dev_ap_stop() != 0) {
                ret = false;
            }
        } else {
            if (awss_stop() != 0) {
                ret = false;
            }
        }
    }

    return ret == true ? ESP_OK : ESP_FAIL;
}

//设置AP模式的SSID
esp_err_t conn_mgr_set_ap_ssid(uint8_t *ssid, int len)
{
    int ret = ESP_FAIL;
    uint8_t ssid_kv[32] = {0};
    int len_kv = 32;

    if (!ssid || !len) {
        ESP_LOGI(TAG, "input ssid and len error");
        return ret;
    }
    ret = HAL_Kv_Get(AP_SSID_KEY, ssid_kv, &len_kv);
    if (ret == ESP_OK && len_kv == len) {
        if (!memcmp(ssid, ssid_kv, len)) {
            return ESP_OK;
        }
    }

    ret = HAL_Kv_Set(AP_SSID_KEY, ssid, len, 0);
    ESP_LOGI(TAG, "%s %s", __FUNCTION__, (ret == ESP_OK) ? "success" : "fail");

    return ret;
}

//设置智能配网模式
esp_err_t conn_mgr_set_sc_mode(conn_sc_mode_t mode)
{
    int ret = ESP_FAIL;
    uint8_t mode_kv = 0;
    int len_kv = sizeof(uint8_t);

    ret = HAL_Kv_Get(SC_MODE, &mode_kv, &len_kv);
    if (ret == ESP_OK) {
        if (mode == mode_kv) {
            return ESP_OK;
        }
    }

    ret = HAL_Kv_Set(SC_MODE, &mode, sizeof(uint8_t), 0);
    ESP_LOGI(TAG, "%s %s", __FUNCTION__, (ret == ESP_OK) ? "success" : "fail");

    return ret;
}
