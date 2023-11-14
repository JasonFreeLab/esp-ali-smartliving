/*
 * JasonFreeLab
 *
 */

#include <stdio.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_system.h"
#ifndef CONFIG_IDF_TARGET_ESP8266
#include "esp_chip_info.h"
#endif

#include "nvs_flash.h"
#include "nvs.h"

#include "iot_import.h"

#define MFG_PARTITION_NAME "fctry"
#define NVS_PRODUCT "aliyun-key"

static const char *TAG = "wrapper_product";

static bool s_part_init_flag;

static esp_err_t HAL_ProductParam_init(void)
{
    esp_err_t ret = ESP_OK;

    do {
        if (s_part_init_flag == false) {
            if ((ret = nvs_flash_init_partition(MFG_PARTITION_NAME)) != ESP_OK) {
                ESP_LOGE(TAG, "NVS Flash init %s failed, Please check that you have flashed fctry partition!!!", MFG_PARTITION_NAME);
                break;
            }

            s_part_init_flag = true;
        }
    } while (0);

    return ret;
}

static int HAL_GetProductParam(char *param_name, const char *param_name_str)
{
    esp_err_t ret;
    size_t read_len = 0;
    nvs_handle handle;

    do {
        if (HAL_ProductParam_init() != ESP_OK) {
            break;
        }

        if (param_name == NULL) {
            ESP_LOGE(TAG, "%s param %s NULL", __func__, param_name);
            break;
        }

        ret = nvs_open_from_partition(MFG_PARTITION_NAME, NVS_PRODUCT, NVS_READONLY, &handle);

        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "%s nvs_open failed with %x", __func__, ret);
            break;
        }

        ret = nvs_get_str(handle, param_name_str, NULL, (size_t *)&read_len);

        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "%s nvs_get_str get %s failed with %x", __func__, param_name_str, ret);
            break;
        }

        ret = nvs_get_str(handle, param_name_str, param_name, (size_t *)&read_len);

        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "%s nvs_get_str get %s failed with %x", __func__, param_name_str, ret);
        } else {
            ESP_LOGV(TAG, "%s %s %s", __func__, param_name_str, param_name);
        }

        nvs_close(handle);
    } while (0);

    return read_len;
}

int HAL_GetPartnerID(char *pid_str)
{
    if (pid_str != NULL) {
        memset(pid_str, 0x0, PID_STR_MAXLEN);
        strncpy(pid_str, "JasonFreeLab\0", PID_STR_MAXLEN);
    }

    return strlen(pid_str);
}

int HAL_GetModuleID(char *mid_str)
{
    if (mid_str != NULL) {
        memset(mid_str, 0x0, MID_STR_MAXLEN);
        strncpy(mid_str, "Module 0\0", MID_STR_MAXLEN);
    }

    return strlen(mid_str);
}

char *HAL_GetChipID(char *cid_str)
{
    esp_chip_info_t chip_info;

    if (cid_str != NULL) {
        memset(cid_str, 0x0, HAL_CID_LEN);

        esp_chip_info(&chip_info);
        switch (chip_info.model) {
#ifndef CONFIG_IDF_TARGET_ESP8266
            case CHIP_ESP32:
                strncpy(cid_str, "ESP32\0", HAL_CID_LEN);
                break;
            case CHIP_ESP32S2:
                strncpy(cid_str, "ESP32-S2\0", HAL_CID_LEN);
                break;
            case CHIP_ESP32S3:
                strncpy(cid_str, "ESP32-S3\0", HAL_CID_LEN);
                break;
            case CHIP_ESP32C3:
                strncpy(cid_str, "ESP32-C3\0", HAL_CID_LEN);
                break;
            case CHIP_ESP32C2:
                strncpy(cid_str, "ESP32-C2\0", HAL_CID_LEN);
                break;
            case CHIP_ESP32C6:
                strncpy(cid_str, "ESP32-C6\0", HAL_CID_LEN);
                break;
            case CHIP_ESP32H2:
                strncpy(cid_str, "ESP32-H2\0", HAL_CID_LEN);
                break;
            case CHIP_ESP32P4:
                strncpy(cid_str, "ESP32-P4\0", HAL_CID_LEN);
                break;
#endif
            default:
                strncpy(cid_str, "ESP8266\0", HAL_CID_LEN);
                break;
        }
    }

    return cid_str;
}

int HAL_GetDeviceID(char *device_id)
{
    if (device_id != NULL) {
        memset(device_id, 0x0, DEVICE_ID_MAXLEN);
        char device_name[DEVICE_NAME_MAXLEN] = {0};
        char product_key[PRODUCT_KEY_MAXLEN] = {0};
        HAL_GetDeviceName(device_name);
        HAL_GetProductKey(product_key);
        HAL_Snprintf(device_id, DEVICE_ID_MAXLEN, "%s.%s\0", product_key, device_name);
    }
    return strlen(device_id);
}

/**
 * @brief Get device name from user's system persistent storage
 *
 * @param [ou] device_name: array to store device name, max length is IOTX_DEVICE_NAME_LEN
 * @return the actual length of device name
 */
int HAL_GetDeviceName(char *device_name)
{
    return HAL_GetProductParam(device_name, "DeviceName");
}

/**
 * @brief Get device secret from user's system persistent storage
 *
 * @param [ou] device_secret: array to store device secret, max length is IOTX_DEVICE_SECRET_LEN
 * @return the actual length of device secret
 */
int HAL_GetDeviceSecret(char *device_secret)
{
    return HAL_GetProductParam(device_secret, "DeviceSecret");
}

/**
 * @brief Get product key from user's system persistent storage
 *
 * @param [ou] product_key: array to store product key, max length is IOTX_PRODUCT_KEY_LEN
 * @return  the actual length of product key
 */
int HAL_GetProductKey(char *product_key)
{
    return HAL_GetProductParam(product_key, "ProductKey");
}

int HAL_GetProductSecret(char *product_secret)
{
    return HAL_GetProductParam(product_secret, "ProductSecret");
}

/**
 * @brief Get firmware version
 *
 * @param [ou] version: array to store firmware version, max length is IOTX_FIRMWARE_VER_LEN
 * @return the actual length of firmware version
 */
int HAL_GetFirmwareVersion(char *version)
{
    if (version == NULL) {
        ESP_LOGE(TAG, "%s version is NULL", __func__);
        return 0;
    }

    memset(version, 0, FIRMWARE_VERSION_MAXLEN);
    int len = strlen(CONFIG_LINKKIT_FIRMWARE_VERSION);
    if (len > FIRMWARE_VERSION_MAXLEN) {
        len = 0;
    } else {
        memcpy(version, CONFIG_LINKKIT_FIRMWARE_VERSION, len);
    }

    return len;
}

static int HAL_SetProductParam(char *param_name, const char *param_name_str)
{
    esp_err_t ret;
    size_t write_len = 0;
    nvs_handle handle;

    if (HAL_ProductParam_init() != ESP_OK) {
        return ESP_FAIL;
    }

    if (param_name == NULL) {
        ESP_LOGE(TAG, "%s param %s NULL", __func__, param_name);
        return ESP_FAIL;
    }

    ret = nvs_open_from_partition(MFG_PARTITION_NAME, NVS_PRODUCT, NVS_READWRITE, &handle);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "%s nvs_open failed with %x", __func__, ret);
        return ESP_FAIL;
    }

    ret = nvs_set_str(handle, param_name_str, param_name);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "%s nvs_set_str set %s failed with %x", __func__, param_name_str, ret);
    } else {
        write_len = strlen(param_name);
        ESP_LOGV(TAG, "%s %s %s", __func__, param_name_str, param_name);
    }

    nvs_close(handle);

    return write_len;
}

int HAL_SetDeviceName(char *device_name)
{
    return HAL_SetProductParam(device_name, "DeviceName");
}

int HAL_SetDeviceSecret(char *device_secret)
{
    return HAL_SetProductParam(device_secret, "DeviceSecret");
}

int HAL_SetProductKey(char *product_key)
{
    return HAL_SetProductParam(product_key, "ProductKey");
}

int HAL_SetProductSecret(char *product_secret)
{
    return HAL_SetProductParam(product_secret, "ProductSecret");
}
