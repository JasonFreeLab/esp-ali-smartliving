/*
 * JasonFreeLab
 *
 */

#include <stdio.h>
#include <string.h>
#include "nvs_flash.h"
#include "nvs.h"

#include "esp_err.h"
#include "esp_log.h"

#define NVS_PARTITION_NAME  "nvs"
#define NVS_KV              "iotkit-kv"

/*for compatible with older version*/
#define HAL_Kv_Set aos_kv_set
#define HAL_Kv_Get aos_kv_get
#define HAL_Kv_Del aos_kv_del
#define HAL_Kv_Del_By_Prefix aos_kv_del_by_prefix

static const char *TAG = "wrapper_kv";

static bool s_kv_init_flag;

esp_err_t HAL_Kv_Init(void)
{
    esp_err_t ret = ESP_OK;

    do {
        if (s_kv_init_flag == false) {
            ret = nvs_flash_init_partition(NVS_PARTITION_NAME);

            if (ret == ESP_ERR_NVS_NO_FREE_PAGES) {
                ESP_ERROR_CHECK(nvs_flash_erase_partition(NVS_PARTITION_NAME));
                ret = nvs_flash_init_partition(NVS_PARTITION_NAME);
            } else if (ret != ESP_OK) {
                ESP_LOGE(TAG, "NVS Flash init %s failed!", NVS_PARTITION_NAME);
                break;
            }

            s_kv_init_flag = true;
        }
    } while (0);

    return ret;
}

int HAL_Kv_Del(const char *key)
{
    nvs_handle handle;
    esp_err_t ret;

    char key_name[16] = {0};

    if (key == NULL) {
        ESP_LOGE(TAG, "HAL_Kv_Del Null key");
        return ESP_FAIL;
    }

    if (HAL_Kv_Init() != ESP_OK) {
        return ESP_FAIL;
    }

    ret = nvs_open_from_partition(NVS_PARTITION_NAME, NVS_KV, NVS_READWRITE, &handle);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "nvs open %s failed with %x", NVS_KV, ret);
        return ESP_FAIL;
    }

    /*max key name is 15UL*/
    memcpy(key_name, key, sizeof(key_name) - 1);

    ret = nvs_erase_key(handle, key_name);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "nvs erase key %s failed with %x", key_name, ret);
    } else {
        nvs_commit(handle);
    }

    nvs_close(handle);

    return ret;
}

int HAL_Kv_Get(const char *key, void *val, int *buffer_len)
{
    nvs_handle handle;
    esp_err_t ret;

    char key_name[16] = {0};

    if (key == NULL || val == NULL || buffer_len == NULL) {
        ESP_LOGE(TAG, "HAL_Kv_Get Null params");
        return ESP_FAIL;
    }

    if (HAL_Kv_Init() != ESP_OK) {
        return ESP_FAIL;
    }

    ret = nvs_open_from_partition(NVS_PARTITION_NAME, NVS_KV, NVS_READONLY, &handle);

    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "nvs open %s failed with %x", NVS_KV, ret);
        return ESP_FAIL;
    }
    /*max key name is 15UL*/
    memcpy(key_name, key, sizeof(key_name) - 1);

    ret = nvs_get_blob(handle, key_name, val, (size_t *) buffer_len);

    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "nvs get blob %s failed with %x", key_name, ret);
    }

    nvs_close(handle);

    return ret;
}

int HAL_Kv_Set(const char *key, const void *val, int len, int sync)
{
    nvs_handle handle;
    esp_err_t ret;

    char key_name[16] = {0};

    if (key == NULL || val == NULL || len <= 0) {
        ESP_LOGE(TAG, "HAL_Kv_Set NULL params");
        return ESP_FAIL;
    }

    if (HAL_Kv_Init() != ESP_OK) {
        return ESP_FAIL;
    }

    ret = nvs_open_from_partition(NVS_PARTITION_NAME, NVS_KV, NVS_READWRITE, &handle);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "nvs open %s failed with %x", NVS_KV, ret);
        return ESP_FAIL;
    }
    /*max key name is 15UL*/
    memcpy(key_name, key, sizeof(key_name) - 1);
    ESP_LOGI(TAG, "Set %s blob value", key_name);
    ret = nvs_set_blob(handle, key_name, val, len);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "nvs erase key %s failed with %x", key_name, ret);
    } else {
        nvs_commit(handle);
    }

    nvs_close(handle);

    return ret;
}
