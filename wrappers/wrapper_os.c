/*
 * JasonFreeLab
 *
 */

#include <sys/time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/timers.h"

#include "pthread.h"
#include "esp_wifi.h"
#include "esp_log.h"
#ifndef CONFIG_IDF_TARGET_ESP8266
#include "esp_mac.h"
#endif

#include "iot_import.h"

static const char *TAG = "wrapper_os";

#ifdef CONFIG_IDF_TARGET_ESP8266
#if __has_include("esp_idf_version.h")
#include "esp_idf_version.h"
#else
/** Major version number (X.x.x) */
#define ESP_IDF_VERSION_MAJOR   3
/** Minor version number (x.X.x) */
#define ESP_IDF_VERSION_MINOR   2
/** Patch version number (x.x.X) */
#define ESP_IDF_VERSION_PATCH   0
#define ESP_IDF_VERSION_VAL(major, minor, patch) ((major << 16) | (minor << 8) | (patch))
#define ESP_IDF_VERSION  ESP_IDF_VERSION_VAL(ESP_IDF_VERSION_MAJOR, \
                                             ESP_IDF_VERSION_MINOR, \
                                             ESP_IDF_VERSION_PATCH)
#endif

#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(3, 3, 0)
// notes: pthread_exit has already defined on ESP-IDF
void pthread_exit(void *value_ptr)
{
    ESP_LOGE(TAG, "%s: esp82666 not supported!", __FUNCTION__);
}
#endif
#endif

static long long os_time_get(void)
{
    struct timeval tv;
    long long ms;
    gettimeofday(&tv, NULL);
    ms = tv.tv_sec * 1000LL + tv.tv_usec / 1000;
    return ms;
}

static long long delta_time = 0;

void HAL_UTC_Set(long long ms)
{
    delta_time = ms - os_time_get();
}

long long HAL_UTC_Get(void)
{
    return delta_time + os_time_get();
}

/**
 * @brief Create a mutex.
 *
 * @retval NULL : Initialize mutex failed.
 * @retval NOT_NULL : The mutex handle.
 * @see None.
 * @note None.
 */
void *HAL_MutexCreate(void)
{
    return (void *)xSemaphoreCreateMutex();
}

/**
 * @brief Destroy the specified mutex object, it will release related resource.
 *
 * @param [in] mutex @n The specified mutex.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_MutexDestroy(void *mutex)
{
    if (mutex) {
        vSemaphoreDelete((SemaphoreHandle_t)mutex);
    }
}

/**
 * @brief Waits until the specified mutex is in the signaled state.
 *
 * @param [in] mutex @n the specified mutex.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_MutexLock(void *mutex)
{
    if (mutex) {
        xSemaphoreTake((SemaphoreHandle_t)mutex, portMAX_DELAY);
    }
}

/**
 * @brief Releases ownership of the specified mutex object..
 *
 * @param [in] mutex @n the specified mutex.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_MutexUnlock(void *mutex)
{
    if (mutex) {
        xSemaphoreGive((SemaphoreHandle_t)mutex);
    }
}

/**
 * @brief   create a semaphore
 *
 * @return semaphore handle.
 * @see None.
 * @note The recommended value of maximum count of the semaphore is 255.
 */
void *HAL_SemaphoreCreate(void)
{
    return (void *)xSemaphoreCreateCounting(CONFIG_HAL_SEM_MAX_COUNT, CONFIG_HAL_SEM_INIT_COUNT);
}

/**
 * @brief   destory a semaphore
 *
 * @param[in] sem @n the specified sem.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_SemaphoreDestroy(void *sem)
{
    if (sem) {
        vSemaphoreDelete((SemaphoreHandle_t)sem);
    }
}

/**
 * @brief   signal thread wait on a semaphore
 *
 * @param[in] sem @n the specified semaphore.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_SemaphorePost(void *sem)
{
    if (sem) {
        xSemaphoreGive((SemaphoreHandle_t)sem);
    }
}

/**
 * @brief   wait on a semaphore
 *
 * @param[in] sem @n the specified semaphore.
 * @param[in] timeout_ms @n timeout interval in millisecond.
     If timeout_ms is PLATFORM_WAIT_INFINITE, the function will return only when the semaphore is signaled.
 * @return
   @verbatim
   =  0: The state of the specified object is signaled.
   =  -1: The time-out interval elapsed, and the object's state is nonsignaled.
   @endverbatim
 * @see None.
 * @note None.
 */
int HAL_SemaphoreWait(void *sem, uint32_t timeout_ms)
{
    if (pdPASS == xSemaphoreTake((SemaphoreHandle_t)sem, timeout_ms)) {
        return SUCCESS_RETURN;
    }

    return FAIL_RETURN;
}

/**
 * @brief  create a thread
 *
 * @param[out] thread_handle @n The new thread handle, memory allocated before thread created and return it, free it after thread joined or exit.
 * @param[in] start_routine @n A pointer to the application-defined function to be executed by the thread.
        This pointer represents the starting address of the thread.
 * @param[in] arg @n A pointer to a variable to be passed to the start_routine.
 * @param[in] hal_os_thread_param @n A pointer to stack params.
 * @param[out] stack_used @n if platform used stack buffer, set stack_used to 1, otherwise set it to 0.
 * @return
   @verbatim
     = 0: on success.
     = -1: error occur.
   @endverbatim
 * @see None.
 * @note None.
 */
int HAL_ThreadCreate(
    void **thread_handle,
    void *(*work_routine)(void *),
    void *arg,
    hal_os_thread_param_t *hal_os_thread_param,
    int *stack_used)
{
    int ret = -1;
    pthread_attr_t attr = {0};

    if (!thread_handle || !work_routine || 
        !hal_os_thread_param || !stack_used) {
        return NULL_VALUE_ERROR;
    }

    *stack_used = 0;
    ESP_LOGI(TAG, "task name is %s\n", hal_os_thread_param->name);

    if (hal_os_thread_param->stack_size == 0) {
        ret = pthread_create((pthread_t *)thread_handle, NULL, work_routine, arg);
    } else {
        attr.stacksize = hal_os_thread_param->stack_size;
        ret = pthread_create((pthread_t *)thread_handle, &attr, work_routine, arg);
    }
    return ret;

}

void HAL_ThreadDelete(void *thread_handle)
{
    if (NULL == thread_handle) {
        pthread_exit(0);
    } else {
        /*main thread delete child thread*/
        pthread_cancel((pthread_t) thread_handle);
        pthread_join((pthread_t) thread_handle, 0);
    }

}

void HAL_ThreadDetach(void *thread_handle)
{
    pthread_detach((pthread_t)thread_handle);
}

void *HAL_Timer_Create(const char *name, void (*func)(void *), void *user_data)
{
    TimerHandle_t timer_handle = NULL;
    timer_handle = xTimerCreate(name, portMAX_DELAY, pdFALSE, NULL, (TimerCallbackFunction_t)func);

    return (void *)timer_handle;
}

int HAL_Timer_Delete(void *timer)
{
    if (!timer) {
        return FAIL_RETURN;
    }

    if (pdTRUE == xTimerDelete((TimerHandle_t)timer, portMAX_DELAY)) {
        return SUCCESS_RETURN;
    }

    return FAIL_RETURN;
}

int HAL_Timer_Start(void *timer, int ms)
{
    if (!timer) {
        return FAIL_RETURN;
    }

    uint32_t ticks = ms / portTICK_PERIOD_MS;
    if (ticks == 0) {
        ticks = 1;
    }

    if (xTimerChangePeriod(timer, ticks, portMAX_DELAY) != pdTRUE) {
        return FAIL_RETURN;
    }
    if (xTimerStart((TimerHandle_t)timer, portMAX_DELAY) != pdTRUE) {
        return FAIL_RETURN;
    }

    return SUCCESS_RETURN;
}

int HAL_Timer_Stop(void *timer)
{
    if (!timer) {
        return FAIL_RETURN;
    }

    if (pdTRUE == xTimerStop((TimerHandle_t)timer, portMAX_DELAY)) {
        return SUCCESS_RETURN;
    }

    return FAIL_RETURN;
}

int HAL_GetNetifInfo(char *nif_str)
{
    memset(nif_str, 0x0, NIF_STRLEN_MAX);
    /* if the device have only WIFI, then list as follow, note that the len MUST NOT exceed NIF_STRLEN_MAX */
    char net_info[NIF_STRLEN_MAX + 1] = {0} ;
    uint8_t mac[6] = {0};
    esp_err_t ret = esp_wifi_get_mac(WIFI_IF_STA, mac);

    if (ret != ESP_OK) {
        return 0;
    }

    sprintf(net_info, "WIFI|%02X%02X%02X%02X%02X%02X", MAC2STR(mac));
    strncpy(nif_str, net_info, NIF_STRLEN_MAX);
    /* if the device have ETH, WIFI, GSM connections, then list all of them as follow, note that the len MUST NOT exceed NIF_STRLEN_MAX */
    // const char *multi_net_info = "ETH|0123456789abcde|WiFi|03ACDEFF0032|Cellular|imei_0123456789abcde|iccid_0123456789abcdef01234|imsi_0123456789abcde|msisdn_86123456789ab");
    // strncpy(nif_str, multi_net_info, strlen(multi_net_info));
    return strlen(nif_str);
}
