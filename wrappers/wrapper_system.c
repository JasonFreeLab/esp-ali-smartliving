/*
 * JasonFreeLab
 *
 */


#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>
#include <netinet/in.h>

#include "esp_timer.h"
#include "esp_system.h"

#ifdef CONFIG_IDF_TARGET_ESP8266
#include "tcpip_adapter.h"
#else
#include "esp_netif.h"
#endif

#include "iot_import.h"

extern int HAL_Fclose(void *stream)
{
    return (int)1;
}

extern void *HAL_Fopen(const char *path, const char *mode)
{
    return (void*)1;
}

extern uint32_t HAL_Fread(void *buff, uint32_t size, uint32_t count, void *stream)
{
    return (uint32_t)1;
}

extern int HAL_Fseek(void *stream, long offset, int framewhere)
{
    return (int)1;
}

extern long HAL_Ftell(void *stream)
{
    return (long)1;
}

extern uint32_t HAL_Fwrite(const void *ptr, uint32_t size, uint32_t count, void *stream)
{
    return (uint32_t)1;
}

/**
 * @brief Allocates a block of size bytes of memory, returning a pointer to the beginning of the block.
 *
 * @param [in] size @n specify block size in bytes.
 * @return A pointer to the beginning of the block.
 * @see None.
 * @note Block value is indeterminate.
 */
void *HAL_Malloc(uint32_t size)
{
    return calloc(1,size);
}

/**
 * @brief Deallocate memory block
 *
 * @param[in] ptr @n Pointer to a memory block previously allocated with platform_malloc.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_Free(void *ptr)
{
    free(ptr);
}

extern void *HAL_Realloc(void *ptr, uint32_t size)
{
    return realloc(ptr, size);
}


/**
 * @brief Writes formatted data to stream.
 *
 * @param [in] fmt: @n String that contains the text to be written, it can optionally contain embedded format specifiers
     that specifies how subsequent arguments are converted for output.
 * @param [in] ...: @n the variable argument list, for formatted and inserted in the resulting string replacing their respective specifiers.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_Printf(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    fflush(stdout);
}

/**
 * @brief Writes formatted data to string.
 *
 * @param [out] str: @n String that holds written text.
 * @param [in] len: @n Maximum length of character will be written
 * @param [in] fmt: @n Format that contains the text to be written, it can optionally contain embedded format specifiers
     that specifies how subsequent arguments are converted for output.
 * @param [in] ...: @n the variable argument list, for formatted and inserted in the resulting string replacing their respective specifiers.
 * @return bytes of character successfully written into string.
 * @see None.
 * @note None.
 */
int HAL_Snprintf(char *str, const int len, const char *fmt, ...)
{
    va_list args;
    int     rc;

    va_start(args, fmt);
    rc = vsnprintf(str, len, fmt, args);
    va_end(args);

    return rc;
}

int HAL_Vsnprintf(char *str, const int len, const char *format, va_list ap)
{
    return vsnprintf(str, len, format, ap);
}

uint32_t HAL_Random(uint32_t region)
{
    return (region != 0) ? (esp_random() % region) : 0;
}

void HAL_Srandom(uint32_t seed)
{
    return;
}

void HAL_Reboot()
{
    esp_restart();
}

/**
 * @brief Sleep thread itself.
 *
 * @param [in] ms @n the time interval for which execution is to be suspended, in milliseconds.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_SleepMs(uint32_t ms)
{
    usleep(1000 * ms);
}

/**
 * @brief Retrieves the number of milliseconds that have elapsed since the system was boot.
 *
 * @return the number of milliseconds.
 * @see None.
 * @note None.
 */
uint64_t HAL_UptimeMs(void)
{
    return (esp_timer_get_time()/1000);
}

/**
 * @brief check system network is ready(get ip address) or not.
 *
 * @param None.
 * @return 0, net is not ready; 1, net is ready.
 * @see None.
 * @note None.
 */
int HAL_Sys_Net_Is_Ready()
{
    #ifdef CONFIG_IDF_TARGET_ESP8266
    tcpip_adapter_ip_info_t local_ip;
    esp_err_t ret = tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &local_ip);
    #else
    esp_netif_ip_info_t local_ip;
    esp_err_t ret = esp_netif_get_ip_info(esp_netif_get_handle_from_ifkey("WIFI_STA_DEF"), &local_ip);
    #endif

    if ((ESP_OK == ret) && (local_ip.ip.addr != INADDR_ANY)) {
        return 1;
    }

    return 0;
}
