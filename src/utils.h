#ifndef DPDKCAP_UTILS_H
#define DPDKCAP_UTILS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_memory.h>

/*
 * Allow strings to be used for preprocessor #define's
 */
#define STR_EXPAND(tok) #tok
#define STR(tok)        STR_EXPAND(tok)

/*
 * Allows unused function parameters to be marked as unused to
 * avoid unnecessary compile-time warnings.
 */
#ifdef __GNUC__
#define UNUSED(x) UNUSED_##x __attribute__((__unused__))
#else
#define UNUSED(x) UNUSED_##x
#endif

/*
 * Logging definitions
 */
#define RTE_LOGTYPE_DPDKCAP    RTE_LOGTYPE_USER1

#define LOG_ERR(fmt, args...)  RTE_LOG(ERR, DPDKCAP, fmt, ##args)
#define LOG_WARN(fmt, args...) RTE_LOG(WARNING, DPDKCAP, fmt, ##args)
#define LOG_INFO(fmt, args...) RTE_LOG(INFO, DPDKCAP, fmt, ##args)

#ifdef DEBUG
#define LOG_LEVEL               RTE_LOG_DEBUG
#define LOG_DEBUG(fmt, args...) RTE_LOG(DEBUG, DPDKCAP, fmt, ##args)
#else
#define LOG_LEVEL RTE_LOG_INFO
#define LOG_DEBUG(fmt, args...)                                                                                        \
    do {                                                                                                               \
    } while (0);
#endif

char* bytes_format(uint64_t);
char* ul_format(uint64_t);
char* str_replace(const char* src, const char* find, const char* replace);

#endif
