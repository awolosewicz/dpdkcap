#ifndef DPDKCAP_STATISTICS_H
#define DPDKCAP_STATISTICS_H

#include <unistd.h>

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_timer.h>

#include "core_capture.h"
#include "core_write.h"
#include "utils.h"

#define STATS_PERIOD_MS 500
#define ROTATING_CHAR   "-\\|/"

struct stats_data {
    uint16_t* port_list;
    struct write_core_stats* write_core_stats;
    struct capture_core_stats* capture_core_stats;
    uint16_t nb_ports;
    uint16_t nb_queues;
    uint16_t nb_queues_per_port;
    char* log_file;
} __rte_cache_aligned;

/*
 * Starts a non blocking stats display
 */
void start_stats_display(struct stats_data* data, bool volatile* stop_condition);

#endif
