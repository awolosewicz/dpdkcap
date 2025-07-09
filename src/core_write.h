#define _GNU_SOURCE
#ifndef DPDKCAP_CORE_WRITE_H
#define DPDKCAP_CORE_WRITE_H

#include <fcntl.h>
#include <sys/uio.h>

#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include "pcap.h"
#include "utils.h"

#define OUTPUT_FILENAME_LENGTH 100

/* Writing core configuration */
struct write_core_config {
    uint16_t port;
    struct rte_ring* pbuf_free_ring;
    struct rte_ring* pbuf_full_ring;
    uint16_t burst_size;
    uint16_t snaplen;
    uint16_t disk_blk_size;
    bool volatile* stop_condition;
    struct write_core_stats* stats;
    char* output_file_template;
} __rte_cache_aligned;

/* Statistics structure */
struct write_core_stats {
    char output_file[OUTPUT_FILENAME_LENGTH];
    uint16_t core_id;
    uint64_t current_file_bytes;
    uint64_t packets;
    uint64_t bytes;
    struct rte_ring* pbuf_full_ring;
} __rte_cache_aligned;

/* Launches a write task */
int write_core(const struct write_core_config* config);

#endif
