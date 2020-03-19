#ifndef DPDKCAP_CORE_CAPTURE_H
#define DPDKCAP_CORE_CAPTURE_H

#include <sys/time.h>

#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "pcap.h"
#include "utils.h"

#define ETHER_TYPE_FLOW_CONTROL 0x8808
#define OPCODE_PAUSE 0x0001
#define PAUSE_TIME 65535

/* Core configuration structures */
struct capture_core_config {
    uint16_t port;
    uint16_t queue;
    struct rte_ring * pbuf_free_ring;
    struct rte_ring * pbuf_full_ring;
    struct rte_mempool * pause_mbuf_pool;
    uint16_t burst_size;
    uint16_t pause_burst_size;
    uint16_t snaplen;
    uint16_t disk_blk_size;
    uint16_t flow_control;
    uint16_t mw_timestamp;
    bool volatile * stop_condition;
    struct capture_core_stats * stats;
    uint32_t watermark;
} __rte_cache_aligned;

/* Statistics structure */
struct capture_core_stats {
    uint16_t core_id;
    uint64_t packets; //Packets successfully received
    uint32_t buffer_packets; //Packets in one pcap buffer
    uint64_t pause_frames; // Pause frames sent for flow control
    struct rte_ring * pbuf_free_ring;
} __rte_cache_aligned;

/* Launches a capture task */
int capture_core(const struct capture_core_config * config);

#endif
