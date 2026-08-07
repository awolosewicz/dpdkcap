#include "core_capture.h"
#include <rte_ethdev.h>
#include <infiniband/mlx5dv.h>

struct ether_fc_frame {
    uint16_t opcode;
    uint16_t param;
} __rte_packed;

static inline void
prepare_pause_frame(uint16_t port, struct rte_mbuf* mbuf) {
    struct ether_fc_frame* pause_frame;
    struct rte_ether_hdr* hdr;

    /* Prepare a PAUSE frame */
    hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
    pause_frame = (struct ether_fc_frame*)&hdr[1];
    rte_eth_macaddr_get(port, &hdr->src_addr);

    void* tmp = &hdr->dst_addr.addr_bytes[0];
    *((uint64_t*)tmp) = 0x010000C28001ULL;

    hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_FLOW_CONTROL);
    pause_frame->opcode = rte_cpu_to_be_16(OPCODE_PAUSE);
    pause_frame->param = rte_cpu_to_be_16(PAUSE_TIME);
    mbuf->pkt_len = 60;
    mbuf->data_len = 60;
}

static inline void
clone_pause_frames(const struct rte_mbuf* original, struct rte_mbuf** clones, int num, struct rte_mempool* pool) {
    if (unlikely(rte_pktmbuf_alloc_bulk(pool, clones, num))) {
        rte_exit(EXIT_FAILURE,
                 "Error: Could not allocate pause frame buffers "
                 "for cloning on Core %d\n",
                 rte_lcore_id());
    }
    for (int i = 0; i < num; i++) {
        clones[i]->pkt_len = 60;
        clones[i]->data_len = 60;
        rte_mov64(rte_pktmbuf_mtod(clones[i], void*), rte_pktmbuf_mtod(original, void*));
    }
}

static inline uint16_t
send_pause_frames(uint16_t port, uint16_t queue, const struct rte_mbuf* pause_frame, struct rte_mbuf** pause_mbufs,
                  uint16_t num, struct rte_mempool* pool) {
    uint16_t nb_tx = rte_eth_tx_burst(port, queue, pause_mbufs, num);
    if (likely(nb_tx)) {
        clone_pause_frames(pause_frame, pause_mbufs, nb_tx, pool);
    }
    return nb_tx;
}

void
wait_link_up(const struct capture_core_config* config, bool wait) {
    struct rte_eth_link link;
    int retstat = 0;

    if (wait) {
        retstat = rte_eth_link_get(config->port, &link);
    } else {
        retstat = rte_eth_link_get_nowait(config->port, &link);
    }

    if (link.link_status != RTE_ETH_LINK_UP) {
        while (link.link_status != RTE_ETH_LINK_UP) {
            if (unlikely(retstat < 0)) {
                LOG_INFO("Error on retrieving link status for port %u: %s\n", config->port, rte_strerror(-retstat));
                return;
            }
            LOG_INFO("Capture core %u waiting for port %u to come up\n", rte_lcore_id(), config->port);
            retstat = rte_eth_link_get(config->port, &link);
        }

        LOG_INFO("Core %u is capturing packets for port %u at %u Mbps\n", rte_lcore_id(), config->port,
                 link.link_speed);
    }
}

/* TS function from app/test-pmd/util.c */
static inline rte_mbuf_timestamp_t
get_timestamp(const struct rte_mbuf *mbuf)
{
	static int timestamp_dynfield_offset = -1;

	if (timestamp_dynfield_offset < 0) {
		timestamp_dynfield_offset = rte_mbuf_dynfield_lookup(
				RTE_MBUF_DYNFIELD_TIMESTAMP_NAME, NULL);
		if (timestamp_dynfield_offset < 0)
			return 0;
	}

	return *RTE_MBUF_DYNFIELD(mbuf,
			timestamp_dynfield_offset, rte_mbuf_timestamp_t *);
}

static inline uint64_t timespec64_to_ns(const struct timespec *ts)
{
	return ((uint64_t) ts->tv_sec * NS_PER_S) + ts->tv_nsec;
}

/*
 * Capture the traffic from the given port/queue tuple
 */
int
capture_core(const struct capture_core_config* config) {
    const unsigned socket_id = rte_socket_id();
    unsigned dev_socket_id;

    volatile bool* stop_condition = config->stop_condition;

    const uint16_t port = config->port;
    const uint16_t queue = config->queue;

    const uint16_t burst_size = config->burst_size;
    struct rte_mbuf* bufs[burst_size];
    struct rte_mbuf* bufptr;

    struct rte_mempool* pause_mbuf_pool = config->pause_mbuf_pool;
    const uint16_t flow_control = config->flow_control;
    const uint16_t pause_burst_size = config->pause_burst_size;
    struct rte_mbuf* pause_mbufs[pause_burst_size];
    struct rte_mbuf* pause_frame = NULL;

    struct rte_ring* pbuf_free_ring = config->pbuf_free_ring;
    struct rte_ring* pbuf_full_ring = config->pbuf_full_ring;
    const uint32_t watermark = config->watermark;

    struct pcap_buffer* buffer = NULL;
    struct pcap_packet_header* header;
    size_t header_size = sizeof(struct pcap_packet_header);
    uint32_t packet_length;

    const uint16_t mw_timestamp = config->mw_timestamp;
    uint64_t ts_hw, ts_ns;
    struct timespec timespec64;
    uint64_t hw_freq = 0; /* Observed frequency in hz of the HW clock */
    uint64_t startup_ts;
    uint32_t startup_s, startup_ns;
    uint64_t startup_hw;
    unsigned char* trailer_base;
    uint64_t burst_ns = 0;
    bool ts_checked = false, ts_hw_missing = false;

    const uint16_t disk_blk_size = config->disk_blk_size;
    uint16_t i, nb_rx;
    unsigned int overrun = 0, overrun_start = 0, flush = 0;
    unsigned char* oldbuf = NULL;

    LOG_INFO("Core %u is capturing packets for port %u\n", rte_lcore_id(), port);

    dev_socket_id = rte_eth_dev_socket_id(port);
    if (dev_socket_id != socket_id) {
        LOG_WARN("Port %u on different socket from worker; performance will suffer\n", port);
    }

    /* Init stats */
    config->stats->core_id = rte_lcore_id();
    config->stats->pbuf_free_ring = config->pbuf_free_ring;

    wait_link_up(config, true);

    if (flow_control) {
        pause_frame = rte_pktmbuf_alloc(pause_mbuf_pool);
        if (!pause_frame) {
            rte_exit(EXIT_FAILURE,
                     "Error: Could not allocate pause frame buffer "
                     "on Core %d\n",
                     rte_lcore_id());
        }
        prepare_pause_frame(port, pause_frame);
        clone_pause_frames(pause_frame, pause_mbufs, pause_burst_size, pause_mbuf_pool);
    } else {
        config->stats->pause_frames = ~0UL;
    }

    if (!rte_ring_sc_dequeue_bulk(pbuf_free_ring, (void**)&buffer, 1, NULL)) {
        rte_exit(EXIT_FAILURE,
                 "Error: Could not obtain an empty packet buffer (PBUF) "
                 "on Core %d\n",
                 rte_lcore_id());
    }

    if (!mw_timestamp) {
        uint64_t t1 = 0, t2 = 0, w1, w2;
        int retval;

        /*
         * Bracket the device clock reads with wall clock reads so the
         * frequency estimate uses the measured elapsed time rather than
         * assuming the delay was exactly one second
         */
        clock_gettime(CLOCK_REALTIME, &timespec64);
        w1 = timespec64_to_ns(&timespec64);
        retval = rte_eth_read_clock(port, &t1);
        rte_delay_ms(1000);
        if (retval == 0) {
            retval = rte_eth_read_clock(port, &t2);
        }
        clock_gettime(CLOCK_REALTIME, &timespec64);
        w2 = timespec64_to_ns(&timespec64);

        if (retval < 0) {
            LOG_WARN("Cannot read device clock on port %u (%s); "
                     "falling back to software timestamps\n",
                     port, rte_strerror(-retval));
            hw_freq = 0;
            startup_hw = 0;
            startup_s = 0;
            startup_ns = 0;
        }
        else {
            hw_freq = ((t2 - t1) * NS_PER_S) / (w2 - w1);
            rte_eth_read_clock(port, &startup_hw);
            clock_gettime(CLOCK_REALTIME, &timespec64);
            startup_ts = timespec64_to_ns(&timespec64);
            startup_s = (uint32_t)(startup_ts / NS_PER_S);
            startup_ns = (uint32_t)(startup_ts % NS_PER_S);
            LOG_INFO("Port %u device clock calibrated at %lu Hz over %lu ns\n",
                     port, hw_freq, w2 - w1);
        }
    }

    /*
     * Without a usable device clock the only remaining source of arrival
     * time is the host clock, sampled once per burst
     */
    const bool sw_timestamp = !mw_timestamp && hw_freq == 0;

    if (sw_timestamp) {
        LOG_WARN("Port %u capture on core %u is using software timestamps\n", port, rte_lcore_id());
    }

    /* Run until the application is quit or killed. */

    uint64_t total_captured = 0;

    while (likely(!(*stop_condition))) {

        /* Retrieve packets and put them into the ring */
        nb_rx = rte_eth_rx_burst(port, queue, bufs, burst_size);

        if (likely(nb_rx > 0)) {

            if (unlikely(sw_timestamp || ts_hw_missing)) {
                clock_gettime(CLOCK_REALTIME, &timespec64);
                burst_ns = timespec64_to_ns(&timespec64);
            }

            for (i = 0; i < nb_rx; i++) {
                bufptr = bufs[i];

                header = (struct pcap_packet_header*)(buffer->buffer + buffer->offset);
                buffer->offset += header_size;

                packet_length = bufptr->pkt_len;

                header->packet_length = 16;
                header->packet_length_wire = packet_length;

                if (unlikely(bufptr->nb_segs > 1)) {
                    /*
                     * Walk to the tail 16 bytes, which may straddle the
                     * final segment boundary
                     */
                    uint32_t remaining = 16;
                    uint32_t skip = packet_length - 16;
                    struct rte_mbuf* seg = bufptr;
                    while (skip >= seg->data_len) {
                        skip -= seg->data_len;
                        seg = seg->next;
                    }
                    while (remaining > 0) {
                        uint32_t take = RTE_MIN(remaining, seg->data_len - skip);
                        rte_memcpy(buffer->buffer + buffer->offset, rte_pktmbuf_mtod_offset(seg, void*, skip), take);
                        buffer->offset += take;
                        remaining -= take;
                        skip = 0;
                        seg = seg->next;
                    }
                } else {
                    rte_mov16(buffer->buffer + buffer->offset, rte_pktmbuf_mtod_offset(bufptr, void*, packet_length-16));
                    buffer->offset += 16;
                }

                if (mw_timestamp) {
                    trailer_base = buffer->buffer + buffer->offset - 12;
                    header->seconds = ntohl(*(uint32_t*)trailer_base);
                    header->nanoseconds = ntohl(*(uint32_t*)(trailer_base + 4));
                } else if (unlikely(sw_timestamp || ts_hw_missing)) {
                    header->seconds = (uint32_t)(burst_ns / NS_PER_S);
                    header->nanoseconds = (uint32_t)(burst_ns % NS_PER_S);
                } else {
                    ts_hw = get_timestamp(bufptr);

                    /* A zero on the first packet means the dynfield is absent */
                    if (unlikely(!ts_checked)) {
                        ts_checked = true;
                        ts_hw_missing = (ts_hw == 0);
                        if (ts_hw_missing) {
                            LOG_WARN("Port %u delivers no HW timestamps; "
                                     "using software timestamps\n",
                                     port);
                            clock_gettime(CLOCK_REALTIME, &timespec64);
                            burst_ns = timespec64_to_ns(&timespec64);
                        }
                    }

                    if (unlikely(ts_hw_missing)) {
                        header->seconds = (uint32_t)(burst_ns / NS_PER_S);
                        header->nanoseconds = (uint32_t)(burst_ns % NS_PER_S);
                    } else {
                        uint64_t delta = ts_hw - startup_hw;
                        uint64_t ns = (uint64_t)startup_ns + ((delta % hw_freq) * NS_PER_S) / hw_freq;
                        header->seconds = (uint32_t)(delta / hw_freq) + startup_s + (uint32_t)(ns / NS_PER_S);
                        header->nanoseconds = (uint32_t)(ns % NS_PER_S);
                    }
                }

                rte_pktmbuf_free(bufptr);
            }

            /* Update stats */
            config->stats->packets += nb_rx;
            config->stats->buffer_packets += nb_rx;
            flush = 0;
            total_captured += nb_rx;
        } else {
            flush++;
        }

        /* Enqueue buffer to be flushed if full and get a new one */
        if (buffer->offset > watermark || (flush > 9999999 && buffer->offset > disk_blk_size)) {
            buffer->packets = config->stats->buffer_packets;
            overrun = buffer->offset % disk_blk_size;
            if (overrun) {
                buffer->offset -= overrun;
                overrun_start = buffer->offset;
                oldbuf = buffer->buffer;
            }

            while (!(rte_ring_sp_enqueue_bulk(pbuf_full_ring, (void**)&buffer, 1, NULL) || unlikely(*stop_condition))) {
                if (flow_control) {
                    config->stats->pause_frames +=
                        send_pause_frames(port, queue, pause_frame, pause_mbufs, pause_burst_size, pause_mbuf_pool);
                }
            }

            config->stats->buffer_packets = 0;

            while (!(rte_ring_sc_dequeue_bulk(pbuf_free_ring, (void**)&buffer, 1, NULL) || unlikely(*stop_condition))) {
                if (flow_control) {
                    config->stats->pause_frames +=
                        send_pause_frames(port, queue, pause_frame, pause_mbufs, pause_burst_size, pause_mbuf_pool);
                }
            }

            if (overrun) {
                rte_memcpy(buffer->buffer, oldbuf + overrun_start, overrun);
                buffer->offset += overrun;
            }
        }
    }

    if (buffer->offset) {
        buffer->packets = config->stats->buffer_packets;
        unsigned int underrun = disk_blk_size - (buffer->offset % disk_blk_size);
        memset(buffer->buffer + buffer->offset, 0, underrun);
        if (underrun > header_size) {
            add_pad_packet((struct pcap_packet_header*)(buffer->buffer + buffer->offset), underrun);
        }
        buffer->offset += underrun;
        rte_ring_sp_enqueue_bulk(pbuf_full_ring, (void**)&buffer, 1, NULL);
    }

    LOG_INFO("Closed capture core %d (port %d)\n", rte_lcore_id(), port);

    return 0;
}
