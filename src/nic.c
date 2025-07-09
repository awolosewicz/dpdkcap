#include "nic.h"

/**
 * Default receive queue settings.
 */

static const struct rte_eth_conf port_conf_default = {
    .rxmode =
        {
            .mq_mode = RTE_ETH_MQ_RX_NONE,
            .mtu = 0x2600 - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN /* Jumbo Frames of 9.5kb */
        },
    .txmode =
        {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
        },
};

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
int
port_init(uint16_t port, const uint16_t rx_queues, unsigned int num_rxdesc, struct rte_mempool** mbuf_pools,
          unsigned int flow_control) {
    struct rte_ether_addr addr;
    struct rte_eth_conf port_conf = port_conf_default;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_fc_conf fc_conf;
    struct rte_eth_link link;
    uint16_t socket, q, tx_queues = 0;
    int retval, retry = 5;

    if (flow_control) {
        tx_queues = rx_queues;
    }

    /* Check if the port id is valid */
    if (rte_eth_dev_is_valid_port(port) == 0) {
        LOG_ERR("Port identifier %d out of range (0 to %d) or not"
                " attached.\n",
                port, rte_eth_dev_count_avail() - 1);
        return -EINVAL;
    }

    /* Get the device info and validate config*/
    socket = rte_eth_dev_socket_id(port);
    rte_eth_dev_info_get(port, &dev_info);

    /* Display the port MAC address. */
    rte_eth_macaddr_get(port, &addr);
    LOG_INFO("Port %u: MAC=%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
             ", RXdesc/queue=%d\n",
             (unsigned)port, addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2], addr.addr_bytes[3],
             addr.addr_bytes[4], addr.addr_bytes[5], num_rxdesc);

    LOG_INFO("MTU Info : Max = %huB, Min = %huB\n", dev_info.max_mtu, dev_info.min_mtu);

    LOG_INFO("TX Desc Info : Max = %hu, Min = %hu, Multiple of %hu\n", dev_info.tx_desc_lim.nb_max,
             dev_info.tx_desc_lim.nb_min, dev_info.tx_desc_lim.nb_align);

    LOG_INFO("TX Queue Info : Max = %hu\n", dev_info.max_tx_queues);

    LOG_INFO("RX Desc Info : Max = %hu, Min = %hu, Multiple of %hu\n", dev_info.rx_desc_lim.nb_max,
             dev_info.rx_desc_lim.nb_min, dev_info.rx_desc_lim.nb_align);

    LOG_INFO("RX Queue Info : Max = %hu\n", dev_info.max_rx_queues);

    /* Check that the requested number of RX queues is valid */
    if (rx_queues > dev_info.max_rx_queues) {
        LOG_ERR("Port %d can only handle up to %d RX queues (%d "
                "requested).\n",
                port, dev_info.max_rx_queues, rx_queues);
        return -EINVAL;
    }

    /* Check that the requested number of TX queues is valid */
    if (tx_queues > dev_info.max_tx_queues) {
        LOG_ERR("Port %d can only handle up to %d TX queues (%d "
                "requested).\n",
                port, dev_info.max_tx_queues, tx_queues);
        return -EINVAL;
    }

    /* Configure multiqueue (Activate Receive Side Scaling on UDP/TCP fields) */
    if (rx_queues > 1) {
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
        port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
        port_conf.rx_adv_conf.rss_conf.rss_hf = dev_info.flow_type_rss_offloads;
    }

    /* Check if the number of requested RX descriptors is valid */
    if (num_rxdesc > dev_info.rx_desc_lim.nb_max || num_rxdesc < dev_info.rx_desc_lim.nb_min
        || num_rxdesc % dev_info.rx_desc_lim.nb_align != 0) {
        LOG_ERR("Port %d cannot be configured with %d RX "
                "descriptors per queue (min:%d, max:%d, align:%d)\n",
                port, num_rxdesc, dev_info.rx_desc_lim.nb_min, dev_info.rx_desc_lim.nb_max,
                dev_info.rx_desc_lim.nb_align);
        return -EINVAL;
    }

    /* Enable jumbo frames */
    port_conf.rxmode.mtu = RTE_MIN(port_conf.rxmode.mtu, dev_info.max_mtu);

    /* Enable scatter gather */
    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER) {
        port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_SCATTER;
    }

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_queues, tx_queues, &port_conf);
    if (retval) {
        LOG_ERR("Cannot configure port: %d: %s\n", port, rte_strerror(-retval));
        return retval;
    }

    /* Allocate and set up RX queues. */
    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = port_conf.rxmode.offloads;
    if (flow_control) {
        rxq_conf.rx_drop_en = 0;
    }

    for (q = 0; q < rx_queues; q++) {
        retval = rte_eth_rx_queue_setup(port, q, num_rxdesc, socket, &rxq_conf, mbuf_pools[q]);
        if (retval) {
            LOG_ERR("Cannot setup RX queues for port: %d: %s\n", port, rte_strerror(-retval));
            return retval;
        }
    }

    /* Allocate and set up TX queue. */
    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.txmode.offloads;

    for (q = 0; q < tx_queues; q++) {
        retval = rte_eth_tx_queue_setup(port, q, TX_DESC_DEFAULT, socket, &txq_conf);
        if (retval) {
            LOG_ERR("Cannot setup TX queues for port: %d: %s\n", port, rte_strerror(-retval));
            return retval;
        }
    }

    /* Stats bindings (if more than one queue) */
    if (dev_info.max_rx_queues > 1) {
        for (q = 0; q < rx_queues; q++) {
            retval = rte_eth_dev_set_rx_queue_stats_mapping(port, q, q);
            if (retval) {
                LOG_WARN("rte_eth_dev_set_rx_queue_stats_mapping(...):"
                         " %s\n",
                         rte_strerror(-retval));
                LOG_WARN("The queues stats mapping failed. The "
                         "displayed queue stats are thus unreliable.\n");
            }
        }
    }

    /* Get link status */
    do {
        rte_eth_link_get_nowait(port, &link);
    } while (retry-- > 0 && !link.link_status && !sleep(1));

    // if still no link information, must be down
    if (!link.link_status) {
        LOG_ERR("Cannot detect valid link for port: %d\n", port);
        return -ENOLINK;
    }

    /* Enable RX in promiscuous mode for the Ethernet device. */
    rte_eth_promiscuous_enable(port);

    /* Enable flow control */
    retval = rte_eth_dev_flow_ctrl_get(port, &fc_conf);
    if (retval) {
        LOG_ERR("Cannot get flow control parameters for port: %d: %s\n", port, rte_strerror(-retval));
        return retval;
    }

    if (flow_control) {
        fc_conf.mode = RTE_ETH_FC_FULL;
        fc_conf.pause_time = 65535;
        fc_conf.send_xon = 0;
        fc_conf.mac_ctrl_frame_fwd = 1;
        fc_conf.autoneg = 0;
    } else {
        fc_conf.mode = RTE_ETH_FC_NONE;
    }

    retval = rte_eth_dev_flow_ctrl_set(port, &fc_conf);
    if (retval) {
        LOG_ERR("Cannot set flow control parameters for port: %d: %s\n", port, rte_strerror(-retval));
        return retval;
    }

    /* Start the port once everything is ready to capture */
    retval = rte_eth_dev_start(port);
    if (retval) {
        LOG_ERR("Cannot start port: %d: %s\n", port, rte_strerror(-retval));
        return retval;
    }

    return 0;
}
