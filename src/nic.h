#ifndef DPDKCAP_NIC_H
#define DPDKCAP_NIC_H

#include <rte_ethdev.h>

#include "utils.h"

#define TX_DESC_DEFAULT 1024

int port_init(
    uint16_t port,
    const uint16_t rx_queues,
    unsigned int num_rxdesc,
    struct rte_mempool ** mbuf_pools,
    unsigned int flow_control);

#endif
