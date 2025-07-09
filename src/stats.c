#include "stats.h"

/*
 * Prints a set of stats
 */
static int
print_stats(__attribute__((unused)) struct rte_timer* timer, struct stats_data* data) {
    static unsigned int nb_stat_update = 0;
    static struct rte_eth_stats port_stats;

    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    unsigned int i, j;

    nb_stat_update++;

    for (i = 0; i < data->nb_queues; i++) {
        total_packets += data->write_core_stats[i].packets;
        total_bytes += data->write_core_stats[i].bytes;
    }

    printf("\e[1;1H\e[2J");
    printf("=== Packet capture stats %c ===\n", ROTATING_CHAR[nb_stat_update % 4]);

    printf("-- GLOBAL --\n");
    printf("Total packets written: %lu\n", total_packets);
    printf("Total bytes written: %s\n", bytes_format(total_bytes));

    printf("-- PER WRITING CORE --\n");
    for (i = 0; i < data->nb_queues; i++) {
        printf("Writing core %d: %s ", data->write_core_stats[i].core_id, data->write_core_stats[i].output_file);
        printf("(%s)\n", bytes_format(data->write_core_stats[i].current_file_bytes));
    }

    printf("-- PER PORT --\n");
    for (i = 0; i < data->nb_ports; i++) {
        rte_eth_stats_get(data->port_list[i], &port_stats);
        printf("- PORT %d -\n", data->port_list[i]);
        printf("Built-in counters:\n"
               "  RX Successful packets: %lu\n"
               "  RX Successful bytes: %s (avg: %d bytes/pkt)\n"
               "  RX Unsuccessful packets: %lu\n"
               "  RX Missed packets: %lu\n  No MBUF: %lu\n",
               port_stats.ipackets, bytes_format(port_stats.ibytes),
               port_stats.ipackets ? (int)((float)port_stats.ibytes / (float)port_stats.ipackets) : 0,
               port_stats.ierrors, port_stats.imissed, port_stats.rx_nombuf);
        printf("Per queue:\n");
        for (j = 0; j < data->nb_queues_per_port; j++) {
            printf("  Queue %d RX: %lu RX-Error: %lu\n", j, port_stats.q_ipackets[j], port_stats.q_errors[j]);
        }
        printf("  (%d queues hidden)\n", RTE_ETHDEV_QUEUE_STAT_CNTRS - data->nb_queues_per_port);
    }

    printf("===================================\n");
    return 0;
}

static struct rte_timer stats_timer;

void
start_stats_display(struct stats_data* data, bool volatile* stop_condition) {
    //Initialize timers
    rte_timer_subsystem_init();
    rte_timer_init(&(stats_timer));

    //Timer launch
    rte_timer_reset(&(stats_timer), rte_get_timer_hz() * STATS_PERIOD_MS, PERIODICAL, rte_lcore_id(),
                    (void*)print_stats, data);

    //Wait for ctrl+c
    while (likely(!(*stop_condition))) {
        rte_timer_manage();
        rte_delay_us(1000000 * rte_timer_next_ticks() / rte_get_timer_hz());
    }

    rte_timer_stop(&(stats_timer));
}
