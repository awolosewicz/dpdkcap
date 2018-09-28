#include <ncurses.h>

#include "stats.h"

static uint64_t * last_per_cap_core_pkts;
static uint64_t * last_per_wr_core_pkts;
static uint64_t * last_per_wr_core_bytes;

static void wcapture_stats(WINDOW * window, struct stats_data * data) {
    unsigned int i,j;
    static struct rte_eth_stats port_stats;

    for (i=0; i<data->nb_ports; i++) {
        rte_eth_stats_get(data->port_list[i], &port_stats);

        wprintw(window,"PORT %d:\n", data->port_list[i]);
        wprintw(window,"  RX Successful bytes: %s (avg: %d bytes/pkt)\n",
                bytes_format(port_stats.ibytes),
                port_stats.ipackets?(int)((float)port_stats.ibytes/
                    (float)port_stats.ipackets):0);
        wprintw(window, "  RX Successful packets: %s\n",
                ul_format(port_stats.ipackets));
        wprintw(window, "  RX Unsuccessful packets: %s\n",
                ul_format(port_stats.ierrors));
        wprintw(window, "  RX Missed packets: %s\n",
                ul_format(port_stats.imissed));
        wprintw(window, "  MBUF Allocation failures: %s\n",
                ul_format(port_stats.rx_nombuf));

        for (j=i*data->nb_queues_per_port; j<(i+1)*data->nb_queues_per_port; j++) {
            wprintw(window, "  - Queue %2d handled by core %2d:\n", j,
                    data->capture_core_stats[j].core_id);
            wprintw(window, "      HW: RX: %s",
                    ul_format(port_stats.q_ipackets[j]));
            wprintw(window, "  RX-Error: %s\n",
                    ul_format(port_stats.q_errors[j]));

            wprintw(window, "      SW: RX: %s",
                    ul_format(data->capture_core_stats[j].packets));
            wprintw(window, "    Buffer: %s\n",
                    ul_format(data->capture_core_stats[j].buffer_packets));

            wprintw(window, "      Buffers Free: %s\n",
                    ul_format(rte_ring_count(data->capture_core_stats[j].pbuf_free_ring)));

            uint64_t pframes = data->capture_core_stats[j].pause_frames;
            if (pframes == ~0UL)
                wprintw(window, "      Pause Frames: <Disabled>\n");
            else
                wprintw(window, "      Pause Frames: %s\n", ul_format(pframes));

            wprintw(window, "      Pkts/s: %s\n",
                    ul_format((data->capture_core_stats[j].packets-
                               last_per_cap_core_pkts[j])*1000/STATS_PERIOD_MS));

            last_per_cap_core_pkts[j] = data->capture_core_stats[j].packets;

            wprintw(window, "\n");

        }
    }
}

static void wwrite_stats(WINDOW * window, struct stats_data * data) {
    uint64_t total_packets, total_bytes;
    unsigned int i,j;

    // Calculate aggregated stats from writing cores
    for (i=0; i<data->nb_ports; i++) {
        total_packets = 0;
        total_bytes = 0;

        wprintw(window,"PORT %d:\n", data->port_list[i]);

        for (j=i*data->nb_queues_per_port; j<(i+1)*data->nb_queues_per_port; j++) {
            total_packets += data->write_core_stats[j].packets;
            total_bytes += data->write_core_stats[j].bytes;
        }

        wprintw(window,"  Total packets written: %s\n",
                            ul_format(total_packets));
        wprintw(window,"  Total bytes written: %s\n",
                            bytes_format(total_bytes));

        for (j=i*data->nb_queues_per_port; j<(i+1)*data->nb_queues_per_port; j++) {
            wprintw(window, "  - Queue %2d handled by core %2d:\n", j,
                    data->write_core_stats[j].core_id);

            wprintw(window, "      Buffers Pending: %s\n",
                    ul_format(rte_ring_count(data->write_core_stats[j].pbuf_full_ring)));

            wprintw(window, "      Packets: %s\n",
                    ul_format(data->write_core_stats[j].packets));
            wprintw(window, "      Pkts/s: %s\n",
                    ul_format((data->write_core_stats[j].packets-
                               last_per_wr_core_pkts[j])*1000/STATS_PERIOD_MS));

            wprintw(window, "      Bytes: %s\n",
                    bytes_format(data->write_core_stats[j].bytes));
            wprintw(window, "      Bytes/s: %s\n",
                    ul_format((data->write_core_stats[j].bytes-
                               last_per_wr_core_bytes[j])*1000/STATS_PERIOD_MS));

            wprintw(window, "      File: %s (%s)\n",
                    data->write_core_stats[j].output_file,
                    bytes_format(data->write_core_stats[j].current_file_bytes));

            last_per_wr_core_pkts[j] = data->write_core_stats[j].packets;
            last_per_wr_core_bytes[j] = data->write_core_stats[j].bytes;

            wprintw(window, "\n");
        }
    }
}

static WINDOW * border_write, * border_capture;
static WINDOW * window_write, * window_capture;

static void mv_windows(void) {
    wclear(border_write);
    wclear(border_capture);
    wclear(window_write);
    wclear(window_capture);

    wresize(border_write,   LINES-1, COLS/2);
    wresize(border_capture, LINES-1, COLS/2);
    wresize(window_write,   LINES-1-2, COLS/2-2);
    wresize(window_capture, LINES-1-2, COLS/2-2);

    mvderwin(border_write, 1, 0);
    mvderwin(border_capture, 1, COLS/2);
    mvderwin(window_write,  1, 1);
    mvderwin(window_capture, 1, 1);

}

static void init_windows(void) {
    border_write = subwin(stdscr,0,0,0,0);
    border_capture = subwin(stdscr,0,0,0,0);

    window_write = subwin(border_write,0,0,0,0);
    window_capture = subwin(border_capture,0,0,0,0);

    scrollok(window_capture,TRUE);
    scrollok(window_write,TRUE);

    mv_windows();
}

static int printscreen(
        __attribute__((unused))struct rte_timer * timer,
        __attribute__((unused))struct stats_data * data) {
    static int nb_updates = 0;

    nb_updates++;

    clear();
    /* Move the windows */
    mv_windows();

    /* Write into the buffers */
    mvprintw(0,0,"%c - Press q to quit",ROTATING_CHAR[nb_updates%4]);
    box(border_write,0,0);
    mvwprintw(border_write,0,2,"Write stats");
    box(border_capture,0,0);
    mvwprintw(border_capture,0,2,"Capture stats");

    wwrite_stats(window_write, data);
    wcapture_stats(window_capture, data);

    /* Print on screen */
    refresh();

    return 0;
}

static struct rte_timer stats_timer;

void start_stats_display(struct stats_data * data, bool volatile * stop_condition) {
    int ch;

    last_per_cap_core_pkts = calloc(data->nb_queues, sizeof(uint64_t));
    last_per_wr_core_pkts = calloc(data->nb_queues, sizeof(uint64_t));
    last_per_wr_core_bytes = calloc(data->nb_queues, sizeof(uint64_t));

    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);

    //Init windows
    init_windows();

    //Non blocking inputs
    timeout(0);

    //Initialize timers
    rte_timer_subsystem_init();
    rte_timer_init (&(stats_timer));

    //Timer launch
    rte_timer_reset(&(stats_timer), rte_get_timer_hz() * STATS_PERIOD_MS / 1000,
            PERIODICAL, rte_lcore_id(), (void*) printscreen, data);

    //Wait for ctrl+c
    while(likely(!(*stop_condition))) {
        ch = getch();
        switch(ch) {
            case KEY_DOWN:
                break;
            case KEY_UP:
                break;
            case 'q':
                *stop_condition = true;
                break;
        }

        rte_timer_manage();
    }
    rte_timer_stop(&(stats_timer));

    endwin();

    free(last_per_cap_core_pkts);
    free(last_per_wr_core_pkts);
    free(last_per_wr_core_bytes);
}
