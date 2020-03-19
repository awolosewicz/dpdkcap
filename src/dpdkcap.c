#include <signal.h>
#include <argp.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>

#include "core_write.h"
#include "core_capture.h"
#include "nic.h"
#include "pcap.h"
#include "stats.h"
#include "utils.h"

#define RX_DESC_DEFAULT 1024
#define MBUF_CACHE_SIZE 512

#define BURST_SIZE_DEFAULT 128
#define NUM_MBUFS_DEFAULT 65536

#define PAUSE_BURST_SIZE 128
#define PAUSE_MBUF_POOL_SIZE 8192

#define PCAP_SNAPLEN_DEFAULT 65535

#define PCAP_BUF_LEN_DEFAULT 1024 * 1024 * 128
#define NUM_PBUFS_DEFAULT 4

#define MAX_LCORES 1000

#define DISK_BLK_SIZE 4096

#define OUTPUT_TEMPLATE_TOKEN_FILECOUNT "\%FCOUNT"
#define OUTPUT_TEMPLATE_TOKEN_CORE_ID   "\%COREID"
#define OUTPUT_TEMPLATE_DEFAULT "output_" \
    OUTPUT_TEMPLATE_TOKEN_CORE_ID

#define OUTPUT_TEMPLATE_LENGTH 2 * OUTPUT_FILENAME_LENGTH

/* ARGP */
const char *argp_program_version = "dpdkcap 1.1";
static char doc[] = "A DPDK-based packet capture tool";
static char args_doc[] = "";

static struct argp_option options[] = {
    { "output", 'w', "FILE", 0, "Output FILE template (don't add the "\
        "extension). Use \""OUTPUT_TEMPLATE_TOKEN_CORE_ID"\" for "\
            "inserting the lcore id into the file name (automatically added if not "\
            "used). (default: "OUTPUT_TEMPLATE_DEFAULT")", 0 },
    { "stats", 'S', 0, 0, "Print stats every few seconds.", 0 },
    { "nb-mbuf", 'm', "NB_MBUF", 0, "Number of memory buffers per core per port "\
        "used to store the DMA'd packets by the nic driver. Optimal values, "\
            "are powers of 2 (2^q) (default: "STR(NUM_MBUFS_DEFAULT)")", 0 },
    { "mbuf_len", 'i', "MBUF_LEN", 0, "Size (in bytes) of each MBUF (packet buffer). "\
        "Recommened value is 2KB + RTE_PKTMBUF_HEADROOM (default: "STR(RTE_MBUF_DEFAULT_BUF_SIZE)")", 0 },
    { "nb_pbuf", 'n', "NB_PBUF", 0, "Number of memory buffers per core per port "\
        "used to store received packets before being flushed to disk. Optimal values, "\
            "are powers of 2 (2^q) (default: "STR(NUM_PBUFS_DEFAULT)")", 0 },
    { "pbuf_len", 'j', "PBUF_LEN", 0, "Size (in bytes) of each PBUF (pcap buffer). "\
        "Optimal values, are powers of 2 (2^q) (default: "STR(PCAP_BUF_LEN_DEFAULT)")", 0 },
    { "nb_queues_per_port", 'q', "QUEUES_PER_PORT", 0, "Number of queues per port (default: 1)", 0 },
    { "rx_desc", 'd', "DESC_MATRIX", 0, "This option can be used to "\
        "override the default number of RX descriptors configured for all queues "\
            "of each port ("STR(RX_DESC_DEFAULT)"). RX_DESC_MATRIX can have "\
            "multiple formats:\n"\
            "- A single positive value, which will simply replace the default "\
            " number of RX descriptors,\n"\
            "- A list of key-values, assigning a configured number of RX "\
            "descriptors to the given port(s). Format: \n"\
            "  <matrix>   := <key>.<nb_rx_desc> { \",\" <key>.<nb_rx_desc> \",\" "\
            "...\n"\
            "  <key>      := { <interval> | <port> }\n"\
            "  <interval> := <lower_port> \"-\" <upper_port>\n"\
            "  Examples: \n"\
            "  512               - all ports have 512 RX desc per queue\n"\
            "  0.256, 1.512      - port 0 has 256 RX desc per queue,\n"\
            "                      port 1 has 512 RX desc per queue\n"\
            "  0-2.256, 3.1024   - ports 0, 1 and 2 have 256 RX desc per "\
            " queue,\n"\
            "                      port 3 has 1024 RX desc per queue."
            , 0 },
    { "burst_size", 'b', "NUM", 0, "Size of receive burst (default: "STR(BURST_SIZE_DEFAULT)")", 0 },
    { "rotate_seconds", 'r', "SECS", 0, "Create a new set of files every T "\
        "seconds. Use strftime formats within the output file template to rename "\
            "each file accordingly.", 0},
    { "file_size_limit", 'f', "SIZE", 0, "Before writing a packet, check "\
        "whether the target file excess SIZE bytes. If so, creates a new file. " \
            "Use \""OUTPUT_TEMPLATE_TOKEN_FILECOUNT"\" within the output "\
            "file template to index each new file.", 0},
    { "portmask", 'p', "PORTMASK", 0, "Ethernet ports mask (default: 0x1).", 0 },
    { "flow-control", 'z', 0, 0, "Enable flow control.", 0 },
    { "logs", 700, "FILE", 0, "Writes the logs into FILE instead of "\
        "stderr.", 0 },
    { 0 } };

struct arguments {
    int stats;
    uint16_t * port_list;
    uint16_t burst_size;
    uint16_t pause_burst_size;
    uint16_t disk_blk_size;
    uint16_t nb_queues_per_port;
    uint16_t flow_control;
    uint16_t snaplen;
    uint32_t nb_mbufs;
    uint32_t mbuf_len;
    uint32_t nb_pbufs;
    uint32_t pbuf_len;
    uint64_t portmask;
    uint64_t rotate_seconds;
    uint64_t file_size_limit;
    char * output_file_template;
    char * log_file;
    char * num_rx_desc_str_matrix;
} __rte_cache_aligned;

static int parse_matrix_opt(char * arg, unsigned long * matrix,
        unsigned long max_len) {
    char * comma_tokens [100];
    int nb_comma_tokens;
    char * dot_tokens [3];
    int nb_dot_tokens;
    char * dash_tokens [3];
    int nb_dash_tokens;

    char * end;

    unsigned long left_key;
    unsigned long right_key;
    unsigned long  value;

    nb_comma_tokens = rte_strsplit(arg, strlen(arg), comma_tokens, 100, ',');
    // Case with a single value
    if(nb_comma_tokens == 1 && strchr(arg, '.') == NULL) {
        errno = 0;
        value = strtoul(arg, &end, 10);
        if(errno||*end!='\0') return -EINVAL;
        for(unsigned long key=0; key<max_len; key++) {
            matrix[key] = value;
        }
        return 0;
    }

    // Key-value matrix
    if (nb_comma_tokens > 0) {
        for(int comma=0; comma < nb_comma_tokens; comma++) {
            // Split between left and right side of the dot
            nb_dot_tokens = rte_strsplit(comma_tokens[comma],
                    strlen(comma_tokens[comma]), dot_tokens, 3, '.');
            if(nb_dot_tokens != 2)
                return -EINVAL;

            // Handle value
            errno = 0;
            value = strtoul(dot_tokens[1], &end, 10);
            if(errno||*end!='\0') return -EINVAL;

            // Handle key
            nb_dash_tokens = rte_strsplit(dot_tokens[0],
                    strlen(dot_tokens[0]), dash_tokens, 3, '-');
            if(nb_dash_tokens == 1) {
                // Single value
                left_key = strtoul(dash_tokens[0], &end, 10);
                if(errno||*end!='\0') return -EINVAL;
                right_key = left_key;
            } else if (nb_dash_tokens == 2) {
                // Interval value
                left_key =  strtoul(dash_tokens[0], &end, 10);
                if(errno||*end!='\0') return -EINVAL;
                right_key = strtoul(dash_tokens[1], &end, 10);
                if(errno||*end!='\0') return -EINVAL;
            } else {
                return -EINVAL;
            }

            // Fill-in the matrix
            if (right_key < max_len && right_key >= left_key) {
                for (unsigned long key = left_key; key <= right_key; key ++) {
                    matrix[key] = value;
                }
            } else {
                return -EINVAL;
            }
        }
    } else {
        return -EINVAL;
    }
    return 0;
}

static error_t parse_opt(int key, char* arg, struct argp_state *state) {
    struct arguments* args = state->input;
    char *end;

    errno = 0;
    end = NULL;
    switch (key) {
        case 'p':
            /* parse hexadecimal string */
            args->portmask = strtoul(arg, &end, 16);
            if (args->portmask == 0) {
                LOG_ERR("Invalid portmask '%s', no port used\n", arg);
                return -EINVAL;
            }
            break;
        case 'w':
            strncpy(args->output_file_template, arg, OUTPUT_FILENAME_LENGTH);
            break;
        case 'S':
            args->stats = 1;
            break;
        case 'm':
            args->nb_mbufs = strtoul(arg, &end, 10);
            break;
        case 'i':
            args->mbuf_len = strtoul(arg, &end, 10);
            break;
        case 'n':
            args->nb_pbufs = strtoul(arg, &end, 10);
            break;
        case 'j':
            args->pbuf_len = strtoul(arg, &end, 10);
            break;
        case 'b':
            args->burst_size = strtoul(arg, &end, 10);
            break;
        case 'd':
            args->num_rx_desc_str_matrix = arg;
            break;
        case 'q':
            args->nb_queues_per_port = strtoul(arg, &end, 10);
            break;
        case 'r':
            args->rotate_seconds = strtoul(arg, &end, 10);
            break;
        case 'f':
            args->file_size_limit = strtoll(arg, &end, 10);
            break;
        case 'z':
            args->flow_control = 1;
            break;
        case 700:
            args->log_file = arg;
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    if(errno||(end != NULL && *end != '\0')) {
        LOG_ERR("Invalid value '%s'\n", arg);
        return -EINVAL;
    }
    return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };
/* END OF ARGP */

/*
 * Handles signals
 */
static volatile bool stop_condition = false;
static void signal_handler(int sig) {
    LOG_INFO("Caught signal %s on core %u%s\n",
            strsignal(sig), rte_lcore_id(),
            rte_get_master_lcore()==rte_lcore_id()?" (MASTER CORE)":"");
    stop_condition = true;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[]) {

    struct arguments args;
    struct capture_core_config * capture_core_configs;
    struct write_core_config   * write_core_configs;
    struct write_core_stats * write_core_stats;
    struct capture_core_stats * capture_core_stats;
    struct rte_ring ** pbuf_full_rings;
    struct rte_ring ** pbuf_free_rings;
    struct pcap_buffer ** buffers;
    struct rte_mempool ** rx_pools;
    struct rte_mempool ** tx_pools;

    uint16_t port;
    unsigned int lcoreid_list[MAX_LCORES];
    unsigned int nb_lcores;
    unsigned int i,j,k,l,m;
    unsigned int required_cores;
    unsigned int lcore_id;
    int result;

    FILE * log_file;

    /* Setup the signal handler */
    signal(SIGINT, signal_handler);

    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    args = (struct arguments) {
        .stats = 0,
        .port_list = NULL,
        .burst_size = BURST_SIZE_DEFAULT,
        .pause_burst_size = PAUSE_BURST_SIZE,
        .disk_blk_size = DISK_BLK_SIZE,
        .nb_queues_per_port = 1,
        .flow_control = 0,
        .snaplen = PCAP_SNAPLEN_DEFAULT,
        .nb_mbufs = NUM_MBUFS_DEFAULT,
        .mbuf_len = RTE_MBUF_DEFAULT_BUF_SIZE,
        .pbuf_len = PCAP_BUF_LEN_DEFAULT,
        .nb_pbufs = NUM_PBUFS_DEFAULT,
        .portmask = 0x1,
        .rotate_seconds = 0,
        .file_size_limit = 0,
        .output_file_template = NULL,
        .log_file = NULL,
        .num_rx_desc_str_matrix = NULL,
    };

    args.output_file_template = calloc(OUTPUT_FILENAME_LENGTH, 1);
    strncpy(args.output_file_template, OUTPUT_TEMPLATE_DEFAULT,
                        OUTPUT_FILENAME_LENGTH);

    /* Parse arguments */
    argp_parse(&argp, argc, argv, 0, 0, &args);

    /* Change log stream if needed */
    if (args.log_file) {
        log_file = fopen(args.log_file, "w");
        if (!log_file)
            rte_exit(EXIT_FAILURE, "Error: Could not open log file: (%d) %s\n",
                        errno, strerror(errno));

        result = rte_openlog_stream(log_file);
        if (result)
            rte_exit(EXIT_FAILURE, "Error: Could not change log stream: (%d) %s\n",
                        rte_errno, rte_strerror(rte_errno));
    }

    char * tmp_path = strdup(args.output_file_template);
    strcat(tmp_path, "_tmp_file");
    unsigned int maj_dev = 0;

    int fd = open(tmp_path, O_CREAT | O_RDONLY, 0644);
    if (fd<0) {
        LOG_WARN("Warning: Could not open temporary file to read disk block size: %d (%s)\n",
                        errno, strerror(errno));
        goto next;
    }

    struct stat stat_buf;
    if (fstat(fd, &stat_buf) < 0)
        LOG_WARN("Warning: Could not stat temporary file to read disk block size: %d (%s)\n",
                        errno, strerror(errno));
    else
        maj_dev = major(stat_buf.st_dev);

    close(fd);
    remove(tmp_path);

    if (maj_dev != 0) {
        char sysfs_path[100];
        sprintf(sysfs_path, "/sys/dev/block/%u:0/queue/logical_block_size", maj_dev);
        fd = open(sysfs_path, O_RDONLY);

        if (fd<0) {
            LOG_WARN("Warning: Could not read disk block size: %d (%s)\n", errno, strerror(errno));
            goto next;
        }

        char tmp_buf[10];
        if (read(fd, tmp_buf, 9) < 1)
            LOG_WARN("Warning: Could not read disk block size: %d (%s)\n", errno, strerror(errno));
        else
            args.disk_blk_size = strtoul(tmp_buf, NULL, 10);

        close(fd);
    }

next:

    /* Add suffixes to output if needed */
    if (!strstr(args.output_file_template, OUTPUT_TEMPLATE_TOKEN_CORE_ID))
        strcat(args.output_file_template, "_"OUTPUT_TEMPLATE_TOKEN_CORE_ID);

    if (args.file_size_limit && !strstr(args.output_file_template, OUTPUT_TEMPLATE_TOKEN_FILECOUNT))
        strcat(args.output_file_template, "_"OUTPUT_TEMPLATE_TOKEN_FILECOUNT);

    strcat(args.output_file_template, ".pcap");

    /* Check if at least one port is available */
    uint16_t avail_ports = rte_eth_dev_count_avail();
    if (avail_ports == 0)
        rte_exit(EXIT_FAILURE, "Error: No port available.\n");

    /* Fills in the number of rx descriptors matrix */
    unsigned long * num_rx_desc_matrix = calloc(avail_ports, sizeof(unsigned long));
    if (args.num_rx_desc_str_matrix != NULL &&
            parse_matrix_opt(args.num_rx_desc_str_matrix, num_rx_desc_matrix, avail_ports) < 0) {
        rte_exit(EXIT_FAILURE, "Invalid RX descriptors matrix.\n");
    }

    /* Creates the port list */
    uint16_t nb_ports = 0;
    args.port_list = calloc(64, sizeof(uint16_t));
    for (port = 0; port < avail_ports; port++)
        if (args.portmask & (uint64_t)(1ULL << port))
            args.port_list[nb_ports++] = port;

    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "Error: Found no usable port. Check portmask option.\n");

    LOG_INFO("Using %u ports to listen on\n", nb_ports);

    uint16_t nb_queues_per_port = args.nb_queues_per_port;
    uint16_t nb_queues = nb_queues_per_port * nb_ports;
    uint16_t mbuf_len = args.mbuf_len;
    uint32_t nb_mbufs = rte_align32pow2(args.nb_mbufs);
    uint32_t nb_pbufs = rte_align32pow2(args.nb_pbufs);
    uint32_t pbuf_len = rte_align32pow2(args.pbuf_len);
    uint32_t rx_burst_len = mbuf_len * args.burst_size;
    uint32_t watermark = pbuf_len - rx_burst_len;

    LOG_INFO("Cores/Queues Per Port: %d Burst Size: %d\n",
                            nb_queues_per_port, args.burst_size);
    LOG_INFO("MBufs: Num: %d Len: %d B  PBufs: Num: %d Len: %d B\n",
                            nb_mbufs, mbuf_len, nb_pbufs, pbuf_len);
    LOG_INFO("RX Burst Len: %d Watermark: %d\n",
                            rx_burst_len, watermark);
    LOG_INFO("Flow control: %s Pause Burst Size: %d\n",
                            args.flow_control?"ON":"OFF", args.pause_burst_size);
    LOG_INFO("Disk (%d:0) block size = %d\n",
                            maj_dev, args.disk_blk_size);

    if (pbuf_len < 2 * rx_burst_len) {
        rte_exit(EXIT_FAILURE, "Packet buffer length should be atleast %d B.\n",
                2 * rx_burst_len);
    }

    /* Checks core number */
    required_cores = 2 * nb_queues + 1;
    if (rte_lcore_count() < required_cores)
        rte_exit(EXIT_FAILURE, "Assign at least %d cores to dpdkcap. %d found.\n",
                            required_cores, rte_lcore_count());

    LOG_INFO("Using %u cores out of %d allocated\n", required_cores, rte_lcore_count());

    /* Init config stats and buffer lists */
    capture_core_configs = calloc(nb_queues, sizeof(struct capture_core_config));
    write_core_configs = calloc(nb_queues, sizeof(struct write_core_config));

    capture_core_stats = calloc(nb_queues, sizeof(struct capture_core_stats));
    write_core_stats = calloc(nb_queues, sizeof(struct write_core_stats));

    rx_pools = calloc(nb_queues, sizeof(struct mempool *));
    tx_pools = calloc(nb_queues, sizeof(struct mempool *));

    pbuf_full_rings = calloc(nb_queues, sizeof(struct ring *));
    pbuf_free_rings = calloc(nb_queues, sizeof(struct ring *));

    buffers = calloc(nb_queues * nb_pbufs, sizeof(struct pcap_buffer *));

    lcore_id = rte_get_next_lcore(-1, 1, 0);
    nb_lcores = 0;

    /* For each port */
    for (i = 0; i < nb_ports; i++) {
        port = args.port_list[i];

        /* Allocate memory */
        for (j = 0; j < nb_queues_per_port; j++) {

            k = i * nb_queues_per_port + j;
            char name[32];

            sprintf(name, "RX_POOL_%d_%d", i, j);
            rx_pools[k] = rte_pktmbuf_pool_create(name, nb_mbufs,
                            MBUF_CACHE_SIZE, 0, mbuf_len, rte_socket_id());

            if (rx_pools[k] == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create mbuf pool: (%d) %s\n",
                            rte_errno, rte_strerror(rte_errno));

            sprintf(name, "TX_POOL_%d_%d", i, j);
            tx_pools[k] = rte_pktmbuf_pool_create(name, PAUSE_MBUF_POOL_SIZE,
                            MBUF_CACHE_SIZE, 0, mbuf_len, rte_socket_id());

            if (tx_pools[k] == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create pause frame mbuf pool: (%d) %s\n",
                            rte_errno, rte_strerror(rte_errno));

            sprintf(name, "PCE_RING_%d_%d", i, j);
            pbuf_free_rings[k] = rte_ring_create(name, nb_pbufs * 2,
                            rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);

            if (pbuf_free_rings[k] == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create pbuf free ring: (%d) %s\n",
                            rte_errno, rte_strerror(rte_errno));

            sprintf(name, "PCF_RING_%d_%d", i, j);
            pbuf_full_rings[k] = rte_ring_create(name, nb_pbufs * 2,
                            rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);

            if (pbuf_full_rings[k] == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create pbuf full ring: (%d) %s\n",
                            rte_errno, rte_strerror(rte_errno));

            for (l = 0; l < nb_pbufs; l++) {
                m = i * nb_queues_per_port * nb_pbufs + j * nb_pbufs + l;

                buffers[m] = calloc(1, sizeof(struct pcap_buffer));
                buffers[m]->offset = 0;
                buffers[m]->packets = 0;
                buffers[m]->buffer = rte_malloc(NULL, pbuf_len, args.disk_blk_size);

                if (buffers[m]->buffer == NULL)
                    rte_exit(EXIT_FAILURE, "Cannot create pbuf buffer: (%d) %s\n",
                            rte_errno, rte_strerror(rte_errno));
            }

            m = i * nb_queues_per_port * nb_pbufs + j * nb_pbufs;
            rte_ring_sp_enqueue_bulk(pbuf_free_rings[k], (void **)&buffers[m], nb_pbufs, NULL);
        }

        /* Initialise and start the port */
        result = port_init(
                port,
                nb_queues_per_port,
                (num_rx_desc_matrix[i] != 0)?num_rx_desc_matrix[i]:RX_DESC_DEFAULT,
                &rx_pools[i*nb_queues_per_port],
                args.flow_control);

        if (result) {
            rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n", port);
        }

        for (j = 0; j < nb_queues_per_port; j++) {

            k = i * nb_queues_per_port + j;

            //Configure capture core
            struct capture_core_config * config =
                                &(capture_core_configs[k]);
            config->port = port;
            config->queue = j;
            config->pbuf_free_ring = pbuf_free_rings[k];
            config->pbuf_full_ring = pbuf_full_rings[k];
            config->pause_mbuf_pool = tx_pools[k];
            config->stop_condition = &stop_condition;
            config->burst_size = args.burst_size;
            config->pause_burst_size = args.pause_burst_size;
            config->disk_blk_size = args.disk_blk_size;
            config->flow_control = args.flow_control;
            config->snaplen = args.snaplen;
            config->watermark = watermark;
            config->stats = &(capture_core_stats[k]);

            //Launch capture core
            LOG_INFO("Launching capture process: worker=%u, port=%u, core=%u, queue=%u\n", k, port, lcore_id, j);
            result = rte_eal_remote_launch((lcore_function_t *) capture_core, config, lcore_id);
            if (result)
                rte_exit(EXIT_FAILURE, "Error: Could not launch capture process on lcore %d: (%d) %s\n",
                        lcore_id, result, rte_strerror(-result));

            //Add the core to the list
            lcoreid_list[nb_lcores] = lcore_id;
            nb_lcores++;

            lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
        }

        /* Writing cores */
        for (j = 0; j < nb_queues_per_port; j++) {

            k = i * nb_queues_per_port + j;

            //Configure writing core
            struct write_core_config * config =
                                &(write_core_configs[k]);
            config->port = port;
            config->pbuf_free_ring = pbuf_free_rings[k];
            config->pbuf_full_ring = pbuf_full_rings[k];
            config->stop_condition = &stop_condition;
            config->burst_size = nb_pbufs;
            config->disk_blk_size = args.disk_blk_size;
            config->snaplen = args.snaplen;
            config->stats = &(write_core_stats[k]);
            config->output_file_template = args.output_file_template;
            config->rotate_seconds = args.rotate_seconds;
            config->file_size_limit = args.file_size_limit;

            //Launch writing core
            LOG_INFO("Launching write process: worker=%u, port=%u, core=%u, queue=%u\n", k, port, lcore_id, j);
            result = rte_eal_remote_launch((lcore_function_t *) write_core, config, lcore_id);
            if (result)
                rte_exit(EXIT_FAILURE, "Error: Could not launch write process on lcore %d: (%d) %s\n",
                        lcore_id, result, rte_strerror(-result));

            //Add the core to the list
            lcoreid_list[nb_lcores] = lcore_id;
            nb_lcores++;

            lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
        }

    }

    //Initialize stats timer
    struct stats_data sd = {
        .port_list = args.port_list,
        .capture_core_stats = capture_core_stats,
        .write_core_stats = write_core_stats,
        .nb_ports = nb_ports,
        .nb_queues = nb_queues,
        .nb_queues_per_port = nb_queues_per_port,
        .log_file = args.log_file,
    };

    if (args.stats)
        start_stats_display(&sd, &stop_condition);

    while(!stop_condition)
        sleep(5);

    //Wait for all the cores to complete and exit
    LOG_INFO("Waiting for all cores to exit\n");
    for(i = 0; i < nb_lcores; i++) {
        result = rte_eal_wait_lcore(lcoreid_list[i]);
        if (result) {
            LOG_ERR("Core %d did not stop correctly: (%d)\n", lcoreid_list[i], result);
        }
    }

    //Finalize
    free(write_core_stats);
    free(capture_core_stats);
    free(write_core_configs);
    free(capture_core_configs);
    free(rx_pools);
    free(tx_pools);
    free(pbuf_free_rings);
    free(pbuf_full_rings);
    free(num_rx_desc_matrix);
    free(args.output_file_template);
    free(args.port_list);

    return 0;
}
