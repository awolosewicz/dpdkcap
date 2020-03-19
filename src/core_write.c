#include "core_write.h"

/*
 * Change file name from template
 */
static void format_from_template(char * filename,
        const char * template, const int core_id,
        const int file_count, const struct timeval * file_start) {

    char str_buf[OUTPUT_FILENAME_LENGTH];

    //Change file name
    strncpy(filename, template,
            OUTPUT_FILENAME_LENGTH);
    snprintf(str_buf, 50, "%02d", core_id);
    while(str_replace(filename,"\%COREID",str_buf));
    snprintf(str_buf, 50, "%03d", file_count);
    while(str_replace(filename,"\%FCOUNT",str_buf));
    strncpy(str_buf, filename, OUTPUT_FILENAME_LENGTH);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
    strftime(filename, OUTPUT_FILENAME_LENGTH, str_buf,
            localtime(&(file_start->tv_sec)));
#pragma GCC diagnostic pop
}

/*
 * Open pcap file for writing
 */
static inline int open_pcap(char * output_file,
                    unsigned char * file_header, uint16_t disk_blk_size) {

    int fd = open(output_file, O_CREAT | O_WRONLY | O_TRUNC | O_DIRECT | O_NOATIME, 0644);

    if (fd<0) {
        fd = open(output_file, O_CREAT | O_WRONLY | O_TRUNC | O_NOATIME, 0644);

        if (fd<0) {
            LOG_ERR("Core %d could not open %s in write mode: %d (%s)\n",
                    rte_lcore_id(), output_file, errno, strerror(errno));
            return 0;
        }

        LOG_WARN("Core %d could not open %s in direct write mode: %d (%s)\n",
                    rte_lcore_id(), output_file, errno, strerror(errno));
        LOG_INFO("Core %d using normal write mode\n", rte_lcore_id());
        disk_blk_size = sizeof(struct pcap_file_header);
    }

    int written = write(fd, file_header, disk_blk_size);
    if(written < 0) {
        LOG_ERR("Core %d unable to write pcap file header: %d (%s)\n",
                rte_lcore_id(), errno, strerror(errno));
        return 0;
    }

    return fd;
}

/*
 * Close and free a pcap file
 */
static inline int close_pcap(int fd) {
    int retval = close(fd);
    if (retval)
        LOG_ERR("Could not close file: %d (%s)\n", errno, strerror(errno));
    return retval;
}

/*
 * Write the packets from the pcap buffer into a file
 */
int write_core(const struct write_core_config * config) {
    const unsigned socket_id = rte_socket_id();
    unsigned dev_socket_id;

    volatile bool * stop_condition = config->stop_condition;

    const uint16_t port = config->port;

    struct rte_ring * pbuf_free_ring = config->pbuf_free_ring;
    struct rte_ring * pbuf_full_ring = config->pbuf_full_ring;
    int pcap_file;

    struct timeval tv, file_start;
    uint16_t disk_blk_size = config->disk_blk_size;
    unsigned char * file_header = rte_zmalloc(NULL, disk_blk_size, disk_blk_size);
    uint16_t i, nb_bufs;
    int written, retval = 0;
    uint16_t burst_size = config->burst_size;
    struct pcap_buffer * buffers[burst_size];
    struct iovec iov[burst_size];

    char file_name[OUTPUT_FILENAME_LENGTH];
    unsigned int file_count = 0, stop = 0;
    uint64_t file_size = 0;
    bool file_changed = 0;

    gettimeofday(&file_start, NULL);

    LOG_INFO("Core %d is writing using file template: %s.\n",
            rte_lcore_id(), config->output_file_template);

    //Update filename
    format_from_template(file_name, config->output_file_template,
            rte_lcore_id(), file_count, &file_start);

    //Init stats
    config->stats->core_id = rte_lcore_id();
    config->stats->pbuf_full_ring = config->pbuf_full_ring;

    rte_memcpy(config->stats->output_file, file_name, OUTPUT_FILENAME_LENGTH);

    dev_socket_id = rte_eth_dev_socket_id(port);
    if (dev_socket_id != socket_id)
        LOG_WARN("Port %u on different socket from worker; performance will suffer\n", port);

    //Init the common pcap header
    pcap_header_init(file_header, config->snaplen, config->mw_timestamp, disk_blk_size);

    //Open new file
    pcap_file = open_pcap(file_name, file_header, disk_blk_size);
    if(!pcap_file) {
        retval = -1;
        goto cleanup;
    }

    while(1) {
        /* Stop condition */
        if (unlikely(stop > 9999999))
            break;

        if (unlikely(*stop_condition))
            stop++;

        nb_bufs = rte_ring_sc_dequeue_burst(pbuf_full_ring, (void **)buffers, burst_size, NULL);

        if (unlikely(nb_bufs<1))
            continue;

        for(i=0; i<nb_bufs; i++) {
            iov[i].iov_base = buffers[i]->buffer;
            iov[i].iov_len = buffers[i]->offset;
            config->stats->packets += buffers[i]->packets;
            buffers[i]->offset = 0;
        }
        written = writev(pcap_file, iov, nb_bufs);

        while(!(rte_ring_sp_enqueue_bulk(pbuf_free_ring, (void **)buffers, nb_bufs, NULL) || unlikely(*stop_condition)));

        if(unlikely(written<0))
            LOG_ERR("Could not write into file: %d (%s)\n",
                errno, strerror(errno));

        file_size += written;
        config->stats->current_file_bytes = file_size;
        config->stats->bytes += written;

        //Create a new file according to limits
        if(unlikely(config->rotate_seconds)) {
            gettimeofday(&tv, NULL);
            if((uint32_t)(tv.tv_sec-file_start.tv_sec) >= config->rotate_seconds) {
                gettimeofday(&file_start, NULL);
                file_count++;
                file_changed=1;
            }
        }

        if(unlikely(config->file_size_limit)) {
            if(file_size >= config->file_size_limit) {
                file_count++;
                file_changed=1;
            }
        }

        //Open new file
        if(unlikely(file_changed)) {
            //Change file name
            format_from_template(file_name, config->output_file_template,
                    rte_lcore_id(), file_count, &file_start);

            //Update stats
            config->stats->current_file_bytes = 0;
            rte_memcpy(config->stats->output_file, file_name,
                    OUTPUT_FILENAME_LENGTH);

            //Close pcap file and open new one
            if(close_pcap(pcap_file)) {
                retval = -1;
                goto cleanup;
            }

            //Reopen a file
            pcap_file = open_pcap(file_name, file_header, disk_blk_size);
            if(!pcap_file) {
                retval = -1;
                goto cleanup;
            }

            //Reset file size
            file_changed = 0;
            file_size = 0;
        }
    }

cleanup:
    //Close pcap file
    close_pcap(pcap_file);
    rte_free(file_header);

    LOG_INFO("Closed writing core %d\n", rte_lcore_id());

    return retval;
}
