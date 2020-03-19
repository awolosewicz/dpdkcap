#ifndef DPDKCAP_PCAP_H
#define DPDKCAP_PCAP_H

#include "utils.h"

struct pcap_file_header {
    uint32_t magic_number;  /* magic number */
    uint16_t version_major; /* major version number */
    uint16_t version_minor; /* minor version number */
    int32_t  thiszone;      /* GMT to local correction */
    uint32_t sigfigs;       /* accuracy of timestamps */
    uint32_t snaplen;       /* max length of captured packets, in octets */
    uint32_t network;       /* data link type */
} __rte_packed;

struct pcap_packet_header {
    uint32_t seconds;
    uint32_t microseconds;
    uint32_t packet_length;
    uint32_t packet_length_wire;
} __rte_packed;

struct pcap_buffer {
    uint32_t offset;
    uint32_t packets;
    unsigned char * buffer;
} __rte_cache_aligned;

void add_pad_packet(struct pcap_packet_header * pkthdr, int pad_len);

void pcap_header_init(unsigned char * file_header, unsigned int snaplen,
                      unsigned int mw_timestamp, unsigned int disk_blk_size);

#endif
