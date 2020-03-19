#include <stdlib.h>
#include <rte_memcpy.h>

#include "pcap.h"

void add_pad_packet(struct pcap_packet_header * pkthdr, int pad_len) {
    pad_len -= sizeof(struct pcap_packet_header);

    pkthdr->packet_length = pad_len;
    pkthdr->packet_length_wire = pad_len;

    pad_len -= 14;

    if (pad_len > 0) {
        unsigned char * pad_addr = (unsigned char *)pkthdr +
                            sizeof(struct pcap_packet_header) + 14;

        const char pad_txt[] = "Padding packet, please ignore. ";
        int txt_len = strlen(pad_txt);

        for (int i=0; i<=pad_len-txt_len; i+=txt_len)
            rte_memcpy(pad_addr+i, pad_txt, txt_len);
    }
}

void pcap_header_init(unsigned char * file_header,
            unsigned int snaplen, unsigned int disk_blk_size) {

    struct pcap_file_header * pcap_hdr = (struct pcap_file_header *)file_header;
    pcap_hdr->magic_number = 0xa1b23c4d;
    pcap_hdr->version_major = 0x0002;
    pcap_hdr->version_minor = 0x0004;
    pcap_hdr->thiszone = 0;
    pcap_hdr->sigfigs = 0;
    pcap_hdr->snaplen = snaplen;
    pcap_hdr->network = 0x00000001;

    struct pcap_packet_header * pkthdr =
                (struct pcap_packet_header *) (file_header + sizeof(struct pcap_file_header));
    unsigned int pad_len = disk_blk_size - sizeof(struct pcap_file_header);
    add_pad_packet(pkthdr, pad_len);
}
