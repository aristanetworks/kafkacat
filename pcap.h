
/*
 * kafkacat - Apache Kafka consumer and producer
 *
 * Copyright (c) 2015, Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "kafkacat.h"

typedef struct pcap_hdr_s {
        uint32_t magic;
        uint16_t maj_ver;
        uint16_t min_ver;
        int32_t  tz;
        uint32_t accuracy;
        uint32_t snaplen;
        uint32_t dlt;
} pcap_file_header_t;


typedef struct pcaprec_hdr_s {
        uint32_t sec;
        uint32_t nsec;
        uint32_t caplen;
        uint32_t wirelen;
} pcap_packet_header_t;


typedef struct mm_trailer_s {
        unsigned char *base;
        uint32_t sec;
        uint32_t nsec;
        uint8_t port_id;
        uint16_t device_id;
        uint32_t frac_nsec;
        uint32_t seq_num;
} metamako_trailer_t;


typedef struct pkt_s {
        pcap_packet_header_t *header;
        metamako_trailer_t trailer;
        uint16_t vlan1;
        uint16_t vlan2;
        unsigned char *payload;
} packet_t;
