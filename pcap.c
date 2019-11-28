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

#define __need_IOV_MAX

#include "kafkacat.h"
#include "pcap.h"

#include <assert.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/uio.h>


void fmt_init_pcap (FILE *fp) {
    // FIXME: is there a better place for these sanity checks? Configure/compile time?
    assert(sizeof(pcap_file_header_t) == 24);
    assert(sizeof(pcap_packet_header_t) == 16);

    pcap_file_header_t header = {
        .maj_ver = 2,
        .min_ver = 4,
        .tz = 0,
        .accuracy = 0,               // "in practice, all tools set it to 0"
        .snaplen = 65535,
        .dlt = 1,               // LINKTYPE_ETHERNET
    };

    if (conf.pcap_flags & PCAP_FLAG_MICROSEC)
        header.magic = 0xa1b2c3d4; // microsecond magic
    else
        header.magic = 0xa1b23c4d; // nanosecond magic

    int wrote = fwrite(&header, sizeof(header), 1, fp);
    if (wrote != 1)
        KC_FATAL("Output initial write error: %s", strerror(errno));

    fflush(fp);

    if (!(conf.pcap_flags & PCAP_FLAG_PACKET_BUFFERED))
        setbuf(conf.output, NULL);
}

void fmt_term_pcap (FILE *fp) {
    /* NOP */
}

static void get_timestamp(const rd_kafka_message_t *rkmessage, pcap_packet_header_t *hdr) {
#if RD_KAFKA_VERSION >= 0x000902ff
    rd_kafka_timestamp_type_t tstype;
    int64_t ts_millisecond = rd_kafka_message_timestamp(rkmessage, &tstype);
    if (tstype != RD_KAFKA_TIMESTAMP_NOT_AVAILABLE) {
        hdr->sec = (ts_millisecond / 1000);
        hdr->usec = (ts_millisecond % 1000) * 1000000; // convert milli -> nano
    } else
#else
#warning Fallthrough to local timestamping
#endif
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        hdr->sec = tv.tv_sec,
        hdr->usec = tv.tv_usec * 1000;
    }
}

static void extract_vlan_info(packet_t *pkt) {
    uint16_t ethertype;
    int shift = 0;
    pkt->vlan1 = 0xF000;
    pkt->vlan2 = 0xF000;

    ethertype = ntohs(*(uint16_t*)(pkt->payload+12));
    if (ethertype == 0x88a8 || ethertype == 0x9100) {
        pkt->vlan2 = ntohs((*(uint16_t*)(pkt->payload+14))) & 0x0FFF;
        ethertype = ntohs(*(uint16_t*)(pkt->payload+16));
        shift = 4;
    }

    if (ethertype == 0x8100)
        pkt->vlan1 = ntohs((*(uint16_t*)(pkt->payload+14+shift))) & 0x0FFF;
}

static int filter_vlans(packet_t *pkt) {
    extract_vlan_info(pkt);
    int i, valid;

    if (conf.pcap_flags & PCAP_FLAG_FILTER_VLAN1) {
        valid = 0;
        for (i=0; i<conf.num_vlan1; i++)
            if (pkt->vlan1 == conf.vlan1[i]) {
                valid = 1;
                break;
            }
        if (!valid)
            return 1;
    }

    if (conf.pcap_flags & PCAP_FLAG_FILTER_VLAN2) {
        valid = 0;
        for (i=0; i<conf.num_vlan2; i++)
            if (pkt->vlan2 == conf.vlan2[i]) {
                valid = 1;
                break;
            }
        if (!valid)
            return 1;
    }

    return 0;
}


static void extract_trailer_info(packet_t *pkt) {
    pkt->trailer.base = pkt->payload + pkt->header->caplen - 12;
    pkt->trailer.sec = ntohl(*(uint32_t*)pkt->trailer.base);
    pkt->trailer.nsec = ntohl(*(uint32_t*)(pkt->trailer.base+4));
    pkt->header->sec = pkt->trailer.sec;
    pkt->header->usec = pkt->trailer.nsec;
    pkt->trailer.port_id = *(uint8_t*)(pkt->trailer.base+11);
    pkt->trailer.device_id = ntohs(*(uint16_t*)(pkt->trailer.base+9));
}

static int process_metamako_trailer(packet_t *pkt) {
    extract_trailer_info(pkt);
    int i, valid;

    if (conf.pcap_flags & PCAP_FLAG_FILTER_PORT_ID) {
        valid = 0;
        for (i=0; i<conf.num_port_ids; i++)
            if (pkt->trailer.port_id == conf.port_ids[i]) {
                valid = 1;
                break;
            }
        if (!valid)
            return 1;
    }

    if (conf.pcap_flags & PCAP_FLAG_FILTER_DEVICE_ID) {
        valid = 0;
        for (i=0; i<conf.num_device_ids; i++)
            if (pkt->trailer.device_id == conf.device_ids[i]) {
                valid = 1;
                break;
            }
        if (!valid)
            return 1;
        }

    return 0;
}


static void process_packet_buffered(FILE *fp, const rd_kafka_message_t *rkmessage) {
    packet_t pkt;
    int wrote;

    if (conf.pcap_flags & PCAP_FLAG_ADD_PACKET_HEADERS) {
        pcap_packet_header_t header = {
            .caplen = rkmessage->len,
            .wirelen = rkmessage->len,
        };
        get_timestamp(rkmessage, &header);
        pkt.header = &header;
        pkt.payload = rkmessage->payload;
    }
    else {
        pkt.header = (pcap_packet_header_t*)rkmessage->payload;
        pkt.payload = (unsigned char*)rkmessage->payload + sizeof(pcap_packet_header_t);
    }

    if (conf.pcap_flags & PCAP_FLAG_FILTER_VLAN1 ||
                        conf.pcap_flags & PCAP_FLAG_FILTER_VLAN2)
        if (filter_vlans(&pkt))
            return;

    if (conf.pcap_flags & PCAP_FLAG_METAMAKO_TRAILER)
        if(process_metamako_trailer(&pkt))
            return;

    if (conf.pcap_flags & PCAP_FLAG_MICROSEC)
        pkt.header->usec /= 1000;

    wrote = fwrite(pkt.header, sizeof(pcap_packet_header_t), 1, fp);
    wrote &= fwrite(pkt.payload, pkt.header->caplen, 1, fp);
    if (unlikely(wrote != 1))
        KC_FATAL("Output write error: %s", strerror(errno));

    stats.rx_pkts++;
}


static void process(FILE *fp, const rd_kafka_message_t *rkmessage) {
    unsigned int i = 0, exclude = 0,  len = 0, iovcnt = 0;
    struct iovec iov[IOV_MAX];
    packet_t pkt;

    iov[iovcnt].iov_base = rkmessage->payload;

    for ( i=0; i<rkmessage->len; ) {
        exclude = 0;
        pkt.header = (pcap_packet_header_t*)((uintptr_t)rkmessage->payload + i);
        i += sizeof(pcap_packet_header_t);
        pkt.payload = (unsigned char*)rkmessage->payload + i;
        i += pkt.header->caplen;

        if (conf.pcap_flags & PCAP_FLAG_FILTER_VLAN1 ||
                            conf.pcap_flags & PCAP_FLAG_FILTER_VLAN2)
            if (filter_vlans(&pkt)) {
                exclude = 1;
                goto exclude;
            }

        if (conf.pcap_flags & PCAP_FLAG_METAMAKO_TRAILER)
            if(process_metamako_trailer(&pkt)) {
                exclude = 1;
                goto exclude;
            }

        len += (sizeof(pcap_packet_header_t) + pkt.header->caplen);

        stats.rx_pkts++;

exclude:
        if (exclude) {
            if (len) {
                iov[iovcnt++].iov_len = len;
                len = 0;
                if (iovcnt == IOV_MAX) {
                    if (unlikely(writev(fileno(fp), iov, iovcnt) < 0))
                        KC_FATAL("Output write error: %s", strerror(errno));
                    iovcnt = 0;
                }
            }
            iov[iovcnt].iov_base = (void *)((uintptr_t)rkmessage->payload + i);
        }
    }

    if (len)
        iov[iovcnt++].iov_len = len;

    if (iovcnt)
        if (unlikely(writev(fileno(fp), iov, iovcnt) < 0))
            KC_FATAL("Output write error: %s", strerror(errno));
}


void fmt_msg_output_pcap (FILE *fp, const rd_kafka_message_t *rkmessage) {
    if (conf.pcap_flags & PCAP_FLAG_PACKET_BUFFERED)
        process_packet_buffered(fp, rkmessage);
    else
        process(fp, rkmessage);

    if (conf.pkt_cnt && (stats.rx_pkts >= (uint64_t)conf.pkt_cnt))
        conf.run = 0;
}

void parse_pcap_args(char *arglist) {
    conf.flags |= CONF_F_FMT_PCAP;
    conf.pcap_flags = 0;

    char *state;
    char *t = strtok_r(arglist, ",", &state);
    while (t != NULL)
    {
        if (strcmp(t, "microsecond") == 0)
            conf.pcap_flags |= PCAP_FLAG_MICROSEC;
        else if (strcmp(t, "pbuffered") == 0)
            conf.pcap_flags |= PCAP_FLAG_PACKET_BUFFERED;
        else if (strcmp(t, "add_packet_headers") == 0)
            conf.pcap_flags |= PCAP_FLAG_ADD_PACKET_HEADERS;
        else if (strcmp(t, "metamako") == 0)
            conf.pcap_flags |= PCAP_FLAG_METAMAKO_TRAILER;
        else
            KC_FATAL("Unknown pcap flag: '%s'", t);
        t = strtok_r(NULL, ",", &state);
    }
}

void parse_vlan1_args(char *arglist) {
    conf.pcap_flags |= PCAP_FLAG_FILTER_VLAN1;

    char *state;
    char *t = strtok_r(arglist, ",", &state);
    int i = 0;

    while (t != NULL)
    {
        if ( i >= 100)
            break;
        conf.vlan1[i] = (uint16_t)strtol(t, NULL, 10);
        i++;
        t = strtok_r(NULL, ",", &state);
    }
    conf.num_vlan1 = i;
}

void parse_vlan2_args(char *arglist) {
    conf.pcap_flags |= PCAP_FLAG_FILTER_VLAN2;

    char *state;
    char *t = strtok_r(arglist, ",", &state);
    int i = 0;

    while (t != NULL)
    {
        if ( i >= 100)
            break;
        conf.vlan2[i] = (uint16_t)strtol(t, NULL, 10);
        i++;
        t = strtok_r(NULL, ",", &state);
    }
    conf.num_vlan2 = i;
}

void parse_port_id_args(char *arglist) {
    conf.pcap_flags |= PCAP_FLAG_FILTER_PORT_ID;

    char *state;
    char *t = strtok_r(arglist, ",", &state);
    int i = 0;

    while (t != NULL)
    {
        if ( i >= 100)
            break;
        conf.port_ids[i] = (uint8_t)strtol(t, NULL, 10);
        i++;
        t = strtok_r(NULL, ",", &state);
    }
    conf.num_port_ids = i;
}

void parse_device_id_args(char *arglist) {
    conf.pcap_flags |= PCAP_FLAG_FILTER_DEVICE_ID;

    char *state;
    char *t = strtok_r(arglist, ",", &state);
    int i = 0;

    while (t != NULL)
    {
        if ( i >= 100)
            break;
        conf.device_ids[i] = (uint16_t)strtol(t, NULL, 10);
        i++;
        t = strtok_r(NULL, ",", &state);
    }
    conf.num_device_ids = i;
}
