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

#pragma once

#define __need_IOV_MAX

#ifndef _MSC_VER
#include "config.h"
#include <arpa/inet.h>  /* for htonl() */
#include <getopt.h>
#include <syslog.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#else
#pragma comment(lib, "librdkafka.lib")
#pragma comment(lib, "ws2_32.lib")
#include "win32/win32_config.h"
#include "win32/wingetopt.h"
#include <io.h>
#endif

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include <librdkafka/rdkafka.h>

#include "rdport.h"

#ifdef RD_KAFKA_V_HEADER
#define HAVE_HEADERS 1
#else
#define HAVE_HEADERS 0
#endif

#if RD_KAFKA_VERSION >= 0x000b0500
#define HAVE_CONTROLLERID 1
#else
#define HAVE_CONTROLLERID 0
#endif

#ifndef IOV_MAX
#define IOV_MAX 1024
#endif

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

typedef enum {
        KC_FMT_STR,
        KC_FMT_OFFSET,
        KC_FMT_KEY,
        KC_FMT_KEY_LEN,
        KC_FMT_PAYLOAD,
        KC_FMT_PAYLOAD_LEN,
        KC_FMT_PAYLOAD_LEN_BINARY,
        KC_FMT_TOPIC,
        KC_FMT_PARTITION,
        KC_FMT_TIMESTAMP,
        KC_FMT_HEADERS
} fmt_type_t;

#define KC_FMT_MAX_SIZE  128

struct conf {
        int     run;
        int     verbosity;
        int     exitcode;
        int     exitonerror;
        char    mode;
        int     flags;
#define CONF_F_FMT_JSON   0x1 /* JSON formatting */
#define CONF_F_KEY_DELIM  0x2 /* Producer: use key delimiter */
#define CONF_F_OFFSET     0x4 /* Print offsets */
#define CONF_F_TEE        0x8 /* Tee output when producing */
#define CONF_F_NULL       0x10 /* Send empty messages as NULL */
#define CONF_F_LINE	  0x20 /* Read files in line mode when producing */
#define CONF_F_APIVERREQ  0x40 /* Enable api.version.request=true */
#define CONF_F_APIVERREQ_USER 0x80 /* User set api.version.request */
#define CONF_F_NO_CONF_SEARCH 0x100 /* Disable default config file search */
#define CONF_F_BROKERS_SEEN 0x200 /* Brokers have been configured */

#if ENABLE_PCAP
#define CONF_F_FMT_PCAP 0x400 /* PCAP formatted output */
        int pcap_flags;
#define PCAP_FLAG_UNUSED                0x1 /* Unused */
#define PCAP_FLAG_PACKET_BUFFERED       0x2 /* Flush output after each packet */
#define PCAP_FLAG_ADD_PACKET_HEADERS    0x4 /* Add packet headers per message (assumes one packet per kafka message) */
#define PCAP_FLAG_METAMAKO_TRAILER      0x8 /* Assume metamako packet trailer, and extract timestamp */
#define PCAP_FLAG_FILTER_VLAN1          0x10 /* Filter received packets based on provided VLAN 1 tags */
#define PCAP_FLAG_FILTER_VLAN2          0x20 /* Filter received packets based on provided VLAN 2 tags */
#define PCAP_FLAG_FILTER_PORT_ID        0x40 /* Filter received packets based on provided source port ids */
#define PCAP_FLAG_FILTER_DEVICE_ID      0x80 /* Filter received packets based on provided source device ids */

        int64_t  pkt_cnt;

        int      num_vlan1;
        int      num_vlan2;
        int      num_port_ids;
        int      num_device_ids;

        uint16_t vlan1[100];
        uint16_t vlan2[100];
        uint8_t  port_ids[100];
        uint16_t device_ids[100];
#endif
        int     delim;
        int     key_delim;

        struct {
                fmt_type_t type;
                const char *str;
                int         str_len;
        } fmt[KC_FMT_MAX_SIZE];
        int     fmt_cnt;
        int     msg_size;
        char   *brokers;
        char   *topic;
        int32_t partition;
        rd_kafka_headers_t *headers;
        char   *group;
        char   *fixed_key;
        int32_t fixed_key_len;
        int64_t offset;
        int     exit_eof;
        int64_t msg_cnt;
        char   *null_str;
        int     null_str_len;
        FILE   *output;

        rd_kafka_conf_t       *rk_conf;
        rd_kafka_topic_conf_t *rkt_conf;

        rd_kafka_t            *rk;
        rd_kafka_topic_t      *rkt;

        char   *debug;
};

extern struct conf conf;

struct stats {
        uint64_t tx;
        uint64_t tx_err_q;
        uint64_t tx_err_dr;
        uint64_t tx_delivered;

        uint64_t rx;
#if ENABLE_PCAP
        uint64_t rx_pkts;
#endif
};

extern struct stats stats;

void RD_NORETURN fatal0 (const char *func, int line,
                                       const char *fmt, ...);

void error0 (int erroronexit, const char *func, int line,
                                       const char *fmt, ...);

#define KC_FATAL(.../*fmt*/)  fatal0(__FUNCTION__, __LINE__, __VA_ARGS__)

#define KC_ERROR(.../*fmt*/)  error0(conf.exitonerror, __FUNCTION__, __LINE__, __VA_ARGS__)

/* Info printout */
#define KC_INFO(VERBLVL,.../*fmt*/) do {                    \
                if (conf.verbosity >= (VERBLVL))     \
                        fprintf(stderr, "%% " __VA_ARGS__);  \
        } while (0)



/*
 * format.c
 */
void fmt_msg_output (FILE *fp, const rd_kafka_message_t *rkmessage);

void fmt_parse (const char *fmt);

void fmt_init (FILE *fp);
void fmt_term (FILE *fp);



#if ENABLE_JSON
/*
 * json.c
 */
void fmt_msg_output_json (FILE *fp, const rd_kafka_message_t *rkmessage);
void metadata_print_json (const struct rd_kafka_metadata *metadata,
                          int32_t controllerid);
void partition_list_print_json (const rd_kafka_topic_partition_list_t *parts,
                                void *json_gen);
void fmt_init_json (FILE *fp);
void fmt_term_json (FILE *fp);

#endif

#if ENABLE_PCAP
/*
 * pcap.c
 */

void fmt_init_pcap (FILE *fp);
void fmt_term_pcap (FILE *fp);
void fmt_msg_output_pcap (FILE *fp, const rd_kafka_message_t *rkmessage);
void parse_pcap_args(char *arglist);
void parse_vlan1_args(char *arglist);
void parse_vlan2_args(char *arglist);
void parse_port_id_args(char *arglist);
void parse_device_id_args(char *arglist);


#if ENABLE_WIRESHARK
/*
 * wireshark.c
 */

void extcap_interfaces (void);
void extcap_dlts (const char *iface);
void extcap_config (const char *iface);

#endif

#endif


/*
 * tools.c
 */
int query_offsets_by_time (rd_kafka_topic_partition_list_t *offsets);
