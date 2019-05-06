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

void extcap_interfaces (void) {
    printf("extcap {version=1.0}{help=http://www.wireshark.org}{display=Kafka kapture (Kafkacat)}\n");
    printf("interface {value=kafka}{display=Kafkacat}\n");
}

void extcap_dlts (const char *iface) {
    printf("dlt {number=1}{name=DLT_EN10MB}{display=Raw Frames}\n");
}

void extcap_config (const char *iface) {
    printf("arg {number=0}{call=-b}{display=Broker Address}{tooltip=IP or hostname of Kafka broker}{placeholder=eg: mybroker:9092}{type=string}{required=true}\n");
    printf("arg {number=1}{call=-t}{display=Topic}{tooltip=Topic to subscribe to}{type=string}{required=true}\n");
    printf("arg {number=2}{call=-o}{display=Offset}{tooltip=Offset to start consuming from}{placeholder=beginning | end | stored | <absolute offset> |" \
                                                                "-<value> (relative from end)}{type=string}{required=true}\n");
    printf("arg {number=3}{call=--extcap-mmtrailer}{display=Extract Metamako Timestamps}{type=boolflag}\n");
    printf("arg {number=4}{call=--extcap-pbuffered}{display=Every kafka message contains only one packet}{type=boolflag}\n");
    printf("arg {number=5}{call=--extcap-add-headers}{display=Add packet headers (assumes packet buffered kafka messages)}{type=boolflag}\n");
}
