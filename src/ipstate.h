/*
 * ipstate.h
 * Purpose: manage windowed quantized-flow accounting
 *
 * Copyright (c) 2009 - 2012, TortoiseLabs LLC.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "protocols.h"
#include "packet.h"

#ifndef __IPSTATE_H__
#define __IPSTATE_H__

typedef struct iprecord_ iprecord_t;
typedef struct flowdata_ flowdata_t;

struct flowdata_ {
        time_t last;
        time_t current;
        unsigned long bytes;
        unsigned long bytes_pending;
        unsigned long flow;
        unsigned long packets;
        unsigned long packets_pending;
        unsigned long pps;
	unsigned int count;
};

struct iprecord_ {
	time_t last;
        uint32_t addr;
	flowdata_t flows[IPPROTO_MAX + 1];
};

void ipstate_clear(void);
void ipstate_update(packet_info_t *packet);
void ipstate_setup(mowgli_eventloop_t *eventloop);
void ipstate_reset_flowcount(struct in_addr *ip);

#endif
