/*
 * flowcache.h
 * Purpose: cache for flow entries                   
 *
 * Copyright (c) 2012, TortoiseLabs LLC.
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

#ifndef __FLOWCACHE_H
#define __FLOWCACHE_H

#include "patricia.h"

#define FLOW_HASH_SIZE		65536 >> 12
#define FLOW_HASH(src_port)	(src_port % FLOW_HASH_SIZE)

typedef struct _flowrecord {
	struct _flowrecord *prev, *next;

	time_t first_seen;
	bool injected;

	uint16_t src_port;
	uint16_t dst_port;

	uint32_t bytes;
	uint32_t packets;
} flowcache_record_t;

typedef struct {
	patricia_tree_t *src_host_tree;
} flowcache_dst_host_t;

typedef struct {
	flowcache_record_t *flows[FLOW_HASH_SIZE];
} flowcache_src_host_t;

flowcache_record_t *flowcache_record_insert(flowcache_record_t *parent, uint16_t src_port, uint16_t dst_port);
flowcache_record_t *flowcache_record_delete(flowcache_record_t *head);
flowcache_record_t *flowcache_record_lookup(flowcache_src_host_t *src, uint16_t src_port, uint16_t dst_port);
flowcache_dst_host_t *flowcache_dst_host_lookup(struct in_addr *addr);
flowcache_src_host_t *flowcache_src_host_lookup(flowcache_dst_host_t *dst, struct in_addr *addr);

void flowcache_setup(mowgli_eventloop_t *eventloop);

#endif
