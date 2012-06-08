/*
 * flowcache.c
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

#include "stdinc.h"
#include "protocols.h"
#include "packet.h"
#include "ipstate.h"
#include "patricia.h"
#include "hook.h"
#include "flowcache.h"

static patricia_tree_t *dst_host_tree = NULL;

static magazine_t flowcache_record_magazine = MAGAZINE_INIT(sizeof(flowcache_record_t));
static magazine_t flowcache_src_magazine = MAGAZINE_INIT(sizeof(flowcache_src_host_t));
static magazine_t flowcache_dst_magazine = MAGAZINE_INIT(sizeof(flowcache_dst_host_t));

flowcache_record_t *
flowcache_record_insert(flowcache_dst_host_t *dst, flowcache_src_host_t *src, flowcache_record_t *parent, uint16_t src_port, uint16_t dst_port, uint8_t ip_type)
{
	flowcache_record_t *child;

	child = magazine_alloc(&flowcache_record_magazine);
	child->next = parent;

	child->src = src;
	child->dst = dst;
	child->ip_type = ip_type;

	/* reparent the parent node if one is present. */
	if (child->next != NULL)
		child->next->prev = child;

	child->first_seen = child->last_seen = mowgli_eventloop_get_time(eventloop);

	child->src_port = src_port;
	child->dst_port = dst_port;

	child->src->flowcount++;
	child->dst->flowcount++;

	return child;
}

flowcache_record_t *
flowcache_record_delete(flowcache_record_t *head)
{
	flowcache_record_t *next;

	DPRINTF("destroying flow %p (%d -> %d)\n", head, head->src_port, head->dst_port);

	next = head->next;
	if (next)
	{
		next->prev = head->prev;

		if (next->prev)
			next->prev->next = next;
	}

	head->dst->flowcount--;
	head->src->flowcount--;

	ipstate_decr_flow(&head->dst->addr, head->ip_type);
	magazine_release(&flowcache_record_magazine, head);

	return next;
}

flowcache_record_t *
flowcache_record_lookup(flowcache_src_host_t *src, uint16_t src_port, uint16_t dst_port)
{
	flowcache_record_t *head, *node;

#ifdef VERBOSE_DEBUG
	DPRINTF("looking for flow %d -> %d for source %p hashv %d\n", src_port, dst_port, src, FLOW_HASH(src_port));
#endif

	for (head = src->flows[FLOW_HASH(src_port)], node = head; node != NULL; node = node->next)
	{
		if (node->src_port == src_port && node->dst_port == dst_port)
		{
			node->last_seen = mowgli_eventloop_get_time(eventloop);
			return node;
		}
	}

	return NULL;
}

flowcache_dst_host_t *
flowcache_dst_host_lookup(struct in_addr *addr)
{
	prefix_t *pfx;
	patricia_node_t *node;
	flowcache_dst_host_t *host;

	return_val_if_fail(addr != NULL, NULL);

        pfx = New_Prefix(AF_INET, addr, 32);
	node = patricia_search_exact(dst_host_tree, pfx);
	Deref_Prefix(pfx);

	if (node != NULL)
		return node->data;

	host = magazine_alloc(&flowcache_dst_magazine);
	host->addr = *addr;
	host->src_host_tree = New_Patricia(32);

	pfx = New_Prefix(AF_INET, addr, 32);
	node = patricia_lookup(dst_host_tree, pfx);
	node->data = host;
	Deref_Prefix(pfx);

	return host;
}

flowcache_src_host_t *
flowcache_src_host_lookup(flowcache_dst_host_t *dst, struct in_addr *addr)
{
	prefix_t *pfx;
	patricia_node_t *node;
	flowcache_src_host_t *host;

	return_val_if_fail(dst != NULL, NULL);
	return_val_if_fail(addr != NULL, NULL);

        pfx = New_Prefix(AF_INET, addr, 32);
	node = patricia_search_exact(dst->src_host_tree, pfx);
	Deref_Prefix(pfx);

	if (node != NULL)
		return node->data;

	host = magazine_alloc(&flowcache_src_magazine);
	host->addr = *addr;

	pfx = New_Prefix(AF_INET, addr, 32);
	node = patricia_lookup(dst->src_host_tree, pfx);
	node->data = host;
	Deref_Prefix(pfx);

	return host;
}

static void
flowcache_src_free(flowcache_src_host_t *src)
{
	flowcache_record_t *record;
	int hashv;

	DPRINTF("clearing flow cache for source %p\n", src);

	for (hashv = 0; hashv < FLOW_HASH_SIZE; hashv++)
	{
		record = src->flows[hashv];

		while (record != NULL)
		{
			record = flowcache_record_delete(record);
		}
	}

	magazine_release(&flowcache_src_magazine, src);
}

static void
flowcache_dst_free(flowcache_dst_host_t *dst)
{
	DPRINTF("clearing flow cache for target %p\n", dst);

	Destroy_Patricia(dst->src_host_tree, (void_fn_t) flowcache_src_free);

	magazine_release(&flowcache_dst_magazine, dst);
}

void
flowcache_dst_clear(struct in_addr *addr)
{
	flowcache_dst_host_t *dst;

	dst = flowcache_dst_host_lookup(addr);
	if (dst == NULL)
		return;

	flowcache_dst_free(dst);
}

void
flowcache_setup(mowgli_eventloop_t *eventloop)
{
	(void) eventloop;

	dst_host_tree = New_Patricia(32);
}
