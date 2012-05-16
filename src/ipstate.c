/*
 * ipstate.c
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

#include "stdinc.h"
#include "protocols.h"
#include "packet.h"
#include "ipstate.h"
#include "patricia.h"
#include "hook.h"

#define IP_EXPIRY_TIME		(600)

static patricia_tree_t *iprecord_trie = NULL;

static iprecord_t *
ipstate_find(uint32_t ip)
{
	prefix_t *pfx;
	patricia_node_t *node;
	struct in_addr sin;

	sin.s_addr = ip;
	pfx = New_Prefix(AF_INET, &sin, 32);

	node = patricia_search_exact(iprecord_trie, pfx);

	Deref_Prefix(pfx);

	return node != NULL ? node->data : NULL;
}

static void
ipstate_clear_record(iprecord_t *rec)
{
	prefix_t *pfx;
	patricia_node_t *node;
	struct in_addr sin;

	sin.s_addr = rec->addr;
	pfx = New_Prefix(AF_INET, &sin, 32);

	node = patricia_lookup(iprecord_trie, pfx);
	patricia_remove(iprecord_trie, node);

	Deref_Prefix(pfx);

	free(rec);
}

static void
ipstate_expire(void *unused)
{
	patricia_node_t *node;
	time_t ts = mowgli_eventloop_get_time(eventloop);

	PATRICIA_WALK(iprecord_trie->head, node)
	{
		iprecord_t *rec = node->data;

		if ((rec->last + IP_EXPIRY_TIME) > ts)
			continue;

		ipstate_clear_record(rec);
	}
	PATRICIA_WALK_END;
}

static iprecord_t *
ipstate_insert(uint32_t ip)
{
	iprecord_t *rec;
	prefix_t *pfx;
	patricia_node_t *node;
	struct in_addr sin;

	if ((rec = ipstate_find(ip)) != NULL) {
		DPRINTF("record exists %p\n", rec);
		return rec;
	}

	sin.s_addr = ip;
	pfx = New_Prefix(AF_INET, &sin, 32);

	rec = calloc(sizeof(iprecord_t), 1);
	rec->addr = ip;

	node = patricia_lookup(iprecord_trie, pfx);
	node->data = rec;	

	Deref_Prefix(pfx);

	DPRINTF("inserted record %p node %p\n", rec, node);
	return rec;
}

void
ipstate_reset_flowcount(struct in_addr *ip)
{
	iprecord_t *rec;
	int i;

	rec = ipstate_insert(ip->s_addr);
	for (i = 0; i < IPPROTO_MAX; i++)
		rec->flows[i].count = 0;
}

void
ipstate_update(packet_info_t *packet)
{
	iprecord_t *rec;
	uint32_t ip;

	ip = packet->pkt_dst.s_addr;

	rec = ipstate_insert(ip);

	rec->last = packet->ts.tv_sec;
	rec->flows[packet->ip_type].current = packet->ts.tv_sec;
	rec->flows[packet->ip_type].bytes_pending += packet->len;
	rec->flows[packet->ip_type].packets_pending += packet->packets;

	if (packet->new_flow)
		rec->flows[packet->ip_type].count++;

	if (rec->flows[packet->ip_type].last == 0)
		rec->flows[packet->ip_type].last = rec->flows[packet->ip_type].current;

	if (rec->flows[packet->ip_type].last != rec->flows[packet->ip_type].current)
	{
		rec->flows[packet->ip_type].flow = rec->flows[packet->ip_type].bytes_pending / (rec->flows[packet->ip_type].current - rec->flows[packet->ip_type].last);
		rec->flows[packet->ip_type].flow *= 8;
		rec->flows[packet->ip_type].pps = rec->flows[packet->ip_type].packets_pending / (rec->flows[packet->ip_type].current - rec->flows[packet->ip_type].last);

#ifdef DEBUG
		char dst[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET, &packet->pkt_dst, dst, INET6_ADDRSTRLEN);

		DPRINTF("      IP %s has received %ld bytes/%ld packets. (+%zu B/+%d P) %f kbps %ld pps %d active\n", dst,
			rec->flows[packet->ip_type].bytes, rec->flows[packet->ip_type].packets, packet->len, packet->packets, rec->flows[packet->ip_type].flow / 1000., rec->flows[packet->ip_type].pps,
			rec->flows[packet->ip_type].count);
#endif
		HOOK_CALL(HOOK_CHECK_TRIGGER, packet, rec);

		rec->flows[packet->ip_type].bytes += rec->flows[packet->ip_type].bytes_pending;
		rec->flows[packet->ip_type].packets += rec->flows[packet->ip_type].packets_pending;
		rec->flows[packet->ip_type].last = rec->flows[packet->ip_type].current;

		rec->flows[packet->ip_type].bytes_pending = rec->flows[packet->ip_type].packets_pending = 0;
	}
}

void
ipstate_setup(mowgli_eventloop_t *eventloop)
{
	iprecord_trie = New_Patricia(32);
	DPRINTF("iprecord trie %p\n", iprecord_trie);

	mowgli_timer_add(eventloop, "ipstate_expire", ipstate_expire, NULL, IP_EXPIRY_TIME);
}
