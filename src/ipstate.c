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

int ip_expiry_time = IP_EXPIRY_TIME;

static patricia_tree_t *iprecord_trie = NULL;
static magazine_t iprecord_magazine = MAGAZINE_INIT(sizeof(iprecord_t));

static void
ipstate_clear_record(iprecord_t *rec)
{
	prefix_t *pfx;
	patricia_node_t *node;
	struct in_addr sin;

	sin.s_addr = rec->addr.s_addr;
	pfx = New_Prefix(AF_INET, &sin, 32);

	node = patricia_search_exact(iprecord_trie, pfx);
	patricia_remove(iprecord_trie, node);

	Deref_Prefix(pfx);

	flowcache_dst_clear(&sin);
	magazine_release(&iprecord_magazine, rec);
}

static void
ipstate_expire(void *unused)
{
	mowgli_node_t *n, *tn;
	mowgli_list_t clear_list = { NULL, NULL, 0 };
	patricia_node_t *node;
	time_t ts = mowgli_eventloop_get_time(eventloop);

	DPRINTF("starting to expire old entries, %d nodes\n", iprecord_trie->num_active_node);

	PATRICIA_WALK(iprecord_trie->head, node)
	{
		iprecord_t *rec = node->data;

		if (rec != NULL && (rec->last + ip_expiry_time) <= ts)
		{
			DPRINTF("  node %p [ts:%ld] marked for expiry\n", rec, rec->last);
			mowgli_node_add(rec, mowgli_node_create(), &clear_list);
		}
	}
	PATRICIA_WALK_END;

	MOWGLI_ITER_FOREACH_SAFE(n, tn, clear_list.head)
	{
		ipstate_clear_record(n->data);
		mowgli_node_delete(n, &clear_list);
		mowgli_node_free(n);
	}

	DPRINTF("expiry code finished, %d nodes remaining\n", iprecord_trie->num_active_node);
}

static inline iprecord_t *
ipstate_lookup(struct in_addr *ip)
{
	iprecord_t *rec;
	prefix_t *pfx;
	patricia_node_t *node;

	pfx = New_Prefix(AF_INET, ip, 32);

	node = patricia_search_exact(iprecord_trie, pfx);
	if (node != NULL)
	{
		Deref_Prefix(pfx);
		return node->data;
	}

	Deref_Prefix(pfx);
	return NULL;
}

static iprecord_t *
ipstate_insert(struct in_addr *ip)
{
	iprecord_t *rec;
	prefix_t *pfx;
	patricia_node_t *node;

	pfx = New_Prefix(AF_INET, ip, 32);

	node = patricia_search_exact(iprecord_trie, pfx);
	if (node != NULL)
	{
		Deref_Prefix(pfx);
		return node->data;
	}

	rec = magazine_alloc(&iprecord_magazine);
	rec->addr.s_addr = ip->s_addr;

	node = patricia_lookup(iprecord_trie, pfx);
	node->data = rec;

	Deref_Prefix(pfx);

	DPRINTF("inserted record %p node %p\n", rec, node);
	return rec;
}

void
ipstate_decr_flow(struct in_addr *ip, unsigned short ip_type)
{
	iprecord_t *rec;
	flowdata_t *flow;

	rec = ipstate_lookup(ip);
	if (rec == NULL)
		return;

	flow = ipstate_lookup_flowdata(rec, ip_type);
	if (flow == NULL)
		return;

	flow->count--;
}

void
ipstate_incr_flow(struct in_addr *ip, unsigned short ip_type)
{
	iprecord_t *rec;
	flowdata_t *flow;

	rec = ipstate_lookup(ip);
	if (rec == NULL)
		return;

	flow = ipstate_lookup_flowdata(rec, ip_type);
	if (flow == NULL)
		return;

	flow->count++;
}

void
ipstate_update(packet_info_t *packet)
{
	iprecord_t *rec;
	flowdata_t *flow;

	rec = ipstate_insert(&packet->pkt_dst);
	rec->last = packet->ts.tv_sec;

	if (packet->new_flow)
		ipstate_incr_flow(&packet->pkt_dst, packet->ip_type);

	flow = ipstate_lookup_flowdata(rec, packet->ip_type);
	if (flow == NULL)
	{
		DPRINTF("eh?  no flowdata journal entries for iprecord %p\n", rec);
		return;
	}

	flow->current = packet->ts.tv_sec;
	flow->bytes_pending += packet->len;
	flow->packets_pending += packet->packets;

	if (flow->last == 0)
		flow->last = flow->current;

	if (flow->last != flow->current)
	{
		flow->flow = flow->bytes_pending / (flow->current - flow->last);
		flow->flow *= 8;
		flow->pps = flow->packets_pending / (flow->current - flow->last);

#ifdef DEBUG
		char dst[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET, &packet->pkt_dst, dst, INET6_ADDRSTRLEN);

		DPRINTF("      IP %s has received %ld bytes/%ld packets. (+%zu B/+%d P) %f kbps %ld pps %d active\n", dst,
			flow->bytes, flow->packets, packet->len, packet->packets, flow->flow / 1000., flow->pps,
			flow->count);
#endif
		HOOK_CALL(HOOK_CHECK_TRIGGER, packet, rec);

		flow->bytes += flow->bytes_pending;
		flow->packets += flow->packets_pending;
		flow->last = flow->current;

		flow->bytes_pending = flow->packets_pending = 0;
	}
}

void
ipstate_setup(mowgli_eventloop_t *eventloop)
{
	int tock_period = ip_expiry_time / 4;

	iprecord_trie = New_Patricia(32);
	DPRINTF("iprecord trie %p, node lifetime %d, tock period %d\n", iprecord_trie, ip_expiry_time, tock_period);

	mowgli_timer_add(eventloop, "ipstate_expire", ipstate_expire, NULL, tock_period);
}
