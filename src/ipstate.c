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

static patricia_tree_t *iprecord_trie = NULL;
static time_t next_unban_run;

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
	free(rec);
}

void
ipstate_clear(void)
{
	Clear_Patricia(iprecord_trie, (void_fn_t) ipstate_clear_record);
}

static void
ipstate_maybe_clear(void)
{
	if (get_time() > next_unban_run)
	{
		ipstate_clear();
		next_unban_run = get_time() + EXPIRY_CHECK;

		DPRINTF("housekeeping complete.  next run at %lu\n", (unsigned long) next_unban_run);
	}
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
ipstate_update(packet_info_t *packet)
{
	iprecord_t *rec;
	uint32_t ip;

	ip = packet->pkt_dst.s_addr;

	rec = ipstate_insert(ip);

	if (rec->flows[packet->ip_type].first == 0)
		rec->flows[packet->ip_type].first = get_time();

	rec->flows[packet->ip_type].last = get_time();
	rec->flows[packet->ip_type].bytes += packet->len;
	rec->flows[packet->ip_type].packets += packet->packets;

	if (packet->new_flow)
		rec->flows[packet->ip_type].count++;

	if (rec->flows[packet->ip_type].first != rec->flows[packet->ip_type].last)
	{
		rec->flows[packet->ip_type].flow = rec->flows[packet->ip_type].bytes / (rec->flows[packet->ip_type].last - rec->flows[packet->ip_type].first);
		rec->flows[packet->ip_type].flow *= 8;
		rec->flows[packet->ip_type].pps = rec->flows[packet->ip_type].packets / (rec->flows[packet->ip_type].last - rec->flows[packet->ip_type].first);

#ifdef DEBUG
		char dst[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET, &packet->pkt_dst, dst, INET6_ADDRSTRLEN);

		DPRINTF("      IP %s has received %ld bytes/%ld packets. (+%d B/+%d P) %f kbps %d pps %d active\n", dst,
			rec->flows[packet->ip_type].bytes, rec->flows[packet->ip_type].packets, packet->len, packet->packets, rec->flows[packet->ip_type].flow / 1000., rec->flows[packet->ip_type].pps,
			rec->flows[packet->ip_type].count);
#endif
		HOOK_CALL(HOOK_CHECK_TRIGGER, packet, rec);
	}
}

void
init_ipstate(void)
{
	iprecord_trie = New_Patricia(32);
	DPRINTF("iprecord trie %p\n", iprecord_trie);

	next_unban_run = get_time() + EXPIRY_CHECK;
	HOOK_REGISTER(HOOK_TIMER_TICK, ipstate_maybe_clear);
}
