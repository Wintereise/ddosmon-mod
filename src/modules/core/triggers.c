/*
 * triggers.c
 * Purpose: Linear condition triggers.
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

#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

#include "stdinc.h"
#include "protocols.h"
#include "packet.h"
#include "confparse.h"
#include "patricia.h"
#include "ipstate.h"
#include "hook.h"
#include "action.h"

typedef struct _triggeraction {
	struct _triggeraction *next;
	action_t *act;
} triggeraction_t;

typedef struct _trigger {
	struct _trigger *next;

	unsigned int target_pps;
	unsigned int target_mbps;
	unsigned int target_flowcount;
	unsigned int below_mbps;
	unsigned int expiry;
	unsigned char protocol;
	unsigned char tcp_synonly;

	triggeraction_t *list;
} trigger_t;

typedef struct _banrecord {
	struct _banrecord *prev, *next;

        iprecord_t irec;
	packet_info_t pkt;
	trigger_t *t;

        time_t added;
} banrecord_t;

static trigger_t *t_list[IPPROTO_MAX + 1];
static patricia_tree_t *banrecord_trie = NULL;
static banrecord_t *banrecord_list = NULL;
static int expiry;

static void
run_triggers(actiontype_t at, trigger_t *t, packet_info_t *packet, iprecord_t *rec)
{
	triggeraction_t *i;

	for (i = t->list; i != NULL; i = i->next)
		i->act->act(at, packet, rec, i->act->data);
}

static banrecord_t *
ban_find(uint32_t ip)
{
	prefix_t *pfx;
	patricia_node_t *node;
	struct in_addr sin;

	sin.s_addr = ip;
	pfx = New_Prefix(AF_INET, &sin, 32);

	node = patricia_search_exact(banrecord_trie, pfx);

	Deref_Prefix(pfx);

	return node != NULL ? node->data : NULL;
}

static banrecord_t *
trigger_ban(trigger_t *t, packet_info_t *packet, iprecord_t *irec)
{
	banrecord_t *rec;
	prefix_t *pfx;
	patricia_node_t *node;
	struct in_addr sin;

	if (ban_find(irec->addr) != NULL)
		return NULL;

	rec = calloc(sizeof(banrecord_t), 1);
	rec->next = banrecord_list;
	banrecord_list = rec;

	if (rec->next != NULL)
		rec->next->prev = rec;

	rec->t = t;
	memcpy(&rec->irec, irec, sizeof(iprecord_t));
	memcpy(&rec->pkt, packet, sizeof(packet_info_t));
	rec->added = get_time();

	sin.s_addr = irec->addr;
	pfx = New_Prefix(AF_INET, &sin, 32);

	node = patricia_lookup(banrecord_trie, pfx);
	node->data = rec;

	Deref_Prefix(pfx);

	run_triggers(ACTION_BAN, t, packet, &rec->irec);

	return rec;
}

static void
expire_triggers(void)
{
	banrecord_t *rec, *trec;

	for (rec = banrecord_list, trec = rec ? rec->next : NULL; rec != NULL; rec = trec, trec = trec ? trec->next : NULL)
	{
		struct in_addr sin;
		prefix_t *pfx;
		patricia_node_t *node;

		if (get_time() < (rec->added + expiry))
			continue;

		if (rec->t->expiry && get_time() < (rec->added + rec->t->expiry))
			continue;

		run_triggers(ACTION_UNBAN, rec->t, &rec->pkt, &rec->irec);

		sin.s_addr = rec->irec.addr;
		pfx = New_Prefix(AF_INET, &sin, 32);

		node = patricia_lookup(banrecord_trie, pfx);
		patricia_remove(banrecord_trie, node);

		if (rec->prev != NULL)
			rec->prev->next = rec->next;

		if (rec->next != NULL)
			rec->next->prev = rec->prev;

		if (rec == banrecord_list)
			banrecord_list = rec->next;

		Deref_Prefix(pfx);

		free(rec);
	}
}

static void
check_trigger(packet_info_t *packet, iprecord_t *rec)
{
	trigger_t *i;

	for (i = t_list[packet->ip_type]; i != NULL; i = i->next)
	{
		int pps, mbps;
		int do_trigger = 0;

		DPRINTF("check trigger packet %p record %p protocol %d pktproto %d\n", packet, rec, i->protocol, packet->ip_type);

		mbps = (int) floor((rec->flows[packet->ip_type].flow / 1000000.));
		pps = rec->flows[packet->ip_type].pps;

		DPRINTF("... pps %d mbps %d target_pps %d target_mbps %d\n", pps, mbps, i->target_pps, i->target_mbps);

		if (i->target_pps && (pps > i->target_pps))
			do_trigger = 1;

		if (i->target_mbps && (mbps > i->target_mbps))
			do_trigger = 1;

		if (i->target_mbps && (mbps < i->target_mbps))
			do_trigger = 0;

		if (i->below_mbps && (mbps > i->below_mbps))
			do_trigger = 0;

		if (i->tcp_synonly && packet->tcp_flags != TCP_SYN)
			do_trigger = 0;

		if (i->target_flowcount && rec->flows[packet->ip_type].count < i->target_flowcount)
			do_trigger = 0;

		DPRINTF("trigger %p conditions %s for flow %p\n", i, do_trigger == 1 ? "met" : "not met", rec);

		if (do_trigger)
			HOOK_CALL(HOOK_CHECK_EXEMPT, packet, rec, &do_trigger);

		DPRINTF("HOOK_CHECK_EXEMPT result %d\n", do_trigger);

		if (do_trigger)
			trigger_ban(i, packet, rec);
	}
}

static void
parse_actions(trigger_t *t, config_entry_t *entry)
{
	config_entry_t *ce;
	triggeraction_t *ta;

	for (ce = entry; ce != NULL; ce = ce->ce_next)
	{
		action_t *act;

		act = action_find(ce->ce_varname);
		if (act == NULL)
			continue;

		ta = calloc(sizeof(triggeraction_t), 1);
		ta->act = act;
		ta->next = t->list;
		t->list = ta;
	}
}

static void
parse_trigger(config_entry_t *entry)
{
	trigger_t *t;
	config_entry_t *ce;

	t = calloc(sizeof(trigger_t), 1);

	for (ce = entry; ce != NULL; ce = ce->ce_next)
	{
		if (!strcasecmp(ce->ce_varname, "protocol"))
		{
			if (!strcasecmp(ce->ce_vardata, "tcp"))
				t->protocol = 6;
			else if (!strcasecmp(ce->ce_vardata, "tcp-syn"))
			{
				t->protocol = 6;
				t->tcp_synonly = 1;
			}
			else if (!strcasecmp(ce->ce_vardata, "udp"))
				t->protocol = 17;
			else if (!strcasecmp(ce->ce_vardata, "icmp"))
				t->protocol = 1;
		}
		else if (!strcasecmp(ce->ce_varname, "target_mbps"))
			t->target_mbps = atoi(ce->ce_vardata);
		else if (!strcasecmp(ce->ce_varname, "flowcount"))
			t->target_flowcount = atoi(ce->ce_vardata);
		else if (!strcasecmp(ce->ce_varname, "below_mbps"))
			t->below_mbps = atoi(ce->ce_vardata);
		else if (!strcasecmp(ce->ce_varname, "target_pps"))
			t->target_pps = atoi(ce->ce_vardata);
		else if (!strcasecmp(ce->ce_varname, "expiry"))
			t->expiry = atoi(ce->ce_vardata);
		else if (!strcasecmp(ce->ce_varname, "actions"))
			parse_actions(t, ce->ce_entries);
	}

	DPRINTF("t->protocol %d\n", t->protocol);

	t->next = t_list[t->protocol];
	t_list[t->protocol] = t;
}

void
module_cons(config_entry_t *entry)
{
	config_entry_t *ce;

	memset(t_list, 0, sizeof(t_list));

	for (ce = entry; ce != NULL; ce = ce->ce_next)
	{
		if (!strcasecmp(ce->ce_varname, "trigger"))
			parse_trigger(ce->ce_entries);
		else if (!strcasecmp(ce->ce_varname, "expiry"))
			expiry = atoi(ce->ce_vardata);
	}

	banrecord_trie = New_Patricia(32);

	HOOK_REGISTER(HOOK_CHECK_TRIGGER, check_trigger);
	HOOK_REGISTER(HOOK_TIMER_TICK, expire_triggers);
}
