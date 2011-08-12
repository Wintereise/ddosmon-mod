/*
 * netflow.c
 * parse netflow v5 and v9 records.
 *
 * Copyright (c) 2011 TortoiseLabs, Inc.
 *
 * THIS SOFTWARE IS PROPRIETARY AND CONFIDENTIAL.  REDISTRIBUTION WITHOUT PRIOR
 * AUTHORIZATION MAY RESULT IN CIVIL AND/OR CRIMINAL PENALTIES.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>

#include "stdinc.h"
#include "protocols.h"
#include "packet.h"
#include "eventsource.h"
#include "confparse.h"
#include "patricia.h"
#include "ipstate.h"
#include "hook.h"

#ifndef BUFSIZ
#define BUFSIZ 65535
#endif

#define FLOW_EXPIRY_TIME		(EXPIRY_CHECK)

static int sock;

/*****************************************************************************************
 * Netflow packet layout and descriptions.                                               *
 *****************************************************************************************/

typedef struct {
	uint16_t version;
} netflow_common_t;

typedef struct {
	uint16_t version;
	uint16_t flowcount;
	uint32_t uptime;
	uint32_t unix_ts;
	uint32_t unix_tns;
	uint32_t sequence;
	uint8_t engine_type;
	uint8_t engine_id;
	uint16_t samp_interval;
} netflow_v5hdr_t;

typedef struct {
	struct in_addr src;
	struct in_addr dst;
	struct in_addr nexthop;
	uint16_t snmp_in;
	uint16_t snmp_out;
	uint32_t packets;
	uint32_t bytes;
	uint32_t first_ts;
	uint32_t last_ts;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t pad1;
	uint8_t tcp_flags;
	uint8_t proto;
	uint8_t tos;
	uint16_t src_asn;
	uint16_t dst_asn;
	uint8_t src_mask;
	uint8_t dst_mask;
	uint16_t pad2;
} netflow_v5rec_t;

typedef enum {
	NETFLOW_VERSION_5 = 5,
	NETFLOW_VERSION_9 = 9,
	NETFLOW_MAX_VERSION
} netflow_version_t;

typedef enum {
	NETFLOW_PROTO_TCP = 6,
	NETFLOW_PROTO_UDP = 17,
	NETFLOW_MAX_PROTO = 255,
} netflow_proto_t;

static const char *protonames[NETFLOW_MAX_PROTO] = {
	[NETFLOW_PROTO_TCP] = "TCP",
	[NETFLOW_PROTO_UDP] = "UDP",
};

/*****************************************************************************************
 * Flow cache and delta application.                                                     *
 *****************************************************************************************/

#define FLOW_HASH_SIZE		65536 >> 12
#define FLOW_HASH(src_port)	((src_port) >> 12)

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

static patricia_tree_t *dst_host_tree = NULL;

static flowcache_record_t *
flowcache_record_insert(flowcache_record_t *parent, uint16_t src_port, uint16_t dst_port)
{
	flowcache_record_t *child;

	child = calloc(sizeof(*child), 1);
	child->next = parent;

	/* reparent the parent node if one is present. */
	if (child->next != NULL)
		child->next->prev = child;

	child->first_seen = get_time();

	child->src_port = src_port;
	child->dst_port = dst_port;

	return child;
}

static flowcache_record_t *
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

	free(head);

	return next;
}

static flowcache_record_t *
flowcache_record_lookup(flowcache_src_host_t *src, uint16_t src_port, uint16_t dst_port)
{
	flowcache_record_t *head, *node;

#ifdef VERBOSE_DEBUG
	DPRINTF("looking for flow %d -> %d for source %p hashv %d\n", src_port, dst_port, src, FLOW_HASH(src_port));
#endif

	for (head = src->flows[FLOW_HASH(src_port)], node = head; node != NULL; node = node->next)
	{
		if (node->src_port == src_port && node->dst_port == dst_port)
			return node;
	}

	return NULL;
}

static flowcache_dst_host_t *
flowcache_dst_host_lookup(struct in_addr *addr)
{
	prefix_t *pfx;
	patricia_node_t *node;
	flowcache_dst_host_t *host;

        pfx = New_Prefix(AF_INET, addr, 32);
	node = patricia_search_exact(dst_host_tree, pfx);
	Deref_Prefix(pfx);

	if (node != NULL)
		return node->data;

	host = calloc(sizeof(*host), 1);
	host->src_host_tree = New_Patricia(32);

	pfx = New_Prefix(AF_INET, addr, 32);
	node = patricia_lookup(dst_host_tree, pfx);
	node->data = host;

	return host;
}

static flowcache_src_host_t *
flowcache_src_host_lookup(flowcache_dst_host_t *dst, struct in_addr *addr)
{
	prefix_t *pfx;
	patricia_node_t *node;
	flowcache_src_host_t *host;

        pfx = New_Prefix(AF_INET, addr, 32);
	node = patricia_search_exact(dst->src_host_tree, pfx);
	Deref_Prefix(pfx);

	if (node != NULL)
		return node->data;

	host = calloc(sizeof(*host), 1);

	pfx = New_Prefix(AF_INET, addr, 32);
	node = patricia_lookup(dst->src_host_tree, pfx);
	node->data = host;

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

	free(src);
}

static void
flowcache_dst_free(flowcache_dst_host_t *dst)
{
	DPRINTF("clearing flow cache for target %p\n", dst);

	Destroy_Patricia(dst->src_host_tree, (void_fn_t) flowcache_src_free);
        free(dst);
}

static time_t flowcache_next_clear;

static void
flowcache_clear(void)
{
	if (get_time() > flowcache_next_clear)
	{
		Clear_Patricia(dst_host_tree, (void_fn_t) flowcache_dst_free);
		flowcache_next_clear = get_time() + FLOW_EXPIRY_TIME;

		DPRINTF("housekeeping complete.  next housekeeping run at %lu\n", (unsigned long) flowcache_next_clear);
	}
}

/*****************************************************************************************
 * Netflow v5 integration functions for flowcache.                                       *
 *****************************************************************************************/

static flowcache_record_t *
flowcache_correlate_v5(netflow_v5rec_t *rec)
{
	flowcache_src_host_t *src;
	flowcache_dst_host_t *dst;
	flowcache_record_t *record;
	uint8_t hashv = FLOW_HASH(rec->src_port);

	dst = flowcache_dst_host_lookup(&rec->dst);
	src = flowcache_src_host_lookup(dst, &rec->src);

	record = flowcache_record_lookup(src, rec->src_port, rec->dst_port);
	if (record != NULL)
	{
		DPRINTF("found cached flow for %p/hashv:%d\n", rec, hashv);
		return record;
	}

	record = src->flows[hashv] =
		flowcache_record_insert(src->flows[hashv], rec->src_port, rec->dst_port);

	return record;
}

/*****************************************************************************************
 * Netflow packet parsing.                                                               *
 *****************************************************************************************/

typedef void (*netflow_parse_f)(unsigned char *pkt, packet_info_t *info);

static void netflow_parse_v5(unsigned char *pkt, packet_info_t *info)
{
	int flow;
	netflow_v5hdr_t *hdr = (netflow_v5hdr_t *) pkt;
	netflow_v5rec_t *rec = NULL;

	hdr->flowcount = ntohs(hdr->flowcount);
	hdr->uptime = ntohl(hdr->uptime);
	hdr->unix_ts = ntohl(hdr->unix_ts);
	hdr->unix_tns = ntohl(hdr->unix_tns);
	hdr->sequence = ntohl(hdr->sequence);
	hdr->samp_interval = ntohs(hdr->samp_interval) & ~0xc000;

	DPRINTF("  Number of exported flows: %u\n", hdr->flowcount);
	DPRINTF("  Uptime                  : %u ms\n", hdr->uptime);
	DPRINTF("  Epoch                   : %u.%u\n", hdr->unix_ts, hdr->unix_tns);
	DPRINTF("  Sequence                : %u\n", hdr->sequence);
	DPRINTF("  Samplerate              : %u\n", hdr->samp_interval);

	for (flow = 0, rec = (netflow_v5rec_t *) (pkt + sizeof(netflow_v5hdr_t));
	     flow < hdr->flowcount; flow++, rec++)
	{
		packet_info_t inject;

		rec->src_port = ntohs(rec->src_port);
		rec->dst_port = ntohs(rec->dst_port);

		rec->packets = ntohl(rec->packets);
		rec->bytes = ntohl(rec->bytes);

		rec->first_ts = ntohl(rec->first_ts) / 1000;
		rec->last_ts = ntohl(rec->last_ts) / 1000;

#ifdef DEBUG
		static char srcbuf[INET6_ADDRSTRLEN];
		static char dstbuf[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET, &rec->src, srcbuf, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET, &rec->dst, dstbuf, INET6_ADDRSTRLEN);

		DPRINTF("  Flow %d, %s/%d -> %s/%d [%s] {0x%x} (%d bytes, %d packets)\n", flow,
			srcbuf, rec->src_port, dstbuf, rec->dst_port, protonames[rec->proto],
			rec->tcp_flags, rec->bytes, rec->packets);
#endif

		flowcache_record_t *crec;

		crec = flowcache_correlate_v5(rec);

		int fakebps = (rec->bytes - crec->bytes);
		int fakepps = (rec->packets - crec->packets);

		/* nenolod:
		 * it seems that sometimes the netflow counters go backward... we don't want
		 * to go backward, although our state machine seems to not care much about it.
		 */
		if (fakebps < 0 || fakepps < 1)
			continue;

		DPRINTF("    Flow fakepps: (%d - %d) = %d\n", rec->packets, crec->packets, fakepps);
		DPRINTF("    Flow fakebps: (%d - %d) = %d\n", rec->bytes, crec->bytes, fakebps);

		inject = (packet_info_t){
			.pkt_src = rec->src,
			.pkt_dst = rec->dst,
			.src_prt = rec->src_port,
			.dst_prt = rec->dst_port,
			.ether_type = 8,
			.ip_type = rec->proto != 0 ? rec->proto : NETFLOW_PROTO_TCP,
			.len = fakebps,
			.packets = fakepps,
			.tcp_flags = rec->tcp_flags,
			.new_flow = !crec->injected,
		};

		/* if flow is pre-cached, or small, then inject it. */
		if ((crec->bytes != 0 || crec->packets != 0))
		{
			crec->injected = true;
			ipstate_update(&inject);
		}
		else if ((rec->bytes <= 1024 && rec->packets <= 20))
		{
			crec->injected = true;
			ipstate_update(&inject);
		}

		crec->bytes = rec->bytes;
		crec->packets = rec->packets;
	}
}

static void netflow_parse_v9(unsigned char *pkt, packet_info_t *info)
{
	DPRINTF("Todo: %s\n", "implement me");
}

static netflow_parse_f pfunc[NETFLOW_MAX_VERSION] = {
	[NETFLOW_VERSION_5] = netflow_parse_v5,
	[NETFLOW_VERSION_9] = netflow_parse_v9,
};

static void
netflow_prepare(void)
{
	sock = socket(AF_INET, SOCK_DGRAM, 0);

	struct sockaddr_in sin = { .sin_port = htons(9996) };
	bind(sock, (struct sockaddr *) &sin, sizeof sin);

	DPRINTF("listening on udp port %d\n", 9996);

	dst_host_tree = New_Patricia(32);

	HOOK_REGISTER(HOOK_TIMER_TICK, flowcache_clear);
	flowcache_next_clear = get_time() + FLOW_EXPIRY_TIME;
}

static const unsigned char *
netflow_readpkt(packet_info_t *info)
{
	unsigned int len;
	unsigned char pkt[BUFSIZ];
	netflow_common_t *cmn;

#if 0
	DPRINTF("reading udp/%d\n", sock);
#endif

	len = recv(sock, pkt, BUFSIZ, 0);
	info->len = len;
	info->ts.tv_sec = time(NULL);

	/* parse the header ... */
	cmn = (netflow_common_t *) pkt;
	cmn->version = ntohs(cmn->version);

	DPRINTF("Netflow version %d.\n", cmn->version);
	pfunc[cmn->version](pkt, info);

	/*
	 * as netflow is layer-3 oriented, we do not need to parse raw link-layer frames.
	 * returning NULL will bypass the parser.  --nenolod
	 */
	return NULL;
}

static void
netflow_shutdown(void)
{
	close(sock);
}

static eventsource_t netflow_eventsource = {
	netflow_prepare,
	netflow_readpkt,
	netflow_shutdown
};

void
module_cons(config_entry_t *entry)
{
	ev = &netflow_eventsource;
}
