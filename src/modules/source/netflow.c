/*
 * netflow.c
 * Purpose: Parse netflow v1/v5/v9 records
 *
 * Copyright (c) 2011 - 2012, TortoiseLabs LLC.
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

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>

#include "stdinc.h"
#include "protocols.h"
#include "packet.h"
#include "patricia.h"
#include "ipstate.h"
#include "sourcefactory.h"
#include "flowcache.h"
#include "hook.h"

#ifndef BUFSIZ
#define BUFSIZ 65535
#endif

static bool add_ethernet_overhead = false;

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
} netflow_v1hdr_t;

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
	uint16_t pad1;
	uint8_t proto;
	uint8_t tos;
	uint8_t tcp_flags;
	unsigned char pad2[7];
} netflow_v1rec_t;

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

typedef struct {
	uint16_t version;
	uint16_t flowcount;
	uint32_t uptime;
	uint32_t unix_ts;
	uint32_t unix_tns;
	uint32_t sequence;
	uint32_t reserved;
} netflow_v7hdr_t;

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
	uint8_t rtr_flags;
	uint8_t tcp_flags;
	uint8_t proto;
	uint8_t tos;
	uint16_t dst_asn;
	uint16_t src_asn;
	uint8_t dst_mask;
	uint8_t src_mask;
	uint16_t pad2;
	uint32_t router_skip_id;
} netflow_v7rec_t;

typedef struct {
	uint16_t version;
	uint16_t flowcount;
	uint32_t uptime;
	uint32_t unix_ts;
	uint32_t sequence;
	uint32_t source_id;
} netflow_v9hdr_t;

typedef struct {
	uint16_t tmpl_id;
	uint16_t fieldcount;
	struct {
		uint16_t type;
		uint16_t length;
	} record[1];	
} netflow_v9tmplrec_t;

typedef struct {
	uint16_t flowset_id;
	uint16_t length;
} netflow_v9flowset_t;

typedef struct {
	uint16_t tmpl_id;
	uint16_t fieldcount;
} netflow_v9tmpl_t;

typedef struct {
	uint16_t field_id;
	uint16_t length;
} netflow_v9tmpl_cursor_t;

typedef enum {
	NETFLOW_VERSION_1 = 1,
	NETFLOW_VERSION_5 = 5,
	NETFLOW_VERSION_7 = 7,
	NETFLOW_VERSION_9 = 9,
	NETFLOW_MAX_VERSION
} netflow_version_t;

typedef enum {
	NETFLOW_PROTO_TCP = 6,
	NETFLOW_PROTO_UDP = 17,
	NETFLOW_MAX_PROTO = IPPROTO_MAX,
} netflow_proto_t;

static const char *protonames[NETFLOW_MAX_PROTO + 1] = {
	[NETFLOW_PROTO_TCP] = "TCP",
	[NETFLOW_PROTO_UDP] = "UDP",
};

/*****************************************************************************************
 * Netflow v9 exporter housekeeping (most of this part is derivative of nfdump)          *
 *****************************************************************************************/

typedef struct {
	uint16_t input_offset;
	uint16_t output_offset;
	uint16_t length;
} translation_element_t;

typedef struct input_translation_ {
	struct input_translation_	*next;
	uint32_t flags;
	time_t updated;
	uint32_t id;
	uint32_t input_record_size;
	uint32_t output_record_size;
	uint32_t input_index;
	uint32_t zero_index;
	uint32_t src_as_offset;
	uint32_t dst_as_offset;
	uint32_t packet_offset;
	uint32_t byte_offset;
	uint32_t ICMP_offset;
	uint32_t sampler_offset;
	uint32_t sampler_size;
	uint32_t router_ip_offset;
	uint32_t engine_offset;
	translation_element_t element[];
} input_translation_t;

typedef struct {
	uint32_t exporter_id;
	uint32_t version;

	input_translation_t *input_translation_table; 
	input_translation_t *current_table;
} exporter_t;

/* module limited globals */
static struct element_info_s {
	// min number of bytes
	uint16_t	min;
	// max number of bytes
	uint16_t	max;
	// number of optional extension.
	// required extensions and v9 tags not mapping to any extension are set to 0
	// this field is used to form the extension map
	uint16_t	extension;
} element_info[128] = {
	{ 0, 0, 0 }, 	//  0 - empty
	{ 8, 8, 0 }, 	//  1 - NF9_IN_BYTES
	{ 8, 8, 0 }, 	//  2 - NF9_IN_PACKETS
	{ 4, 8, 18 }, 	//  3 - NF9_FLOWS
	{ 1, 1, 0 }, 	//  4 - NF9_IN_PROTOCOL
	{ 1, 1, 0 },	//  5 - NF9_SRC_TOS
	{ 1, 1, 0 },	//  6 - NF9_TCP_FLAGS
	{ 2, 2, 0 },	//  7 - NF9_L4_SRC_PORT
	{ 4, 4, 0 },	//  8 - NF9_IPV4_SRC_ADDR
	{ 1, 1, 8 },	//  9 - NF9_SRC_MASK
	{ 2, 4, 4 },	// 10 - NF9_INPUT_SNMP
	{ 2, 2, 0 },	// 11 - NF9_L4_DST_PORT
	{ 4, 4, 0 },	// 12 - NF9_IPV4_DST_ADDR
	{ 1, 1, 8 },	// 13 - NF9_DST_MASK
	{ 2, 4, 4 },	// 14 - NF9_OUTPUT_SNMP
	{ 4, 4, 9 },	// 15 - NF9_IPV4_NEXT_HOP
	{ 2, 4, 6 },	// 16 - NF9_SRC_AS
	{ 2, 4, 6 },	// 17 - NF9_DST_AS

	{ 4, 4, 11}, 	// 18 - NF9_BGP_V4_NEXT_HOP

	// 19 - 20 not implemented
	{ 0, 0, 0}, { 0, 0, 0}, 				

	{ 4, 4, 0 },	// 21 - NF9_LAST_SWITCHED
	{ 4, 4, 0 },	// 22 - NF9_FIRST_SWITCHED
	{ 4, 8, 16 },	// 23 - NF9_OUT_BYTES
	{ 4, 8, 14 },	// 24 - NF9_OUT_PKTS

	{ 0, 0, 0}, { 0, 0, 0}, 					// 25 - 26 not implemented

	{ 16, 16, 0 },	// 27 - NF9_IPV6_SRC_ADDR
	{ 16, 16, 0 },	// 28 - NF9_IPV6_DST_ADDR
	{ 1, 1, 8 },	// 29 - NF9_IPV6_SRC_MASK
	{ 1, 1, 8 },	// 30 - NF9_IPV6_DST_MASK
	{ 4, 4, 0 },	// 31 - NF9_IPV6_FLOW_LABEL
	{ 2, 2, 0 },	// 32 - NF9_ICMP_TYPE

	{ 0, 0, 0},		// 33 - not implemented

	{ 4, 4, 0}, 	// 34 - NF9_SAMPLING_INTERVAL
	{ 1, 1, 0}, 	// 35 - NF9_SAMPLING_ALGORITHM

	{ 0, 0, 0}, { 0, 0, 0}, // 36 - 37 not implemented

	{ 1, 1, 0 },	// 38 - NF9_ENGINE_TYPE
	{ 1, 1, 0 },	// 39 - NF9_ENGINE_ID

	// 40 - 47   not implemented
	{ 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, 
	
	{ 1, 2, 0}, 	// 48 - NF9_FLOW_SAMPLER_ID
	{ 1, 1, 0}, 	// 49 - FLOW_SAMPLER_MODE
	{ 4, 4, 0}, 	// 50 - NF9_FLOW_SAMPLER_RANDOM_INTERVAL

	// 51 - 54 not implemented
	{ 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, 

	{ 1, 1, 8 }, 	// 55 - NF9_DST_TOS

	// 56 - 57   MACs
	{ 8, 8, 20}, 	// 56 NF9_IN_SRC_MAC
	{ 8, 8, 20}, 	// 57 NF9_OUT_DST_MAC

	{ 2, 2, 13}, 	// 58 - NF9_SRC_VLAN
	{ 2, 2, 13}, 	// 59 - NF9_DST_VLAN

	// 60   not implemented
	{ 0, 0, 0}, 

	{ 1, 1, 8 }, 	// 61 - NF9_DIRECTION

	{ 16, 16, 10}, 	// 62 - NF9_V6_NEXT_HOP
	{ 16, 16, 12}, 	// 63 - NF9_BPG_V6_NEXT_HOP

	// 64 - 69   not implemented
	{ 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, 

	// 70
	{ 4, 4, 22}, 	// 70 - MPLS_LABEL_1
	{ 4, 4, 22}, 	// 71 - MPLS_LABEL_2
	{ 4, 4, 22}, 	// 72 - MPLS_LABEL_2
	{ 4, 4, 22}, 	// 73 - MPLS_LABEL_2
	{ 4, 4, 22}, 	// 74 - MPLS_LABEL_2
	{ 4, 4, 22}, 	// 75 - MPLS_LABEL_2
	{ 4, 4, 22}, 	// 76 - MPLS_LABEL_2
	{ 4, 4, 22}, 	// 77 - MPLS_LABEL_2
	{ 4, 4, 22}, 	// 78 - MPLS_LABEL_2
	{ 4, 4, 22}, 	// 79 - MPLS_LABEL_2

	// 80 - 81   MACs
	{ 8, 8, 21}, 	// 80 NF9_IN_DST_MAC
	{ 8, 8, 21}, 	// 81 NF9_OUT_SRC_MAC

	// 82 - 87   not implemented
	{ 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, 

	// 88 not implemented
	{ 0, 0, 0}, 

	{ 1, 1, 0 }, 	// 89 - NF9_FORWARDING_STATUS

	// 90 - 95   not implemented
	{ 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, 

	// 96 - 103  not implemented
	{ 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, 

	// 104 - 111 not implemented
	{ 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, 

	// 112 - 119 not implemented
	{ 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, 

	// 120 - 127 not implemented
	{ 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}, { 0, 0, 0}  
};

/* this is an ugly hack but it works */
static patricia_tree_t *nf_source_tree = NULL;
static int max_num_v9_tags = 0;

static input_translation_t *
translation_table_new(exporter_t *exporter, uint16_t id)
{
	input_translation_t **table;

	table = &(exporter->input_translation_table);
	while (*table)
	{
		table = &((*table)->next);
	}

	// Allocate enough space for all potential v9 tags, which we support
	// so template refreshing may change the table size without dange of overflowing 
	*table = malloc(sizeof(input_translation_t) + max_num_v9_tags * sizeof(translation_element_t));
	(*table)->id   = id;
	(*table)->next = NULL;

	DPRINTF("got new translation table %u\n", id);

	return *table;
}

static inline input_translation_t *
translation_table_find(exporter_t *exporter, uint16_t id)
{
	input_translation_t *table;

	if (exporter->current_table && (exporter->current_table->id == id))
		return exporter->current_table;

	for (table = exporter->input_translation_table; table != NULL; table = table->next)
	{
		if (table->id == id)
		{
			exporter->current_table = table;
			return table;
		}
	}

	DPRINTF("[%u] got translation table %u (%s)\n", exporter->exporter_id, id, table == NULL ? "not found" : "found");

	exporter->current_table = table;
	return table;
}

static exporter_t *
exporter_correlate(uint32_t source_id)
{
	exporter_t *e;
	prefix_t *pfx;
	patricia_node_t *node;

	pfx = New_Prefix(AF_INET, &source_id, 32);
	node = patricia_search_exact(nf_source_tree, pfx);
	Deref_Prefix(pfx);

	if (node != NULL)
		return node->data;

	e = calloc(sizeof(*e), 1);
	e->exporter_id = source_id;
	e->version = 9;

	pfx = New_Prefix(AF_INET, &source_id, 32);
	node = patricia_lookup(nf_source_tree, pfx);
	node->data = e;
	Deref_Prefix(pfx);

	return e;
}

/*****************************************************************************************
 * Netflow integration functions for flowcache.                                          *
 *****************************************************************************************/

static flowcache_record_t *
flowcache_correlate_v1(netflow_v1rec_t *rec)
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

static flowcache_record_t *
flowcache_correlate_v7(netflow_v7rec_t *rec)
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

static void netflow_parse_v1(unsigned char *pkt, packet_info_t *info)
{
	int flow;
	netflow_v1hdr_t *hdr = (netflow_v1hdr_t *) pkt;
	netflow_v1rec_t *rec = NULL;

	hdr->flowcount = ntohs(hdr->flowcount);
	hdr->uptime = ntohl(hdr->uptime);
	hdr->unix_ts = ntohl(hdr->unix_ts);
	hdr->unix_tns = ntohl(hdr->unix_tns);

	DPRINTF("  Number of exported flows: %u\n", hdr->flowcount);
	DPRINTF("  Uptime                  : %u ms\n", hdr->uptime);
	DPRINTF("  Epoch                   : %u.%u\n", hdr->unix_ts, hdr->unix_tns);

	for (flow = 0, rec = (netflow_v1rec_t *) (pkt + sizeof(netflow_v1hdr_t));
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

		crec = flowcache_correlate_v1(rec);

		int fakebps = (rec->bytes - crec->bytes) + (add_ethernet_overhead ? 14 : 0);
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
			.ts = (struct timeval){
				.tv_sec = hdr->unix_ts,
				.tv_usec = hdr->unix_tns / 1000,
			},
		};

		/* don't inject precache flows */
		if (!crec->injected && ((rec->bytes > 16384) || (rec->packets > 10)))
		{
			crec->bytes = rec->bytes;
			crec->packets = rec->packets;
			continue;
		}

		ipstate_update(&inject);
		crec->injected = true;

		crec->bytes = rec->bytes;
		crec->packets = rec->packets;
	}
}

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

		int fakebps = (rec->bytes - crec->bytes) + (add_ethernet_overhead ? 14 : 0);
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
			.ts = (struct timeval){
				.tv_sec = hdr->unix_ts,
				.tv_usec = hdr->unix_tns / 1000,
			},
		};

		if (!crec->injected && ((rec->bytes > 16384) || (rec->packets > 10)))
		{
			crec->bytes = rec->bytes;
			crec->packets = rec->packets;
			continue;
		}

		ipstate_update(&inject);
		crec->injected = true;

		crec->bytes = rec->bytes;
		crec->packets = rec->packets;
	}
}

static void netflow_parse_v7(unsigned char *pkt, packet_info_t *info)
{
	int flow;
	netflow_v7hdr_t *hdr = (netflow_v7hdr_t *) pkt;
	netflow_v7rec_t *rec = NULL;

	hdr->flowcount = ntohs(hdr->flowcount);
	hdr->uptime = ntohl(hdr->uptime);
	hdr->unix_ts = ntohl(hdr->unix_ts);
	hdr->unix_tns = ntohl(hdr->unix_tns);
	hdr->sequence = ntohl(hdr->sequence);

	DPRINTF("  Number of exported flows: %u\n", hdr->flowcount);
	DPRINTF("  Uptime                  : %u ms\n", hdr->uptime);
	DPRINTF("  Epoch                   : %u.%u\n", hdr->unix_ts, hdr->unix_tns);
	DPRINTF("  Sequence                : %u\n", hdr->sequence);

	for (flow = 0, rec = (netflow_v7rec_t *) (pkt + sizeof(netflow_v7hdr_t));
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

		crec = flowcache_correlate_v7(rec);

		int fakebps = (rec->bytes - crec->bytes) + (add_ethernet_overhead ? 14 : 0);
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
			.ts = (struct timeval){
				.tv_sec = hdr->unix_ts,
				.tv_usec = hdr->unix_tns / 1000,
			},
		};

		if (!crec->injected && ((rec->bytes > 16384) || (rec->packets > 10)))
		{
			crec->bytes = rec->bytes;
			crec->packets = rec->packets;
			continue;
		}

		ipstate_update(&inject);
		crec->injected = true;

		crec->bytes = rec->bytes;
		crec->packets = rec->packets;
	}
}

static void netflow_parse_v9(unsigned char *pkt, packet_info_t *info)
{
	uint8_t *bufiter, *bufstart;
	unsigned int flow;
	netflow_v9hdr_t *hdr = (netflow_v9hdr_t *) pkt;
	netflow_v9flowset_t *fshdr = NULL;
	exporter_t *exp;

	hdr->flowcount = ntohs(hdr->flowcount);
	hdr->uptime = ntohl(hdr->uptime);
	hdr->unix_ts = ntohl(hdr->unix_ts);
	hdr->sequence = ntohl(hdr->sequence);
	hdr->source_id = ntohl(hdr->source_id);

	DPRINTF("  Number of exported flows: %u\n", hdr->flowcount);
	DPRINTF("  Uptime                  : %u ms\n", hdr->uptime);
	DPRINTF("  Epoch                   : %u\n", hdr->unix_ts);
	DPRINTF("  Sequence                : %u\n", hdr->sequence);
	DPRINTF("  Source ID               : %u\n", hdr->source_id);

	exp = exporter_correlate(hdr->source_id);
	DPRINTF("  Exporter object         : %p\n", exp);

	for (flow = 0, fshdr = (netflow_v9flowset_t *) (pkt + sizeof(netflow_v9hdr_t));
	     ((uint8_t *) fshdr - pkt) < info->len; flow++)
	{
		DPRINTF("  Flowset %u [%ld]:\n", flow, ((uint8_t *) fshdr - pkt));

		fshdr->flowset_id = ntohs(fshdr->flowset_id);
		fshdr->length = ntohs(fshdr->length);

		DPRINTF("    Flowset ID            : %u\n", fshdr->flowset_id);
		DPRINTF("    Length                : %u\n", fshdr->length);

		/* skip empty flowsets */
		if (fshdr->length <= 4)
			continue;

		/* per RFC3954: "FlowSet ID value of 0 is reserved for the Template FlowSet." */
		if (!fshdr->flowset_id)
		{
			bool parsedone = false;

			DPRINTF("    Flowset type          : %s\n", "TEMPLATE");

			bufiter = (uint8_t *) fshdr;
			bufiter += sizeof(netflow_v9flowset_t);
			bufstart = bufiter;

			while (!parsedone && ((bufiter - pkt) < info->len))
			{
				input_translation_t *table;
				netflow_v9tmpl_t *tmpl = (netflow_v9tmpl_t *) bufiter;

				tmpl->tmpl_id = ntohs(tmpl->tmpl_id);
				tmpl->fieldcount = ntohs(tmpl->fieldcount);

				DPRINTF("      Template ID         : %u\n", tmpl->tmpl_id);
				DPRINTF("      Field Count         : %u\n", tmpl->fieldcount);

				table = translation_table_new(exp, tmpl->tmpl_id);

				bufiter += sizeof(netflow_v9tmpl_t);

				if ((bufiter - bufstart) <= fshdr->length)
				{
					DPRINTF("Parsing done at %lu bytes\n", (bufiter - pkt));
					parsedone = true;
				}
			}
		}
		else if (fshdr->flowset_id == 1)
		{
			DPRINTF("    Flowset type          : %s\n", "OPTION");
		}
		else
		{
			input_translation_t *table;

			DPRINTF("    Flowset type          : %s\n", "DATA");

			table = translation_table_find(exp, fshdr->flowset_id);

			DPRINTF("      Translation object  : %p\n", table);
		}

		bufiter = (uint8_t *) fshdr;
		bufiter += fshdr->length;
		fshdr = (netflow_v9flowset_t *) bufiter;
	}
}

static netflow_parse_f pfunc[NETFLOW_MAX_VERSION] = {
	[NETFLOW_VERSION_1] = netflow_parse_v1,
	[NETFLOW_VERSION_5] = netflow_parse_v5,
	[NETFLOW_VERSION_7] = netflow_parse_v7,
	[NETFLOW_VERSION_9] = netflow_parse_v9,
};

static void
netflow_handle(mowgli_eventloop_t *eventloop, mowgli_eventloop_io_t *io, mowgli_eventloop_io_dir_t dir, void *userdata)
{
	mowgli_descriptor_t fd;
	unsigned int len;
	unsigned char pkt[BUFSIZ];
	unsigned int num_pkts = 0;
	netflow_common_t *cmn;
	mowgli_eventloop_pollable_t *pollable = mowgli_eventloop_io_pollable(io);
	packet_info_t info;

	if (pollable == NULL)
		return;

	fd = pollable->fd;

#if 0
	DPRINTF("reading udp/%d\n", fd);
#endif

	while (++num_pkts < 1000 && (len = recv(fd, pkt, BUFSIZ, 0)) > sizeof(*cmn))
	{
		info.len = len;
		info.ts.tv_sec = mowgli_eventloop_get_time(eventloop);

		/* parse the header ... */
		cmn = (netflow_common_t *) pkt;
		cmn->version = ntohs(cmn->version);

		DPRINTF("Netflow version %d (len %d).\n", cmn->version, len);
		if (pfunc[cmn->version] != NULL)
			pfunc[cmn->version](pkt, &info);
	}
}

static void
netflow_prepare(mowgli_eventloop_t *eventloop, mowgli_config_file_entry_t *entry)
{
	mowgli_descriptor_t sock;
	unsigned int bind_port = 9996;
	mowgli_eventloop_pollable_t *pollable;
	mowgli_config_file_entry_t *ce;

	MOWGLI_ITER_FOREACH(ce, entry)
	{
		if (!strcasecmp(ce->varname, "bind_port"))
			bind_port = atoi(ce->vardata);
	}

	sock = socket(AF_INET, SOCK_DGRAM, 0);

	struct sockaddr_in sin = { .sin_family = AF_INET, .sin_port = htons(bind_port) };
	bind(sock, (struct sockaddr *) &sin, sizeof sin);

	DPRINTF("listening on udp port %d\n", bind_port);

	pollable = mowgli_pollable_create(eventloop, sock, NULL);
	mowgli_pollable_setselect(eventloop, pollable, MOWGLI_EVENTLOOP_IO_READ, netflow_handle);
}

void
module_cons(mowgli_eventloop_t *eventloop, mowgli_config_file_entry_t *entry)
{
	mowgli_config_file_entry_t *ce;
	int i;

	nf_source_tree = New_Patricia(32);

	for (i = 0; i < 128; i++)
	{
		if (element_info[i].min)
			max_num_v9_tags++;
	}

	DPRINTF("%d recognized netflow v9 tags\n", max_num_v9_tags);

	MOWGLI_ITER_FOREACH(ce, entry)
	{
		if (!strcasecmp(ce->varname, "add-ethernet-overhead"))
			add_ethernet_overhead = true;
	}

	source_register("netflow", netflow_prepare);
}
