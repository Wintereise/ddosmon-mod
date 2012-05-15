/*
 * pcap.c
 * Purpose: Initialization and management of pcap buffers.
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

#include "stdinc.h"
#include "protocols.h"
#include "packet.h"
#include "eventsource.h"
#include "ipstate.h"

#ifndef BUFSIZ
#define BUFSIZ 65535
#endif

typedef void (*dissector_func_t)(packet_info_t *info, const unsigned char *packet);

static dissector_func_t ip_dissectors[IPPROTO_MAX + 1];

static void
dissect_tcp(packet_info_t *info, const unsigned char *packet)
{
	const struct tcp_hdr *tcp;

	tcp = (struct tcp_hdr *)(packet);

	DPRINTF("    TCP (%d -> %d) checksum %x window %d flag %s\n", ntohs(tcp->sport), ntohs(tcp->dport), ntohs(tcp->chksum), ntohs(tcp->window), tcp->flags & TCP_SYN ? "S" : ".");

	info->src_prt = ntohs(tcp->sport);
	info->dst_prt = ntohs(tcp->dport);
	info->tcp_flags = tcp->flags;

	ipstate_update(info);
}

static void
dissect_udp(packet_info_t *info, const unsigned char *packet)
{
	const struct udp_hdr *udp;

	udp = (struct udp_hdr *)(packet);

	DPRINTF("    UDP (%d -> %d) checksum %x length %d\n", ntohs(udp->udp_sport), ntohs(udp->udp_dport), ntohs(udp->udp_sum), ntohs(udp->udp_len));

	info->src_prt = ntohs(udp->udp_sport);
	info->dst_prt = ntohs(udp->udp_dport);

	ipstate_update(info);
}

static void
dissect_icmp(packet_info_t *info, const unsigned char *packet)
{
	const struct icmp_hdr *icmp;

	icmp = (struct icmp_hdr *)(packet);

	DPRINTF("    ICMP checksum %x\n", ntohs(icmp->icmp_sum));

	ipstate_update(info);
}

static void
dissect_ip(packet_info_t *info, const unsigned char *packet)
{
#ifdef DEBUG
	char srcbuf[INET6_ADDRSTRLEN];
	char dstbuf[INET6_ADDRSTRLEN];
#endif
	const struct ip_hdr *ip;

	ip = (struct ip_hdr *)(packet);
	if (SIZE_IP(ip) < 20)
		return;

	info->pkt_src =	ip->ip_src;
	info->pkt_dst = ip->ip_dst;
	info->ip_type = ip->ip_p;

#ifdef DEBUG
	inet_ntop(AF_INET, &ip->ip_src, srcbuf, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip->ip_dst, dstbuf, INET6_ADDRSTRLEN);
#endif

	DPRINTF("  IP type %d (%s -> %s)\n", ip->ip_p, srcbuf, dstbuf);

	if (ip_dissectors[info->ip_type] != NULL)
		ip_dissectors[info->ip_type](info, packet + SIZE_IP(ip));
}

void
dissect_ethernet(packet_info_t *info, const unsigned char *packet)
{
	const struct ether_hdr *ether;

	ether = (struct ether_hdr *)(packet);

	DPRINTF("Ethernet type %d (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x -> %.2x:%.2x:%.2x:%.2x:%.2x:%.2x)\n",
		ether->ether_type,
		ether->ether_shost[0], 
		ether->ether_shost[1], 
		ether->ether_shost[2], 
		ether->ether_shost[3], 
		ether->ether_shost[4], 
		ether->ether_shost[5],
		ether->ether_dhost[0], 
		ether->ether_dhost[1], 
		ether->ether_dhost[2], 
		ether->ether_dhost[3], 
		ether->ether_dhost[4], 
		ether->ether_dhost[5]);

	info->ether_type = ether->ether_type;
	if (info->ether_type == 8)
		dissect_ip(info, packet + SIZE_ETHERNET(ether));
}

void
init_dissectors(void)
{
	memset(&ip_dissectors, '\0', sizeof(ip_dissectors));

	ip_dissectors[1] = &dissect_icmp;
	ip_dissectors[6] = &dissect_tcp;
	ip_dissectors[17] = &dissect_udp;
}

/******************************************************************************************************/

static pcap_t *handle;
static char *interface, *pcapfilter;

static pcap_t *
open_interface(const char *interface)
{
	pcap_t *handle_;
	char errbuf[PCAP_ERRBUF_SIZE];

	handle_ = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if (handle_ == NULL)
	{
		fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	return handle_;
}

static void
set_pcap_filter(pcap_t *handle, const char *filter, uint32_t netmask)
{
	struct bpf_program fp;

	if (pcap_compile(handle, &fp, filter, 0, netmask) == -1)
	{
		fprintf(stderr, "pcap_compile() failed: %s\n", pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "pcap_setfilter() failed: %s\n", pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
}

static int
pcap_prepare(void)
{
	handle = open_interface(interface);
	DPRINTF("opened pcap/%s as %p\n", interface, handle);

	set_pcap_filter(handle, pcapfilter, 0);
	DPRINTF("set pcap filter %s\n", pcapfilter);

	return pcap_get_selectable_fd(handle);
}

static const unsigned char *
pcap_readpkt(int fd, packet_info_t *info)
{
	struct pcap_pkthdr hdr;
	const unsigned char *pkt;

	DPRINTF("reading pcap/%p\n", handle);

	pkt = pcap_next(handle, &hdr);
	if (pkt != NULL)
	{
		info->packets = 1;
		info->len = hdr.len;
		info->ts = hdr.ts;
		info->new_flow = 0;

		dissect_ethernet(info, pkt);
	}

	return NULL;
}

static void
pcap_shutdown(int fd)
{
	pcap_close(handle);
}

static eventsource_t pcap_eventsource = {
	pcap_prepare,
	pcap_readpkt,
	pcap_shutdown
};

void
module_cons(mowgli_eventloop_t *eventloop, mowgli_config_file_entry_t *entry)
{
	mowgli_config_file_entry_t *ce;

	init_dissectors();

	MOWGLI_ITER_FOREACH(ce, entry)
	{
		if (!strcasecmp(ce->varname, "interface"))
			interface = strdup(ce->vardata);

		if (!strcasecmp(ce->varname, "pcap_string"))
			pcapfilter = strdup(ce->vardata);
	}

	ev = &pcap_eventsource;
}
