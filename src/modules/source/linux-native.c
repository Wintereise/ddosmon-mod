/*
 * linux-native.c
 * Purpose: edge-triggered native packet sniffer for linux
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

#ifdef __linux__

#include <stdint.h>
#include <stdlib.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>

#include "stdinc.h"
#include "protocols.h"
#include "packet.h"
#include "ipstate.h"
#include "flowcache.h"

#ifndef BUFSIZ
#define BUFSIZ 65535
#endif

/**********************************************************************************
 * Flowcache integration.                                                         *
 **********************************************************************************/
static flowcache_record_t *
pcap_correlate_flow(packet_info_t *info)
{
	flowcache_src_host_t *src;
	flowcache_dst_host_t *dst;
	flowcache_record_t *record;
	uint8_t hashv = FLOW_HASH(info->src_prt);

	dst = flowcache_dst_host_lookup(&info->pkt_dst);
	src = flowcache_src_host_lookup(dst, &info->pkt_src);

	record = flowcache_record_lookup(src, info->src_prt, info->dst_prt);
	if (record != NULL)
	{
		DPRINTF("found cached flow for %p/hashv:%d\n", info, hashv);
		return record;
	}

	record = flowcache_record_insert(dst, src, info->src_prt, info->dst_prt, info->ip_type);

	return record;
}

static void
pcap_inject_flow(packet_info_t *info)
{
	flowcache_record_t *record;

	record = pcap_correlate_flow(info);
	record->bytes += info->len;
	record->packets += info->packets;

	info->new_flow = !record->injected;

	ipstate_update(info);

	record->injected = true;
}

/**********************************************************************************
 * Protocol dissectors.                                                           *
 **********************************************************************************/
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

	pcap_inject_flow(info);
}

static void
dissect_udp(packet_info_t *info, const unsigned char *packet)
{
	const struct udp_hdr *udp;

	udp = (struct udp_hdr *)(packet);

	DPRINTF("    UDP (%d -> %d) checksum %x length %d\n", ntohs(udp->udp_sport), ntohs(udp->udp_dport), ntohs(udp->udp_sum), ntohs(udp->udp_len));

	info->src_prt = ntohs(udp->udp_sport);
	info->dst_prt = ntohs(udp->udp_dport);

	pcap_inject_flow(info);
}

static void
dissect_icmp(packet_info_t *info, const unsigned char *packet)
{
	const struct icmp_hdr *icmp;

	icmp = (struct icmp_hdr *)(packet);

	DPRINTF("    ICMP checksum %x\n", ntohs(icmp->icmp_sum));

	pcap_inject_flow(info);
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
	else
		pcap_inject_flow(info);
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

/**********************************************************************************
 * netlink glue                                                                   *
 **********************************************************************************/
static void
linux_handle(mowgli_eventloop_t *eventloop, mowgli_eventloop_io_t *io, mowgli_eventloop_io_dir_t dir, void *userdata)
{
	mowgli_eventloop_pollable_t *pollable = mowgli_eventloop_io_pollable(io);
	unsigned char buffer[BUFSIZ];
	size_t len;

	while ((len = recvfrom(pollable->fd, buffer, BUFSIZ, 0, NULL, NULL)) >= 14)
	{
		packet_info_t info;

		info.packets = 1;

		info.len = len;
		info.ts.tv_sec = mowgli_eventloop_get_time(eventloop);
		info.ts.tv_usec = 0;

		info.new_flow = 0;

		dissect_ethernet(&info, buffer);
	}
}

static int
linux_prepare(mowgli_eventloop_t *eventloop, mowgli_config_file_entry_t *entry)
{
	mowgli_eventloop_pollable_t *pollable;
	mowgli_config_file_entry_t *ce;
	char *interface = NULL;
	int fd;
	int ifindex = 0;
	bool promisc;

	MOWGLI_ITER_FOREACH(ce, entry)
	{
		if (!strcasecmp(ce->varname, "interface"))
			interface = strdup(ce->vardata);
		if (!strcasecmp(ce->varname, "promisc"))
			promisc = true;
	}

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (fd < 0)
		return;

	if (interface)
	{
		struct sockaddr_ll sll;
		struct ifreq ethreq = {};

		mowgli_strlcpy(ethreq.ifr_name, interface, IFNAMSIZ);
		ioctl(fd, SIOCGIFINDEX, &ethreq);

		DPRINTF("ifindex for %s: %d\n", interface, ethreq.ifr_ifindex);

		ifindex = ethreq.ifr_ifindex;

		sll.sll_family = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_IP);
		sll.sll_ifindex = ifindex;

		if (bind(fd, (struct sockaddr *) &sll, sizeof sll) < 0)
		{
			DPRINTF("unable to bind(2) to interface '%s' (index %d): %s\n", interface, ifindex, strerror(errno));
			goto out;
		}

		DPRINTF("bound to interface '%s'\n", interface);
	}

	if (promisc)
	{
		struct packet_mreq mr;

		mr.mr_ifindex = ifindex;
		mr.mr_type = PACKET_MR_PROMISC;

		if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof mr) < 0)
		{
			DPRINTF("unable to add packet membership for fd=%d\n", fd);
			goto out;
		}

		DPRINTF("enabled promisc mode for fd=%d\n", fd);
	}

out:
	DPRINTF("opened raw packet socket as fd=%d\n", fd);

	pollable = mowgli_pollable_create(eventloop, fd, NULL);
	mowgli_pollable_setselect(eventloop, pollable, MOWGLI_EVENTLOOP_IO_READ, linux_handle);
}

void
module_cons(mowgli_eventloop_t *eventloop, mowgli_config_file_entry_t *entry)
{
	mowgli_config_file_entry_t *ce;

	init_dissectors();

	source_register("linux", linux_prepare);
}

#endif
