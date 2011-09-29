/*
 * dissectors.c: Parsing of ethernet and IP packets
 */

#include "stdinc.h"
#include "protocols.h"
#include "packet.h"
#include "ipstate.h"

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
