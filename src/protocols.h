/*
 * protocols.h
 * Purpose: Definition of protocols in structure format.
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

#ifndef __PROTOCOLS_H__
#define __PROTOCOLS_H__

#include <netinet/in.h>			/* struct in_addr */

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct ether_hdr {
	unsigned char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	unsigned char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	unsigned short ether_type; /* IP? ARP? RARP? etc */
};

#define SIZE_ETHERNET(enet)		(14)

/* IP header */
struct ip_hdr {
	unsigned char ip_vhl;		/* version << 4 | header length >> 2 */
	unsigned char ip_tos;		/* type of service */
	unsigned short ip_len;		/* total length */
	unsigned short ip_id;		/* identification */
	unsigned short ip_off;		/* fragment offset field */
#define IP_RF 0x8000			/* reserved fragment flag */
#define IP_DF 0x4000			/* dont fragment flag */
#define IP_MF 0x2000			/* more fragments flag */
#define IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	unsigned char ip_ttl;		/* time to live */
	unsigned char ip_p;		/* protocol */
	unsigned short ip_sum;		/* checksum */
	struct in_addr ip_src, ip_dst; 	/* source and dest address */
};

#define IP_HL(ip)			(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)			(((ip)->ip_vhl) >> 4)
#define SIZE_IP(ip)			(IP_HL(ip) * 4)
#define IPPROTO_MAX			(255)

struct udp_hdr {
	unsigned short udp_sport;	/* source port */
	unsigned short udp_dport;	/* destination port */
	unsigned short udp_len;		/* packet length */
	unsigned short udp_sum;		/* checksum */
};

#define SIZE_UDP(udp)			(8)

struct icmp_hdr {
	unsigned char icmp_type;	/* source port */
	unsigned char icmp_code;	/* destination port */
	unsigned short icmp_sum;		/* packet length */
	union {
		struct {
			unsigned short id;
			unsigned short seq;
		} echo;
		struct {
			unsigned short unused;
			unsigned short mtu;
		} frag;
		unsigned int gateway;
	};
};

#define SIZE_TCP			(24)

struct tcp_hdr {
	unsigned short sport;
	unsigned short dport;
	unsigned int seq;
	unsigned int ack_seq;
	unsigned char offset;
	unsigned char flags;
	unsigned short window;
	unsigned short chksum;
	unsigned short urgency;
};

#define TCP_FIN		0x1
#define TCP_SYN		0x2
#define TCP_RST		0x4
#define TCP_PSH		0x8
#define TCP_ACK		0x10
#define	TCP_URG		0x20

#endif
