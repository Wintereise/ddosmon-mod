/*
 * packet.h
 * Purpose: Structure for describing packet data.
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

#ifndef __PACKET_H__
#define __PACKET_H__

typedef struct {
	struct in_addr pkt_src;
	struct in_addr pkt_dst;
	unsigned short src_prt;
	unsigned short dst_prt;
	unsigned short ether_type;
	unsigned char ip_type;
	size_t len;
	struct timeval ts;
	unsigned int packets;
	unsigned char tcp_flags;
	unsigned char new_flow;
} packet_info_t;

void dissect_ethernet(packet_info_t *info, const unsigned char *packet);
void init_dissectors(void);

#endif
