/*
 * packet.h: Structure for describing packet data.
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
