#include "protocols.h"
#include "packet.h"

#ifndef __IPSTATE_H__
#define __IPSTATE_H__

typedef struct iprecord_ iprecord_t;
typedef struct flowdata_ flowdata_t;

struct flowdata_ {
        time_t first;
        time_t last;
        unsigned long bytes;
        unsigned long flow;
        unsigned long packets;
        unsigned long pps;
	unsigned int count;
};

struct iprecord_ {
        uint32_t addr;
	flowdata_t flows[IPPROTO_MAX + 1];
};

void ipstate_clear(void);
void ipstate_update(packet_info_t *packet);
void init_ipstate(void);

#endif
