/*
 * pcap.c: Initialization and management of pcap buffers.
 */

#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>

#include "stdinc.h"
#include "protocols.h"
#include "packet.h"
#include "eventsource.h"
#include "confparse.h"

#ifndef BUFSIZ
#define BUFSIZ 65535
#endif

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

static void
pcap_prepare(void)
{
	handle = open_interface(interface);
	DPRINTF("opened pcap/%s as %p\n", interface, handle);

	set_pcap_filter(handle, pcapfilter, 0);
	DPRINTF("set pcap filter %s\n", pcapfilter);
}

static const unsigned char *
pcap_readpkt(packet_info_t *info)
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
	}

	return pkt;
}

static void
pcap_shutdown(void)
{
	pcap_close(handle);
}

static eventsource_t pcap_eventsource = {
	pcap_prepare,
	pcap_readpkt,
	pcap_shutdown
};

void
module_cons(config_entry_t *entry)
{
	config_entry_t *ce;

	for (ce = entry; ce != NULL; ce = ce->ce_next)
	{
		if (!strcasecmp(ce->ce_varname, "interface"))
			interface = strdup(ce->ce_vardata);

		if (!strcasecmp(ce->ce_varname, "pcap_string"))
			pcapfilter = strdup(ce->ce_vardata);
	}

	ev = &pcap_eventsource;
}
