/*
 * eventsource.h: Management of event sources.
 */

#ifndef __EVENTSOURCE_H
#define __EVENTSOURCE_H

typedef struct {
	void (*prepare)(void);
	const unsigned char *(*read)(packet_info_t *info);
	void (*shutdown)(void);
} eventsource_t;

extern eventsource_t *ev;

#endif
