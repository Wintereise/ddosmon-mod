/*
 * eventsource.h: Management of event sources.
 */

#ifndef __EVENTSOURCE_H
#define __EVENTSOURCE_H

typedef struct {
	int (*prepare)(void);
	const unsigned char *(*read)(int fd, packet_info_t *info);
	void (*shutdown)(int fd);
} eventsource_t;

extern eventsource_t *ev;

#endif
