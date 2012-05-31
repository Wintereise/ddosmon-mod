/*
 * main.c
 * Purpose: main() (global init + eventloop)
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

#include <stdint.h>
#include <stdlib.h>
#include <signal.h>

#include "autoconf.h"
#include "stdinc.h"
#include "protocols.h"
#include "packet.h"
#include "ipstate.h"
#include "hook.h"
#include "flowcache.h"

#ifdef HAVE_GETRLIMIT
# include <sys/time.h>
# include <sys/resource.h>
#endif

hook_t *hook_list[MAX_HOOKS];
mowgli_eventloop_t *eventloop;

#ifdef DEBUG
#define NEVER_FORK
#endif

#ifdef NEVER_FORK
#undef HAVE_FORK
#endif

static void
daemonize(const char *b_wm)
{
#ifdef HAVE_FORK
	int pid;

	if ((pid = fork()) < 0)
	{
		fprintf(stderr, "ddosmon: can't fork into background: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	else if (pid != 0)
	{
		printf("ddosmon: build identifier %s\n", b_wm);
		printf("ddosmon: pid %d\n", pid);
		printf("ddosmon: running in background mode from %s\n", PREFIX);
		exit(EXIT_SUCCESS);
	}

	if (setsid() < 0)
	{
		fprintf(stderr, "ddosmon: unable to create new session\n");
		exit(EXIT_FAILURE);
	}

	dup2(0, 1);
	dup2(0, 2);
#else
	printf("ddosmon: build identifier %s [DEBUG]\n", b_wm);
#endif
}

int
main(int argc, const char *argv[])
{
	int fd;
	static char *build_watermark = WATERMARK;
#ifdef HAVE_GETRLIMIT
	struct rlimit rlim;
#endif

#ifdef HAVE_GETRLIMIT
	if (!getrlimit(RLIMIT_CORE, &rlim))
	{
		rlim.rlim_cur = rlim.rlim_max;
		setrlimit(RLIMIT_CORE, &rlim);
	}
#endif

	signal(SIGCHLD, SIG_IGN);

	daemonize(build_watermark);

	eventloop = mowgli_eventloop_create();

	conf_process(eventloop);
	ipstate_setup(eventloop);
	flowcache_setup(eventloop);

	/* everything is set up, lets run the app */
	mowgli_eventloop_run(eventloop);

	return EXIT_SUCCESS;
}
