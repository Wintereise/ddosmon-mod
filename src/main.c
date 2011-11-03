/*
 * main.c: main() (global init + eventloop)
 */

#include <stdint.h>
#include <stdlib.h>
#include <signal.h>

#include "autoconf.h"
#include "stdinc.h"
#include "protocols.h"
#include "packet.h"
#include "eventsource.h"
#include "ipstate.h"
#include "hook.h"

#ifdef HAVE_GETRLIMIT
# include <sys/time.h>
# include <sys/resource.h>
#endif

extern void conf_process(void);

eventsource_t *ev = NULL;
hook_t *hook_list[MAX_HOOKS];

#ifdef DEBUG
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

/* avoid calling unnecessary time-related syscalls */
static time_t cachetime;

time_t
get_time(void)
{
	return cachetime;
}

int
main(int argc, const char *argv[])
{
	static char *build_watermark = WATERMARK;
#ifdef HAVE_GETRLIMIT
	struct rlimit rlim;
#endif

	/* set up cachetime */
	cachetime = time(NULL);

#ifdef HAVE_GETRLIMIT
	if (!getrlimit(RLIMIT_CORE, &rlim))
	{
		rlim.rlim_cur = rlim.rlim_max;
		setrlimit(RLIMIT_CORE, &rlim);
	}
#endif

	signal(SIGCHLD, SIG_IGN);

	daemonize(build_watermark);

	init_ipstate();
	init_dissectors();

	conf_process();
	if (ev == NULL)
		return EXIT_FAILURE;

	ev->prepare();

	for (;;)
	{
		const unsigned char *pkt;
		packet_info_t info;

		pkt = ev->read(&info);
		if (pkt != NULL)
			dissect_ethernet(&info, pkt);

		cachetime = time(NULL);
		HOOK_CALL(HOOK_TIMER_TICK, cachetime);
	}

	ev->shutdown();

	return EXIT_SUCCESS;
}
