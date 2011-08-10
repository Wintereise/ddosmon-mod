/*
 * trigger.c: Code for sending to the router.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>

#include "stdinc.h"
#include "confparse.h"
#include "action.h"

#include <libssh2.h>

static char *router_ssh_user, *router_ssh_pass, *router_host, *router_enable_pass;
static int router_port, nullroute_tag = 666;
static char *router_pubkey = NULL, *router_privkey = NULL;

static int
ssh_channel_writef(LIBSSH2_CHANNEL *channel, const char *fmt, ...)
{
	char *line;
	size_t len;
	va_list va;
	int ret;

	va_start(va, fmt);
	len = vasprintf(&line, fmt, va);
	va_end(va);

	DPRINTF("writing [\n%s] = ", line);
	ret = libssh2_channel_write(channel, line, len);
	DPRINTF("%d\n", ret);

	free(line);

	return len;
}

static int
open_socket(const char *host, int port)
{
	struct sockaddr_in sa;
	struct in_addr ia;
	int sock;

	inet_pton(AF_INET, host, &ia);

	if (!(sock = socket(AF_INET, SOCK_STREAM, 0)))
		return -1;

	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = ia.s_addr;

	if (connect(sock, (struct sockaddr *) &sa, sizeof(sa)) == -1)
	{
		close(sock);
		return -1;
	}

	return sock;
}

static void
trigger_ban(packet_info_t *info, iprecord_t *irec)
{
	int fd;
	char ipbuf[INET6_ADDRSTRLEN];
	LIBSSH2_SESSION *session;
	LIBSSH2_CHANNEL *channel;
	int is_internal = 0;

	inet_ntop(AF_INET, &info->pkt_dst, ipbuf, INET6_ADDRSTRLEN);

	fd = open_socket(router_host, router_port);

	session = libssh2_session_init();
	if (libssh2_session_startup(session, fd))
		goto shutdown;

	if (router_pubkey != NULL && router_privkey != NULL)
	{
		if (libssh2_userauth_publickey_fromfile(session, router_ssh_user, router_pubkey,
							router_privkey, router_ssh_pass))
		{
			if (libssh2_userauth_password(session, router_ssh_user, router_ssh_pass))
				goto shutdown;
		}
	}
	else if (libssh2_userauth_password(session, router_ssh_user, router_ssh_pass))
		goto shutdown;

	if (!(channel = libssh2_channel_open_session(session)))
		goto shutdown;

	if (libssh2_channel_request_pty(channel, "vanilla"))
		goto no_shell;

	if (libssh2_channel_shell(channel))
		goto no_shell;

	ssh_channel_writef(channel, "enable\n");
	ssh_channel_writef(channel, "%s\n", router_enable_pass);
	ssh_channel_writef(channel, "conf t\n");
	ssh_channel_writef(channel, "ip route %s 255.255.255.255 Null0 tag %d\n", ipbuf, nullroute_tag);
	ssh_channel_writef(channel, "exit\n");
	ssh_channel_writef(channel, "exit\n");
	libssh2_channel_send_eof(channel);

no_shell:
	libssh2_channel_free(channel);

shutdown:
	libssh2_session_disconnect(session, "closing session");
	libssh2_session_free(session);
	close(fd);
}

static void
trigger_unban(packet_info_t *info, iprecord_t *irec)
{
	int fd;
	char ipbuf[INET6_ADDRSTRLEN];
	LIBSSH2_SESSION *session;
	LIBSSH2_CHANNEL *channel;
	int is_internal = 0;

	inet_ntop(AF_INET, &info->pkt_dst, ipbuf, INET6_ADDRSTRLEN);

	fd = open_socket(router_host, router_port);

	session = libssh2_session_init();
	if (libssh2_session_startup(session, fd))
		goto shutdown;

	if (router_pubkey != NULL && router_privkey != NULL)
	{
		if (libssh2_userauth_publickey_fromfile(session, router_ssh_user, router_pubkey,
							router_privkey, router_ssh_pass))
		{
			if (libssh2_userauth_password(session, router_ssh_user, router_ssh_pass))
				goto shutdown;
		}
	}
	else if (libssh2_userauth_password(session, router_ssh_user, router_ssh_pass))
		goto shutdown;

	if (!(channel = libssh2_channel_open_session(session)))
		goto shutdown;

	if (libssh2_channel_request_pty(channel, "vanilla"))
		goto no_shell;

	if (libssh2_channel_shell(channel))
		goto no_shell;

	ssh_channel_writef(channel, "enable\n");
	ssh_channel_writef(channel, "%s\n", router_enable_pass);
	ssh_channel_writef(channel, "conf t\n");
	ssh_channel_writef(channel, "no ip route %s 255.255.255.255 Null0 tag %d\n", ipbuf, nullroute_tag);
	ssh_channel_writef(channel, "exit\n");
	ssh_channel_writef(channel, "exit\n");
	libssh2_channel_send_eof(channel);

no_shell:
	libssh2_channel_free(channel);

shutdown:
	libssh2_session_disconnect(session, "closing session");
	libssh2_session_free(session);
	close(fd);
}

static void
trigger_nullroute(actiontype_t act, packet_info_t *packet, iprecord_t *irec, void *data)
{
	if (act == ACTION_BAN)
	{
		trigger_ban(packet, irec);
		return;
	}

	trigger_unban(packet, irec);
}

void
module_cons(config_entry_t *entry)
{
	config_entry_t *ce;

	for (ce = entry; ce != NULL; ce = ce->ce_next)
	{
		if (!strcasecmp(ce->ce_varname, "ssh_host"))
			router_host = strdup(ce->ce_vardata);
		else if (!strcasecmp(ce->ce_varname, "ssh_user"))
			router_ssh_user = strdup(ce->ce_vardata);
		else if (!strcasecmp(ce->ce_varname, "ssh_pass"))
			router_ssh_pass = strdup(ce->ce_vardata);
		else if (!strcasecmp(ce->ce_varname, "ssh_pubkey"))
			router_pubkey = strdup(ce->ce_vardata);
		else if (!strcasecmp(ce->ce_varname, "ssh_privkey"))
			router_privkey = strdup(ce->ce_vardata);
		else if (!strcasecmp(ce->ce_varname, "enable_password"))
			router_enable_pass = strdup(ce->ce_vardata);
		else if (!strcasecmp(ce->ce_varname, "ssh_port"))
			router_port = atoi(ce->ce_vardata);
		else if (!strcasecmp(ce->ce_varname, "nullroute_tag"))
			nullroute_tag = atoi(ce->ce_vardata);
	}

	action_register("cisco-nullroute", trigger_nullroute, NULL);
}
