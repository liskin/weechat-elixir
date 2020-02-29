#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <glib.h>

#include <ei.h>
#include <weechat-plugin.h>

#include "version.h"

#define TIMEOUT_NORMAL 1000
#define LISTEN_BACKLOG 10

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(ei_x_buff, ei_x_free);

static struct t_weechat_plugin *weechat_plugin = NULL;

typedef struct client {
	int fd;
	struct t_hook *fd_hook;
	char nodename[MAXNODELEN + 1];
} client_t;

static void client_free(client_t *client);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(client_t, client_free);

static struct global {
	ei_cnode ec;
	int server_fd;
	struct t_hook *server_fd_hook;
	int publish_fd;
	GList *clients;
} global = {
	.server_fd = -1,
	.server_fd_hook = NULL,
	.publish_fd = -1,
	.clients = NULL,
};

static void safe_close_fd(int *fd) {
	if (fd && *fd >= 0) {
		ei_close_connection(*fd);
		*fd = -1;
	}
}

static void safe_unhook(struct t_hook **hook) {
	if (hook && *hook) {
		weechat_unhook(*hook);
		*hook = NULL;
	}
}

static int client_sock_cb(const void *pointer, void *data, int client_fd);

static int client_add(int fd, const char *nodename) {
	g_autoptr(client_t) client = g_new(client_t, 1);

	client->fd = fd;
	client->fd_hook = weechat_hook_fd(fd,
		1 /* flag_read */, 0 /* flag_write */, 0 /* flag_exception */,
		client_sock_cb, client, NULL);
	if (client->fd_hook == NULL) {
		weechat_printf(NULL, "erl/client_add: error (weechat_hook_fd)");
		return WEECHAT_RC_ERROR;
	}

	strncpy(client->nodename, nodename, MAXNODELEN);
	client->nodename[MAXNODELEN] = 0;

	global.clients = g_list_prepend(global.clients, g_steal_pointer(&client));

	return WEECHAT_RC_OK;
}

static void client_free(client_t *client) {
	// TODO: https://github.com/weechat/weechat/blob/feb6258910d7fe907fddeea32e57f786079d82ec/src/plugins/plugin-script.c#L1046 (use nodename)

	safe_unhook(&client->fd_hook);
	safe_close_fd(&client->fd);

	g_free(client);
}

static int client_handle_reg_send(client_t *client,
		erlang_msg *msg, ei_x_buff *x, ei_x_buff *x_reply) {
	int index = 0;

	int version;
	if (ei_decode_version(x->buff, &index, &version))
		goto error;

	if (true) { /* FIXME: debug dump */
		int tmpindex = index;
		char *term = NULL;

		if (ei_s_print_term(&term, x->buff, &tmpindex) != ERL_ERROR) {
			weechat_printf(NULL, "erl/client_handle_reg_send: %s sent %s", msg->from.node, term);
			free(term);
		}
	}

	char atom[MAXATOMLEN];
	if (ei_decode_atom(x->buff, &index, atom) == 0) {
		if (strcmp(atom, "self") == 0) {
			return ei_x_encode_tuple_header(x_reply, 2)
				|| ei_x_encode_atom(x_reply, "ok")
				|| ei_x_encode_pid(x_reply, ei_self(&global.ec));
		}
	}

error:
	return ei_x_encode_atom(x_reply, "error");
}

static int client_handle_msg(client_t *client, erlang_msg *msg, ei_x_buff *x) {
	g_auto(ei_x_buff) x_reply;

	if (ei_x_new_with_version(&x_reply))
		return WEECHAT_RC_ERROR;

	switch (msg->msgtype) {
		case ERL_REG_SEND:
			if (client_handle_reg_send(client, msg, x, &x_reply))
				return WEECHAT_RC_ERROR;
			if (ei_send_tmo(client->fd, &msg->from, x_reply.buff, x_reply.index, TIMEOUT_NORMAL) == ERL_ERROR)
				return WEECHAT_RC_ERROR;
			break;
		case ERL_LINK: /* we don't need to react to this, BEAM will handle it */
			break;
		case ERL_EXIT: /* someone linked to us and died, close connection */
			return WEECHAT_RC_ERROR;
		case ERL_EXIT2: /* someone killed us, close connection */
			return WEECHAT_RC_ERROR;
		default:
			weechat_printf(NULL, "erl/client_handle_msg: unexpected msgtype %ld", msg->msgtype);
	}

	return WEECHAT_RC_OK;
}

static int client_sock_cb(const void *pointer, void *data, int client_fd) {
	client_t *client = (client_t *) pointer;

	erlang_msg msg;
	g_auto(ei_x_buff) x;

	if (ei_x_new(&x))
		goto error;

	/* there's no buffering in ei_xreceive_msg, so we just process one message
	 * and let weechat's fd hook call us again if there's more */
	switch (ei_xreceive_msg(client_fd, &msg, &x)) {
		case ERL_TICK:
			break;
		case ERL_MSG:
			if (client_handle_msg(client, &msg, &x) != WEECHAT_RC_OK)
				goto error;
			break;
		case ERL_ERROR:
			goto error;
	}

	return WEECHAT_RC_OK;

error:
	weechat_printf(NULL, "erl/client_sock_cb: disconnecting client %s", client->nodename);
	global.clients = g_list_remove(global.clients, client);
	client_free(client);
	return WEECHAT_RC_ERROR;
}

static int server_sock_cb(const void *pointer, void *data, int server_fd) {
	int fd;
	ErlConnect conn;

	fd = ei_accept_tmo(&global.ec, server_fd, &conn, TIMEOUT_NORMAL);
	if (fd == ERL_ERROR) {
		if (erl_errno == ETIMEDOUT) {
			return WEECHAT_RC_OK;
		} else {
			weechat_printf(NULL, "erl/server_sock_cb: error (ei_accept_tmo)");
			return WEECHAT_RC_ERROR;
		}
	}

	if (client_add(fd, conn.nodename) != WEECHAT_RC_OK)
		return WEECHAT_RC_ERROR;

	weechat_printf(NULL, "erl/server_sock_cb: connected client %s", conn.nodename);
	return WEECHAT_RC_OK;
}

void server_cleanup() {
	g_list_free_full(g_steal_pointer(&global.clients), (GDestroyNotify) client_free);

	safe_close_fd(&global.publish_fd);

	safe_unhook(&global.server_fd_hook);
	safe_close_fd(&global.server_fd);
}

int server_init() {
	struct in_addr loopback_addr = { .s_addr = htonl(INADDR_LOOPBACK) };
	int port = 0;

	if (ei_init()) {
		weechat_printf(NULL, "erl/weechat_plugin_init: error (ei_init)");
		goto error;
	}

	// TODO: weechat-<username>
	if (ei_connect_xinit(
			&global.ec,
			"localhost" /* thishostname */,
			"weechat" /* thisalivename */,
			"weechat@localhost" /* thisnodename */,
			&loopback_addr,
			NULL, /* cookie, read from ~/.erlang.cookie */
			time(NULL) /* creation */
			) < 0) {
		weechat_printf(NULL, "erl/weechat_plugin_init: error (ei_connect_xinit)");
		goto error;
	}

	global.server_fd = ei_xlisten(&global.ec, &loopback_addr, &port, LISTEN_BACKLOG);
	if (global.server_fd == ERL_ERROR) {
		weechat_printf(NULL, "erl/weechat_plugin_init: error (ei_xlisten)");
		goto error;
	}

	global.server_fd_hook = weechat_hook_fd(global.server_fd,
		1 /* flag_read */, 0 /* flag_write */, 0 /* flag_exception */,
		server_sock_cb, NULL, NULL);
	if (global.server_fd_hook == NULL) {
		weechat_printf(NULL, "erl/weechat_plugin_init: error (weechat_hook_fd)");
		goto error;
	}

	global.publish_fd = ei_publish_tmo(&global.ec, port, TIMEOUT_NORMAL);
	if (global.publish_fd == ERL_ERROR) {
		weechat_printf(NULL, "erl/weechat_plugin_init: error (ei_publish_tmo)");
		goto error;
	}

	return WEECHAT_RC_OK;

error:
	server_cleanup();

	return WEECHAT_RC_ERROR;
}

#pragma GCC visibility push(default)

WEECHAT_PLUGIN_NAME("erl");
WEECHAT_PLUGIN_DESCRIPTION("Erlang C node plugin for WeeChat");
WEECHAT_PLUGIN_AUTHOR("Tomas Janousek <tomi@nomi.cz>");
WEECHAT_PLUGIN_VERSION(PLUGIN_ERLANG_NODE_VERSION);
WEECHAT_PLUGIN_LICENSE("GPL3");

int weechat_plugin_init(struct t_weechat_plugin *plugin, int argc, char *argv[])
{
	weechat_plugin = plugin;

	return server_init();
}

int weechat_plugin_end(struct t_weechat_plugin *plugin)
{
	server_cleanup();

	return WEECHAT_RC_OK;
}

#pragma GCC visibility pop
