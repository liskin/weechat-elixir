#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <ei.h>
#include <weechat-plugin.h>

#include "version.h"

#define TIMEOUT_NORMAL 1000
#define LISTEN_BACKLOG 10

static struct t_weechat_plugin *weechat_plugin = NULL;

struct client {
	struct client *next;
	int fd;
	struct t_hook *fd_hook;
	char nodename[MAXNODELEN + 1];
};

static struct global {
	ei_cnode ec;
	int server_fd;
	struct t_hook *server_fd_hook;
	int publish_fd;
	struct client *clients;
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

static struct client *client_add(int fd, const char *nodename) {
	struct client *clients_head = NULL;

	clients_head = malloc(sizeof(*clients_head));
	if (clients_head == NULL)
		goto error;

	clients_head->fd = fd;
	clients_head->fd_hook = weechat_hook_fd(fd,
		1 /* flag_read */, 0 /* flag_write */, 0 /* flag_exception */,
		client_sock_cb, clients_head, NULL);
	if (clients_head->fd_hook == NULL) {
		weechat_printf(NULL, "erl/client_add: error (weechat_hook_fd)");
		goto error;
	}

	strncpy(clients_head->nodename, nodename, MAXNODELEN);
	clients_head->nodename[MAXNODELEN] = 0;

	clients_head->next = global.clients;
	global.clients = clients_head;

	return clients_head;

error:
	safe_unhook(clients_head ? &clients_head->fd_hook : NULL);
	safe_close_fd(&fd);
	return NULL;
}

static void client_remove(struct client **clients_head) {
	struct client *tmp = *clients_head;

	// TODO: https://github.com/weechat/weechat/blob/feb6258910d7fe907fddeea32e57f786079d82ec/src/plugins/plugin-script.c#L1046 (use nodename)
	safe_unhook(&tmp->fd_hook);
	safe_close_fd(&tmp->fd);

	*clients_head = tmp->next;
	free(tmp);
}

static struct client **client_find(int fd) {
	struct client **clients_head = &global.clients;

	while (*clients_head) {
		if ((*clients_head)->fd == fd)
			return clients_head;

		clients_head = &(*clients_head)->next;
	}

	return NULL;
}

static int client_handle_reg_send(struct client *client,
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

static int client_handle_msg(struct client *client, erlang_msg *msg, ei_x_buff *x) {
	ei_x_buff x_reply;

	if (ei_x_new_with_version(&x_reply))
		goto error;

	switch (msg->msgtype) {
		case ERL_REG_SEND:
			if (client_handle_reg_send(client, msg, x, &x_reply))
				goto error;
			if (ei_send_tmo(client->fd, &msg->from, x_reply.buff, x_reply.index, TIMEOUT_NORMAL) == ERL_ERROR)
				goto error;
			break;
		case ERL_LINK: /* we don't need to react to this, BEAM will handle it */
			break;
		case ERL_EXIT: /* someone linked to us and died, close connection */
			goto error;
		case ERL_EXIT2: /* someone killed us, close connection */
			goto error;
		default:
			weechat_printf(NULL, "erl/client_handle_msg: unexpected msgtype %ld", msg->msgtype);
	}

	ei_x_free(&x_reply);
	return 0;

error:
	ei_x_free(&x_reply);
	return ERL_ERROR;
}

static int client_sock_cb(const void *pointer, void *data, int client_fd) {
	struct client *client = (struct client *) pointer;

	erlang_msg msg;
	ei_x_buff x;

	if (ei_x_new(&x))
		goto error;

	/* there's no buffering in ei_xreceive_msg, so we just process one message
	 * and let weechat's fd hook call us again if there's more */
	switch (ei_xreceive_msg(client_fd, &msg, &x)) {
		case ERL_TICK:
			break;
		case ERL_MSG:
			if (client_handle_msg(client, &msg, &x) == 0)
				break;
		case ERL_ERROR:
			goto error;
	}

	ei_x_free(&x);
	return WEECHAT_RC_OK;

error:
	weechat_printf(NULL, "erl/client_sock_cb: disconnecting client %s", client->nodename);
	ei_x_free(&x);
	client_remove(client_find(client_fd));
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

	if (client_add(fd, conn.nodename) == NULL)
		return WEECHAT_RC_ERROR;

	weechat_printf(NULL, "erl/server_sock_cb: connected client %s", conn.nodename);
	return WEECHAT_RC_OK;
}

#pragma GCC visibility push(default)

WEECHAT_PLUGIN_NAME("erl");
WEECHAT_PLUGIN_DESCRIPTION("Erlang C node plugin for WeeChat");
WEECHAT_PLUGIN_AUTHOR("Tomas Janousek <tomi@nomi.cz>");
WEECHAT_PLUGIN_VERSION(PLUGIN_ERLANG_NODE_VERSION);
WEECHAT_PLUGIN_LICENSE("GPL3");

int weechat_plugin_init(struct t_weechat_plugin *plugin, int argc, char *argv[])
{
	struct in_addr loopback_addr = { .s_addr = htonl(INADDR_LOOPBACK) };
	int port = 0;

	weechat_plugin = plugin;

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
	safe_close_fd(&global.publish_fd);
	safe_close_fd(&global.server_fd);

	return WEECHAT_RC_ERROR;
}

int weechat_plugin_end(struct t_weechat_plugin *plugin)
{
	while (global.clients)
		client_remove(&global.clients);

	safe_close_fd(&global.publish_fd);

	safe_unhook(&global.server_fd_hook);
	safe_close_fd(&global.server_fd);

	return WEECHAT_RC_OK;
}

#pragma GCC visibility pop
