/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <memory.h>
#include <glib.h>
#include <errno.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/handlers.h>
#include <linux/cifsd_server.h>

#include <ipc.h>
#include <cifsdtools.h>
#include <worker_pool.h>

static struct nl_sock *sk;

static struct nla_policy cifsd_nl_policy[CIFSD_EVENT_MAX] = {
	[CIFSD_EVENT_STARTING_UP] = {
		.minlen = sizeof(struct cifsd_startup_shutdown),
	},

	[CIFSD_EVENT_SHUTTING_DOWN] = {
		.minlen = sizeof(struct cifsd_startup_shutdown),
	},

	[CIFSD_EVENT_LOGIN_REQUEST] = {
		.minlen = sizeof(struct cifsd_startup_shutdown),
	},

	[CIFSD_EVENT_LOGIN_RESPONSE] = {
		.minlen = sizeof(struct cifsd_startup_shutdown),
	},

	[CIFSD_EVENT_TREE_CONNECT_REQUEST] = {
		.minlen = sizeof(struct cifsd_startup_shutdown),
	},

	[CIFSD_EVENT_TREE_CONNECT_RESPONSE] = {
		.minlen = sizeof(struct cifsd_startup_shutdown),
	},

	[CIFSD_EVENT_TREE_DISCONNECT_REQUEST] = {
		.minlen = sizeof(struct cifsd_startup_shutdown),
	},

	[CIFSD_EVENT_LOGOUT_REQUEST] = {
		.minlen = sizeof(struct cifsd_startup_shutdown),
	},
};

static int nlink_msg_cb(struct nl_msg *nlmsg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_data(nlmsg_hdr(nlmsg));
        struct nlattr *attrs[CIFSD_EVENT_MAX + 1];
	size_t sz;
	struct cifsd_ipc_msg *event;

        if (nlmsg_parse(nlh, 0, attrs, CIFSD_EVENT_MAX, cifsd_nl_policy) < 0) {
		pr_err("Unalbe to parse IPC message.\n");
		return NL_SKIP;
	}

	if (!attrs[nlh->nlmsg_type]) {
		pr_err("Cannot find type %d\n", nlh->nlmsg_type);
		return NL_SKIP;
	}

	sz = nla_len(attrs[nlh->nlmsg_type]);
	event = ipc_msg_alloc(sz);
	if (!event)
		return NL_SKIP;

	event->type = nlh->nlmsg_type;
	event->sz = sz;

	memcpy(CIFSD_IPC_MSG_PAYLOAD(event),
	       nla_data(attrs[nlh->nlmsg_type]),
	       sz);
	wp_ipc_msg_push(event);
	return NL_SKIP;
}

struct cifsd_ipc_msg *ipc_msg_alloc(size_t sz)
{
	struct cifsd_ipc_msg *msg;
	size_t msg_sz = sz + sizeof(struct cifsd_ipc_msg) - sizeof(void *);

	msg = malloc(msg_sz);
	if (msg) {
		memset(msg, 0x00, msg_sz);
		msg->destination = -1;
		msg->sz = sz;
	}
	return msg;
}

void ipc_msg_free(struct cifsd_ipc_msg *msg)
{
	free(msg);
}

int ipc_msg_send(struct cifsd_ipc_msg *msg)
{
	struct nl_msg *nlmsg;
	struct nlmsghdr *hdr;
	int ret = -EINVAL;

	nlmsg = nlmsg_alloc();
	if (!nlmsg) {
		ret = -ENOMEM;
		goto out_error;
	}

	hdr = nlmsg_put(nlmsg, getpid(), 0, msg->type, 0, 0);
	if (!hdr)
		goto out_error;

	/* Use msg->type as attribute TYPE */
	ret = nla_put(nlmsg, msg->type, msg->sz, CIFSD_IPC_MSG_PAYLOAD(msg));
	if (ret)
		goto out_error;

	ret = nl_send_auto(sk, nlmsg);
	if (ret > 0)
		ret = 0;

out_error:
	if (nlmsg)
		nlmsg_free(nlmsg);
	return ret;
}

static int ipc_cifsd_starting_up(void)
{
	struct cifsd_startup_shutdown *ev;
	struct cifsd_ipc_msg *msg = ipc_msg_alloc(sizeof(*ev));
	int ret;

	if (!msg)
		return -ENOMEM;

	ev = CIFSD_IPC_MSG_PAYLOAD(msg);
	msg->destination = CIFSD_IPC_DESTINATION_KERNEL;
	msg->type = CIFSD_EVENT_STARTING_UP;

	ev->pid = 0;
	strncpy(ev->version, CIFSD_VERSION, sizeof(ev->version));

	ret = ipc_msg_send(msg);

	ipc_msg_free(msg);
	return ret;
}

static int ipc_cifsd_shutting_down(void)
{
	struct cifsd_startup_shutdown *ev;
	struct cifsd_ipc_msg *msg = ipc_msg_alloc(sizeof(*ev));
	int ret;

	if (!msg)
		return -ENOMEM;

	ev = CIFSD_IPC_MSG_PAYLOAD(msg);
	msg->destination = CIFSD_IPC_DESTINATION_KERNEL;
	msg->type = CIFSD_EVENT_SHUTTING_DOWN;

	ev->pid = 0;
	strncpy(ev->version, CIFSD_VERSION, sizeof(ev->version));

	ret = ipc_msg_send(msg);

	ipc_msg_free(msg);
	return ret;
}

int ipc_receive_loop(void)
{
	if (ipc_cifsd_starting_up())
		return -EINVAL;

	cifsd_health_status = CIFSD_HEALTH_RUNNING;
	while (cifsd_health_status == CIFSD_HEALTH_RUNNING) {
		if (nl_recvmsgs_default(sk) < 0) {
			pr_err("Recieve error\n");
			break;
		}
	}
	return -EINVAL;
}

void ipc_destroy(void)
{
	if (cifsd_health_status == CIFSD_HEALTH_RUNNING)
		ipc_cifsd_shutting_down();

	nl_socket_free(sk);
	nl_cb_put(cb);
	sk = NULL;
	cb = NULL;
}

int ipc_init(void)
{
	sk = nl_socket_alloc();
	if (!sk)
		goto out_error;

	if (nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM,
				nlink_msg_cb, NULL))
		goto out_error;

	nl_socket_enable_msg_peek(sk);
	nl_socket_disable_seq_check(sk);

	nl_socket_set_local_port(sk, getpid());
	nl_socket_set_peer_port(sk, 0);
	nl_socket_set_peer_groups(sk, 0);
	nl_socket_enable_auto_ack(sk);

	if (nl_connect(sk, CIFSD_TOOLS_NETLINK))
		goto out_error;

	cifsd_health_status = CIFSD_HEALTH_RUNNING;
	return 0;

out_error:
	ipc_destroy();
	return -EINVAL;
}
