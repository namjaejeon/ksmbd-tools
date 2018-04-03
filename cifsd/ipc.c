/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@sourceforge.net
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
static struct nl_cb *cb;

static int nlink_msg_cb(struct nl_msg *nlmsg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_data(nlmsg_hdr(nlmsg));
	size_t sz = nlmsg_datalen(nlh);
	struct ipc_msg *event = ipc_msg_alloc(sz);

	if (!event)
		return NL_SKIP;

	pr_err(">>> GOT MSG\n");

	event->type = nlh->nlmsg_type;
	event->sz = sz;

	memcpy(IPC_MSG_PAYLOAD(event), nlmsg_data(nlmsg_hdr(nlmsg)), sz);
	wp_ipc_msg_push(event);
	return NL_SKIP;
}

struct ipc_msg *ipc_msg_alloc(size_t sz)
{
	struct ipc_msg *msg;
	size_t msg_sz = sz + sizeof(struct ipc_msg) - sizeof(void *);

	msg = malloc(msg_sz);
	if (msg) {
		memset(msg, 0x00, msg_sz);
		msg->destination = -1;
		msg->sz = sz;
	}
	return msg;
}

void ipc_msg_free(struct ipc_msg *msg)
{
	free(msg);
}

int ipc_msg_send(struct ipc_msg *msg)
{
	struct nl_msg *nlmsg;
	struct nlmsghdr *hdr;
	int ret = -EINVAL;

	nlmsg = nlmsg_alloc();
	if (!nlmsg) {
		ret = -ENOMEM;
		goto out_error;
	}

	hdr = nlmsg_put(nlmsg,
			msg->destination,
			NL_AUTO_SEQ,
			msg->type,
			0,
			0);
	if (!hdr)
		goto out_error;

	ret = nla_put(nlmsg, NLA_UNSPEC, msg->sz, IPC_MSG_PAYLOAD(msg));
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
	struct ipc_msg *msg = ipc_msg_alloc(sizeof(*ev));
	int ret;

	if (!msg)
		return -ENOMEM;

	pr_info("Starting up...\n");

	ev = IPC_MSG_PAYLOAD(msg);
	msg->destination = CIFSD_IPC_DESTINATION_KERNEL;
	msg->type = CIFSD_EVENT_STARTING_UP;

	ev->pid = getpid();
	strncpy(ev->version, CIFSD_VERSION, sizeof(ev->version));

	ret = ipc_msg_send(msg);

	ipc_msg_free(msg);
	return ret;
}

static int ipc_cifsd_shutting_down(void)
{
	struct cifsd_startup_shutdown *ev;
	struct ipc_msg *msg = ipc_msg_alloc(sizeof(*ev));
	int ret;

	if (!msg)
		return -ENOMEM;

	pr_info("Shutting down...\n");

	ev = IPC_MSG_PAYLOAD(msg);
	msg->destination = CIFSD_IPC_DESTINATION_KERNEL;
	msg->type = CIFSD_EVENT_SHUTTING_DOWN;

	ev->pid = getpid();
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
		if (nl_recvmsgs_default(sk) < 0)
			break;
	}
	return -EINVAL;
}

void ipc_final_release(void)
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

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb)
		goto out_error;

	nl_socket_enable_msg_peek(sk);
	nl_socket_disable_seq_check(sk);

	if (nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, nlink_msg_cb, NULL))
		goto out_error;

	if (nl_connect(sk, CIFSD_TOOLS_NETLINK))
		goto out_error;

	cifsd_health_status = CIFSD_HEALTH_RUNNING;
	return 0;

out_error:
	ipc_final_release();
	return -EINVAL;
}
