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
#include <netlink/genl/genl.h>
#include <netlink/handlers.h>
#include <linux/genetlink.h>
#include <netlink/genl/mngt.h>

#include <linux/cifsd_server.h>

#include <ipc.h>
#include <cifsdtools.h>
#include <worker_pool.h>

static struct nl_sock *sk;

struct cifsd_ipc_msg *ipc_msg_alloc(size_t sz)
{
	struct cifsd_ipc_msg *msg;
	size_t msg_sz = sz + sizeof(struct cifsd_ipc_msg);

	msg = malloc(msg_sz);
	if (msg) {
		memset(msg, 0x00, msg_sz);
		msg->sz = sz;
	}
	return msg;
}

void ipc_msg_free(struct cifsd_ipc_msg *msg)
{
	free(msg);
}

static int generic_event(int type, void *payload, size_t sz)
{
	struct cifsd_ipc_msg *event;

	event = ipc_msg_alloc(sz);
	if (!event)
		return -ENOMEM;

	event->type = type;
	event->sz = sz;

	memcpy(CIFSD_IPC_MSG_PAYLOAD(event),
	       payload,
	       sz);
	wp_ipc_msg_push(event);
	return 0;
}

static int handle_generic_event(struct nl_cache_ops *unused,
				struct genl_cmd *cmd,
				struct genl_info *info,
				void *arg)
{
	if (!info->attrs[cmd->c_id])
		return NL_SKIP;

	return generic_event(cmd->c_id,
			    nla_data(info->attrs[cmd->c_id]),
			    nla_len(info->attrs[cmd->c_id]));
}

static int nlink_msg_cb(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = genlmsg_hdr(nlmsg_hdr(msg));

	if (gnlh->version != CIFSD_GENL_VERSION) {
		pr_err("IPC message version mistamtch: %d\n", gnlh->version);
		return NL_SKIP;
	}

	pr_debug("RECV:\n");
	nl_msg_dump(msg, stdout);

	return genl_handle_msg(msg, NULL);
}

static int handle_unsupported_event(struct nl_cache_ops *unused,
				    struct genl_cmd *cmd,
				    struct genl_info *info,
				    void *arg)
{
	pr_err("Unsupported IPC event %d, ignore.\n", cmd->c_id);
	return NL_SKIP;
}

static int ipc_cifsd_starting_up(void)
{
	struct cifsd_startup_shutdown *ev;
	struct cifsd_ipc_msg *msg = ipc_msg_alloc(sizeof(*ev));
	int ret;

	if (!msg)
		return -ENOMEM;

	ev = CIFSD_IPC_MSG_PAYLOAD(msg);
	msg->type = CIFSD_EVENT_STARTING_UP;

	strncpy(ev->reserved, "HELO", sizeof(ev->reserved));

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
	msg->type = CIFSD_EVENT_SHUTTING_DOWN;

	strncpy(ev->reserved, "QUIT", sizeof(ev->reserved));

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
			pr_err("Recv() error\n");
			break;
		}
	}
	return -EINVAL;
}

static struct nla_policy cifsd_nl_policy[CIFSD_EVENT_MAX] = {
	[CIFSD_EVENT_UNSPEC] = {
		.minlen = 0,
	},

	[CIFSD_EVENT_HEARTBEAT_REQUEST] = {
		.minlen = sizeof(struct cifsd_heartbeat),
	},

	[CIFSD_EVENT_HEARTBEAT_RESPONSE] = {
		.minlen = sizeof(struct cifsd_heartbeat),
	},

	[CIFSD_EVENT_STARTING_UP] = {
		.minlen = sizeof(struct cifsd_startup_shutdown),
	},

	[CIFSD_EVENT_SHUTTING_DOWN] = {
		.minlen = sizeof(struct cifsd_startup_shutdown),
	},

	[CIFSD_EVENT_LOGIN_REQUEST] = {
		.minlen = sizeof(struct cifsd_login_request),
	},

	[CIFSD_EVENT_LOGIN_RESPONSE] = {
		.minlen = sizeof(struct cifsd_login_response),
	},

	[CIFSD_EVENT_SHARE_CONFIG_REQUEST] = {
		.minlen = sizeof(struct cifsd_share_config_request),
	},

	[CIFSD_EVENT_SHARE_CONFIG_RESPONSE] = {
		.minlen = sizeof(struct cifsd_share_config_response),
	},

	[CIFSD_EVENT_TREE_CONNECT_REQUEST] = {
		.minlen = sizeof(struct cifsd_tree_connect_request),
	},

	[CIFSD_EVENT_TREE_CONNECT_RESPONSE] = {
		.minlen = sizeof(struct cifsd_tree_connect_response),
	},

	[CIFSD_EVENT_TREE_DISCONNECT_REQUEST] = {
		.minlen = sizeof(struct cifsd_tree_disconnect_request),
	},

	[CIFSD_EVENT_LOGOUT_REQUEST] = {
		.minlen = sizeof(struct cifsd_logout_request),
	},

	[CIFSD_RPC_COMMAND_RAP_REQUEST] = {
		.minlen = sizeof(struct cifsd_rpc_command),
	},

	[CIFSD_RPC_COMMAND_RAP_RESPONSE] = {
		.minlen = sizeof(struct cifsd_rpc_command),
	},

	[CIFSD_RPC_COMMAND_SRVSVC_REQUEST] = {
		.minlen = sizeof(struct cifsd_rpc_command),
	},

	[CIFSD_RPC_COMMAND_SRVSVC_RESPONSE] = {
		.minlen = sizeof(struct cifsd_rpc_command),
	},

	[CIFSD_RPC_COMMAND_WKS_REQUEST] = {
		.minlen = sizeof(struct cifsd_rpc_command),
	},

	[CIFSD_RPC_COMMAND_WKS_RESPONSE] = {
		.minlen = sizeof(struct cifsd_rpc_command),
	},
};

static struct genl_cmd cifsd_genl_cmds[] = {
	{
		.c_id		= CIFSD_EVENT_UNSPEC,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_unsupported_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
	{
		.c_id		= CIFSD_EVENT_HEARTBEAT_REQUEST,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_generic_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
	{
		.c_id		= CIFSD_EVENT_HEARTBEAT_RESPONSE,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_unsupported_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
	{
		.c_id		= CIFSD_EVENT_STARTING_UP,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_unsupported_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
	{
		.c_id		= CIFSD_EVENT_SHUTTING_DOWN,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_unsupported_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
	{
		.c_id		= CIFSD_EVENT_LOGIN_REQUEST,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_generic_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
	{
		.c_id		= CIFSD_EVENT_LOGIN_RESPONSE,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_unsupported_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
	{
		.c_id		= CIFSD_EVENT_SHARE_CONFIG_REQUEST,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_generic_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
	{
		.c_id		= CIFSD_EVENT_SHARE_CONFIG_RESPONSE,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_unsupported_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
	{
		.c_id		= CIFSD_EVENT_TREE_CONNECT_REQUEST,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_generic_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
	{
		.c_id		= CIFSD_EVENT_TREE_CONNECT_RESPONSE,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_unsupported_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
	{
		.c_id		= CIFSD_EVENT_TREE_DISCONNECT_REQUEST,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_generic_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
	{
		.c_id		= CIFSD_EVENT_LOGOUT_REQUEST,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_generic_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
	{
		.c_id		= CIFSD_RPC_COMMAND_RAP_REQUEST,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_unsupported_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
	{
		.c_id		= CIFSD_RPC_COMMAND_RAP_RESPONSE,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_unsupported_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
	{
		.c_id		= CIFSD_RPC_COMMAND_SRVSVC_REQUEST,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_unsupported_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
	{
		.c_id		= CIFSD_RPC_COMMAND_SRVSVC_RESPONSE,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_unsupported_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
	{
		.c_id		= CIFSD_RPC_COMMAND_WKS_REQUEST,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_unsupported_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
	{
		.c_id		= CIFSD_RPC_COMMAND_WKS_RESPONSE,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_unsupported_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
};

#define ARRAY_SIZE(X) (sizeof(X) / sizeof((X)[0]))

static struct genl_ops cifsd_family_ops = {
	.o_name = CIFSD_GENL_NAME,
	.o_cmds = cifsd_genl_cmds,
	.o_ncmds = ARRAY_SIZE(cifsd_genl_cmds),
};

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

	nlmsg_set_proto(nlmsg, NETLINK_GENERIC);
	hdr = genlmsg_put(nlmsg, getpid(), 0, cifsd_family_ops.o_id,
			  0, NLM_F_MULTI, msg->type, CIFSD_GENL_VERSION);
	if (!hdr)
		goto out_error;

	/* Use msg->type as attribute TYPE */
	ret = nla_put(nlmsg, msg->type, msg->sz, CIFSD_IPC_MSG_PAYLOAD(msg));
	if (ret)
		goto out_error;

	pr_debug("SEND\n");
	nl_msg_dump(nlmsg, stdout);

	ret = nl_send_auto_complete(sk, nlmsg);
	if (ret > 0)
		ret = 0;

out_error:
	if (nlmsg)
		nlmsg_free(nlmsg);
	return ret;
}

void ipc_destroy(void)
{
	if (cifsd_health_status == CIFSD_HEALTH_RUNNING)
		ipc_cifsd_shutting_down();

	genl_unregister_family(&cifsd_family_ops);
	nl_socket_free(sk);
	sk = NULL;
}

int ipc_init(void)
{
	sk = nl_socket_alloc();
	if (!sk) {
		pr_err("Cannot allocate netlink socket\n");
		goto out_error;
	}

	nl_socket_disable_seq_check(sk);
	if (nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM,
				nlink_msg_cb, NULL))
		goto out_error;

	if (nl_connect(sk, NETLINK_GENERIC)) {
		pr_err("Cannot connect to generic netlink.\n");
		goto out_error;
	}

	if (genl_register_family(&cifsd_family_ops)) {
		pr_err("Cannot register netlink family\n");
		goto out_error;
	}
	if (genl_ops_resolve(sk, &cifsd_family_ops)) {
		pr_err("Cannot resolve netlink family\n");
		goto out_error;
	}

	cifsd_health_status = CIFSD_HEALTH_RUNNING;
	return 0;

out_error:
	ipc_destroy();
	return -EINVAL;
}
