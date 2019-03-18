// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
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

#include <cifsdtools.h>
#include <ipc.h>
#include <worker.h>

static struct nl_sock *sk;

struct cifsd_ipc_msg *ipc_msg_alloc(size_t sz)
{
	struct cifsd_ipc_msg *msg;
	size_t msg_sz = sz + sizeof(struct cifsd_ipc_msg) + 1;

	if (msg_sz > CIFSD_IPC_MAX_MESSAGE_SIZE)
		pr_err("IPC message is too large: %lu\n", msg_sz);

	msg = calloc(1, msg_sz);
	if (msg) {
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

#if TRACING_DUMP_NL_MSG
	nl_msg_dump(msg, stdout);
#endif

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
	struct cifsd_startup_request *ev;
	struct cifsd_ipc_msg *msg;
	int ifc_alloc_size = 0;
	int ret;

	if (global_conf.bind_interfaces_only && global_conf.interfaces)
		ifc_alloc_size = strlen(global_conf.interfaces);

	msg = ipc_msg_alloc(sizeof(*ev) + ifc_alloc_size);
	if (!msg)
		return -ENOMEM;

	ev = CIFSD_IPC_MSG_PAYLOAD(msg);
	msg->type = CIFSD_EVENT_STARTING_UP;

	ev->signing = global_conf.server_signing;
	ev->tcp_port = global_conf.tcp_port;
	ev->ipc_timeout = global_conf.ipc_timeout;
	ev->deadtime = global_conf.deadtime;

	if (global_conf.server_min_protocol) {
		strncpy(ev->min_prot,
			global_conf.server_min_protocol,
			sizeof(ev->min_prot) - 1);
	}
	if (global_conf.server_max_protocol) {
		strncpy(ev->max_prot,
			global_conf.server_max_protocol,
			sizeof(ev->max_prot) - 1);
	}
	if (global_conf.netbios_name) {
		strncpy(ev->netbios_name,
			global_conf.netbios_name,
			sizeof(ev->netbios_name) - 1);
	}
	if (global_conf.server_string) {
		strncpy(ev->server_string,
			global_conf.server_string,
			sizeof(ev->server_string) - 1);
	}
	if (global_conf.work_group) {
		strncpy(ev->work_group,
			global_conf.work_group,
			sizeof(ev->work_group) - 1);
	}

	if (global_conf.bind_interfaces_only && global_conf.interfaces) {
		char *config_payload;

		config_payload = CIFSD_STARTUP_CONFIG_INTERFACES(ev);
		strcpy(config_payload, global_conf.interfaces);
	}

	ret = ipc_msg_send(msg);
	ipc_msg_free(msg);
	return ret;
}

static int ipc_cifsd_shutting_down(void)
{
	return 0;
}

int ipc_process_event(void)
{
	if (nl_recvmsgs_default(sk) < 0) {
		pr_err("Recv() error %s\n", strerror(errno));
		return -EINVAL;
	}
	return 0;
}

static struct nla_policy cifsd_nl_policy[CIFSD_EVENT_MAX] = {
	[CIFSD_EVENT_UNSPEC] = {
		.minlen = 0,
	},

	[CIFSD_EVENT_HEARTBEAT_REQUEST] = {
		.minlen = sizeof(struct cifsd_heartbeat),
	},

	[CIFSD_EVENT_STARTING_UP] = {
		.minlen = sizeof(struct cifsd_startup_request),
	},

	[CIFSD_EVENT_SHUTTING_DOWN] = {
		.minlen = sizeof(struct cifsd_startup_request),
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

	[CIFSD_EVENT_RPC_REQUEST] = {
		.minlen = sizeof(struct cifsd_rpc_command),
	},

	[CIFSD_EVENT_RPC_RESPONSE] = {
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
		.c_id		= CIFSD_EVENT_RPC_REQUEST,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_generic_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
	{
		.c_id		= CIFSD_EVENT_RPC_RESPONSE,
		.c_attr_policy	= cifsd_nl_policy,
		.c_msg_parser	= &handle_unsupported_event,
		.c_maxattr	= CIFSD_EVENT_MAX,
	},
};

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
			  0, 0, msg->type, CIFSD_GENL_VERSION);
	if (!hdr) {
		pr_err("genlmsg_put() has failed, aborting IPC send()\n");
		goto out_error;
	}

	/* Use msg->type as attribute TYPE */
	ret = nla_put(nlmsg, msg->type, msg->sz, CIFSD_IPC_MSG_PAYLOAD(msg));
	if (ret) {
		pr_err("nla_put() has failed, aborting IPC send()\n");
		goto out_error;
	}

#if TRACING_DUMP_NL_MSG
	nl_msg_dump(nlmsg, stdout);
#endif

	nl_complete_msg(sk, nlmsg);
	ret = nl_send_auto(sk, nlmsg);
	if (ret > 0)
		ret = 0;
	else
		pr_err("nl_send_auto() has failed: %d\n", ret);

out_error:
	if (nlmsg)
		nlmsg_free(nlmsg);
	return ret;
}

void ipc_destroy(void)
{
	if (cifsd_health_status & CIFSD_HEALTH_RUNNING) {
		ipc_cifsd_shutting_down();
		genl_unregister_family(&cifsd_family_ops);
	}

	nl_socket_free(sk);
	sk = NULL;
}

int ipc_init(void)
{
	int ret;

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

	do {
		/*
		 * Chances are we can start before cifsd kernel module is up
		 * and running. So just wait for the kcifsd to register the
		 * netlink family and accept our connection.
		 */
		ret = genl_ops_resolve(sk, &cifsd_family_ops);
		if (ret) {
			pr_err("Cannot resolve netlink family\n");
			sleep(5);
		}
	} while (ret);

	if (ipc_cifsd_starting_up()) {
		pr_err("Unable to send startup event\n");
		return -EINVAL;
	}

	cifsd_health_status = CIFSD_HEALTH_RUNNING;
	return 0;

out_error:
	ipc_destroy();
	return -EINVAL;
}
