/*
 *   cifsd-tools/cifsd/pipecb.c
 *
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
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

#include <assert.h>
#include "cifsd.h"
#include "list.h"
#include "netlink.h"

#define CREATE	0x1
#define REMOVE	0x2
#define READ	0x4
#define WRITE	0x8
#define TRANS	0x10

void initialize(void)
{
	INIT_LIST_HEAD(&cifsd_clients);
}

struct cifsd_client_info *head;

struct cifsd_client_info *lookup_client(__u64 clienthash)
{
	struct cifsd_client_info *client;
	struct list_head *tmp;

	if (!list_empty(&cifsd_clients)) {
		list_for_each(tmp, &cifsd_clients) {
			client = list_entry(tmp, struct cifsd_client_info, list);
			if (client->hash == clienthash) {
				cifsd_debug("found matching clienthash %llu, client %p\n", clienthash, client);
				return client;
			}
		}
	}

	client = calloc(1, sizeof(struct cifsd_client_info));
	if (client) {
		client->hash = clienthash;
		INIT_LIST_HEAD(&client->list);
		INIT_LIST_HEAD(&client->pipelist);
		list_add(&client->list, &cifsd_clients);
		cifsd_debug("added clienthash %llu\n", clienthash);
	}
	return client;
}

struct cifsd_pipe *lookup_pipe(__u64 clienthash, int pipetype)
{
	struct cifsd_client_info *client;
	struct cifsd_pipe *pipe;
	struct list_head *tmp;

	client = lookup_client(clienthash);
	if (!client) {
		cifsd_err("Failed to locate client (0x%llx)\n", clienthash);
		return NULL;
	}

	if (list_empty(&client->pipelist)) {
		cifsd_err("No pipe yet opened from the client(0x%llx)\n",
				clienthash);
		return NULL;
	}

	list_for_each(tmp, &client->pipelist) {
		pipe = list_entry(tmp, struct cifsd_pipe, list);
		if (pipe->pipe_type == pipetype)
			return pipe;
	}

	return NULL;
}

static struct cifsd_pipe *initpipe(int pipetype, char *codepage)
{
	struct cifsd_pipe *pipe = NULL;
	pipe = (struct cifsd_pipe*) calloc(1, sizeof(struct cifsd_pipe));
	if (pipe) {
		pipe->pipe_type = pipetype;
		strncpy(pipe->codepage, codepage, CIFSD_CODEPAGE_LEN - 1);
		INIT_LIST_HEAD(&pipe->list);
	}
	return pipe;
}

static int cifsd_create_pipe(__u64 clienthash, int pipetype, char *codepage)
{
        struct cifsd_pipe *pipe;
	struct cifsd_client_info *client;

	pipe = initpipe(pipetype, codepage);
	if (!pipe) {
		cifsd_err("Failed to allocate memory for cifsd pipe\n");
		return -ENOMEM;
	}

	client = lookup_client(clienthash);
	if (!client) {
		cifsd_err("Failed to allocate memory for cifsd client object\n");
		return -ENOMEM;
	}

	cifsd_debug("added pipe %p, in client 0x%llx, client %p\n",
			pipe, clienthash, client);
	list_add(&pipe->list, &client->pipelist);

	return 0;
}

static int cifsd_remove_pipe(__u64 clienthash, int pipetype)
{
	struct cifsd_pipe *pipe;

	pipe = lookup_pipe(clienthash, pipetype);
	if (!pipe) {
		cifsd_err("dcerpc pipe of type (%d) not found \n", pipetype);
		return -EINVAL;
	}

	cifsd_debug("remove pipe %p from clienthash 0x%llx\n", pipe,
			clienthash);
	/* If need to add logic about cleaning up pipe buffers, ADD HERE */
	list_del(&pipe->list);
	free(pipe);
	return 0;
}

static int handle_create_pipe_event(void *msg)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)msg;
	struct cifsd_uevent *ev = NLMSG_DATA(nlh);
	int ret;

	cifsd_debug("CREATE: on server handle 0x%llx, pipe type %u\n",
			ev->server_handle, ev->pipe_type);
	ret = cifsd_create_pipe(ev->server_handle, ev->pipe_type,
			ev->k.c_pipe.codepage);
	if (ret) {
		//TODO:	... prepare pipe create failure netlink msg ...
		cifsd_debug("CREATE: pipe failed %d\n", ret);
	}

	return ret;
}

static int handle_remove_pipe_event(void *msg)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)msg;
	struct cifsd_uevent *ev = NLMSG_DATA(nlh);
	int ret;

	cifsd_debug("DESTROY: on server handle 0x%llx, pipe %u\n",
			ev->server_handle, ev->pipe_type);
	ret = cifsd_remove_pipe(ev->server_handle, ev->pipe_type);
	if (ret) {
		//TODO:	... prepare pipe removal failure netlink msg...
		cifsd_debug("DESTROY: pipe failed %d\n", ret);
	}

	return ret;
}

static int handle_read_pipe_event(void *msg)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)msg;
	struct cifsd_uevent *ev = NLMSG_DATA(nlh);
	struct cifsd_uevent rsp_ev;
	struct cifsd_pipe *pipe;
	char *buf;
	int ret = 0;
	int nbytes = 0;

	cifsd_debug("READ: on server handle 0x%llx\n", ev->server_handle);
	assert(ev->k.r_pipe.out_buflen < NETLINK_CIFSD_MAX_PAYLOAD);
	buf = calloc(1, NETLINK_CIFSD_MAX_PAYLOAD);
	if (!buf) {
		cifsd_debug("failed to allocate memory\n");
		ret = -ENOMEM;
		goto out;
	}

	pipe = lookup_pipe(ev->server_handle, ev->pipe_type);
	if (!pipe) {
		cifsd_debug("READ: pipetype %u lookup failed for clienthash 0x%llx\n",
				ev->pipe_type, ev->server_handle);
		ret = -ENOENT;
		goto out;
	}

	nbytes = process_rpc_rsp(pipe, buf, ev->k.r_pipe.out_buflen);
	if (nbytes < 0) {
		ret = nbytes;
		nbytes = 0;
	}
	cifsd_debug("READ: length %d\n", nbytes);

out:
	memset(&rsp_ev, 0, sizeof(rsp_ev));
	rsp_ev.type = CIFSD_UEVENT_READ_PIPE_RSP;
	rsp_ev.server_handle = ev->server_handle;
	rsp_ev.pipe_type = ev->pipe_type;

	rsp_ev.error = ret;
	rsp_ev.buflen = nbytes;
	rsp_ev.u.r_pipe_rsp.read_count = nbytes;
	ret = cifsd_common_sendmsg(&rsp_ev, buf, nbytes);
	cifsd_debug("READ: response u->k send, on server handle 0x%llx, ret %d\n",
			ev->server_handle, ret);
	if (buf)
		free(buf);
	return ret;
}

static int handle_write_pipe_event(void *msg)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)msg;
	struct cifsd_uevent *ev = NLMSG_DATA(nlh);
	struct cifsd_uevent rsp_ev;
	struct cifsd_pipe *pipe;
	int ret;

	cifsd_debug("WRITE: on server handle 0x%llx\n", ev->server_handle);
	pipe = lookup_pipe(ev->server_handle, ev->pipe_type);
	if (!pipe) {
		cifsd_debug("WRITE: pipetype %u lookup failed for clienthash 0x%llx\n",
				ev->pipe_type, ev->server_handle);
		ret = -ENOENT;
		goto out;
	}

	ret = process_rpc(pipe, ev->buffer);
	if (ret)
		cifsd_debug("process_rpc: failed ret %d\n", ret);

out:
	memset(&rsp_ev, 0, sizeof(rsp_ev));
	rsp_ev.type = CIFSD_UEVENT_WRITE_PIPE_RSP;
	rsp_ev.server_handle = ev->server_handle;
	rsp_ev.pipe_type = ev->pipe_type;

	rsp_ev.error = ret;
	rsp_ev.buflen = 0;
	rsp_ev.u.w_pipe_rsp.write_count = ret < 0 ? 0 : ev->buflen;
	ret = cifsd_common_sendmsg(&rsp_ev, NULL, 0);
	cifsd_debug("WRITE: response u->k send, on server handle 0x%llx, ret %d\n",
			ev->server_handle, ret);
	return ret;
}

static int handle_ioctl_pipe_event(void *msg)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)msg;
	struct cifsd_uevent *ev = NLMSG_DATA(nlh);
	struct cifsd_uevent rsp_ev;
	struct cifsd_pipe *pipe;
	char *buf;
	int ret;
	int nbytes = 0;

	cifsd_debug("IOCTL: on server handle %llu\n", ev->server_handle);
	assert(ev->k.i_pipe.out_buflen < NETLINK_CIFSD_MAX_PAYLOAD);
	buf = calloc(1, NETLINK_CIFSD_MAX_PAYLOAD);
	if (!buf) {
		cifsd_debug("failed to allocate memory\n");
		ret = -ENOMEM;
		goto out;
	}

	pipe = lookup_pipe(ev->server_handle, ev->pipe_type);
	if (!pipe) {
		cifsd_debug("IOCTL: pipetype %u lookup failed for clienthash 0x%llx\n",
				ev->pipe_type, ev->server_handle);
		ret = -ENOENT;
		goto out;
	}

	ret = process_rpc(pipe, ev->buffer);
	if (ret) {
		cifsd_debug("process_rpc: failed %d\n", ret);
		goto out;
	}

	nbytes = process_rpc_rsp(pipe, buf, ev->k.i_pipe.out_buflen);
	if (nbytes < 0) {
		ret = nbytes;
		nbytes = 0;
	}

out:
	memset(&rsp_ev, 0, sizeof(rsp_ev));
	rsp_ev.type = CIFSD_UEVENT_IOCTL_PIPE_RSP;
	rsp_ev.server_handle = ev->server_handle;
	rsp_ev.pipe_type = ev->pipe_type;

	rsp_ev.error = ret;
	rsp_ev.buflen = nbytes;
	rsp_ev.u.i_pipe_rsp.data_count = nbytes;
	ret = cifsd_common_sendmsg(&rsp_ev, buf, nbytes);
	cifsd_debug("IOCTL: response u->k send, on server handle 0x%llx, ret %d\n",
			ev->server_handle, ret);
	if (buf)
		free(buf);

	return ret;
}

static int handle_lanman_pipe_event(void *msg)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)msg;
	struct cifsd_uevent *ev = NLMSG_DATA(nlh);
	struct cifsd_uevent rsp_ev;
	struct cifsd_pipe *pipe;
	char *buf;
	int ret;
	int nbytes = 0;
	int param_len = 0;

	cifsd_debug("LANMAN: on server handle 0x%llx\n", ev->server_handle);
	assert(ev->k.l_pipe.out_buflen < NETLINK_CIFSD_MAX_PAYLOAD);
	buf = calloc(1, NETLINK_CIFSD_MAX_PAYLOAD);
	if (!buf) {
		cifsd_debug("failed to allocate memory\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = cifsd_create_pipe(ev->server_handle, ev->pipe_type,
			ev->k.l_pipe.codepage);
	if (ret) {
		cifsd_debug("CREATE: pipe failed %d\n", ret);
		goto out;
	}

	pipe = lookup_pipe(ev->server_handle, ev->pipe_type);
	if (!pipe) {
		cifsd_debug("LANMAN: pipetype %u lookup failed for clienthash 0x%llx\n",
				ev->pipe_type, ev->server_handle);
		ret = -ENOENT;
		goto out;
	}

	strncpy(pipe->username, ev->k.l_pipe.username,
			CIFSD_USERNAME_LEN - 1);
	nbytes = handle_lanman_pipe(pipe, ev->buffer, buf, &param_len);
	if (nbytes < 0) {
		ret = nbytes;
		nbytes = 0;
	}

out:
	memset(&rsp_ev, 0, sizeof(rsp_ev));
	rsp_ev.type = CIFSD_UEVENT_LANMAN_PIPE_RSP;
	rsp_ev.server_handle = ev->server_handle;
	rsp_ev.pipe_type = ev->pipe_type;

	rsp_ev.error = ret;
	rsp_ev.buflen = nbytes;
	rsp_ev.u.l_pipe_rsp.data_count = nbytes;
	rsp_ev.u.l_pipe_rsp.param_count = param_len;
	ret = cifsd_common_sendmsg(&rsp_ev, buf, nbytes);
	cifsd_debug("IOCTL: response u->k send, on server handle 0x%llx, ret %d\n",
			ev->server_handle, ret);
	if (buf)
		free(buf);

	ret = cifsd_remove_pipe(ev->server_handle, ev->pipe_type);
	if (ret)
		cifsd_debug("DESTROY: pipe failed %d\n", ret);

	return ret;
}

/*
 * once the pipe is available, utilize the code from process_rpc/process_rpc_rsp
 * modify the rpc request/response to use the pipe from above methods
 */
int request_handler(void *msg)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)msg;
	struct cifsd_uevent *ev = NLMSG_DATA(nlh);
	int ret = 0;

	cifsd_debug("got %u event, pipe type %u\n", nlh->nlmsg_type,
			ev->pipe_type);

	switch (nlh->nlmsg_type) {
	case CIFSD_KEVENT_CREATE_PIPE:
		ret = handle_create_pipe_event(msg);
		break;

	case CIFSD_KEVENT_DESTROY_PIPE:
		ret = handle_remove_pipe_event(msg);
		break;

	case CIFSD_KEVENT_READ_PIPE:
		ret = handle_read_pipe_event(msg);
		break;

	case CIFSD_KEVENT_WRITE_PIPE:
		ret = handle_write_pipe_event(msg);
		break;

	case CIFSD_KEVENT_IOCTL_PIPE:
		ret = handle_ioctl_pipe_event(msg);
		break;

	case CIFSD_KEVENT_LANMAN_PIPE:
		ret = handle_lanman_pipe_event(msg);
		break;

	case CFISD_KEVENT_USER_DAEMON_EXIST:
		cifsd_err("cifsd already exist!\n");
		exit(1);
		break;

	default:
		cifsd_err("unknown event %u\n", ev->type);
		ret = -EINVAL;
		break;
	}

	return ret;
}
