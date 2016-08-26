/*
 *   cifssrv-tools/cifssrvd/pipecb.c
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

#include "cifssrv.h"
#include "list.h"
#include "netlink.h"

#define CREATE	0x1
#define REMOVE	0x2
#define READ	0x4
#define WRITE	0x8
#define TRANS	0x10

/* List of connected clients */
struct list_head cifssrvd_clients;

void initialize(void)
{
	INIT_LIST_HEAD(&cifssrvd_clients);
}

struct cifssrvd_client_info *head;

struct cifssrvd_client_info *lookup_client(__u64 clienthash)
{
	struct cifssrvd_client_info *client;
	struct list_head *tmp;

	if (!list_empty(&cifssrvd_clients)) {
		list_for_each(tmp, &cifssrvd_clients) {
			client = list_entry(tmp, struct cifssrvd_client_info, list);
			if (client->hash == clienthash) {
				cifssrv_debug("found matching clienthash %llu, client %p\n", clienthash, client);
				return client;
			}
		}
	}

	client = calloc(1, sizeof(struct cifssrvd_client_info));
	if (client) {
		client->hash = clienthash;
		INIT_LIST_HEAD(&client->list);
		INIT_LIST_HEAD(&client->pipelist);
		list_add(&client->list, &cifssrvd_clients);
		cifssrv_debug("added clienthash %llu\n", clienthash);
	}
	return client;
}

struct cifssrv_pipe *lookup_pipe(unsigned int clienthash, int pipetype)
{
	struct cifssrvd_client_info *client;
	struct cifssrv_pipe *pipe;
	struct list_head *tmp;

	client = lookup_client(clienthash);
	if (!client) {
		cifssrv_err("Failed to locate client (0x%x)\n", clienthash);
		return NULL;
	}

	if (list_empty(&client->pipelist)) {
		cifssrv_err("No pipe yet opened from the client(0x%x)\n", clienthash);
		return NULL;
	}

	list_for_each(tmp, &client->pipelist) {
		pipe = list_entry(tmp, struct cifssrv_pipe, list);
		if (pipe->pipe_type == pipetype)
			return pipe;
	}

	return NULL;
}

static struct cifssrv_pipe *initpipe(int pipetype, char *codepage)
{
	struct cifssrv_pipe *pipe = NULL;
	pipe = (struct cifssrv_pipe*) calloc(1, sizeof(struct cifssrv_pipe));
	if (pipe) {
		pipe->pipe_type = pipetype;
		strncpy(pipe->codepage, codepage, CIFSSRV_CODEPAGE_LEN - 1);
		INIT_LIST_HEAD(&pipe->list);
	}
	return pipe;
}

static int cifssrv_create_pipe(__u64 clienthash, int pipetype, char *codepage)
{
        struct cifssrv_pipe *pipe;
	struct cifssrvd_client_info *client;

	pipe = initpipe(pipetype, codepage);
	if (!pipe) {
		cifssrv_err("Failed to allocate memory for cifssrv pipe\n");
		return -ENOMEM;
	}

	client = lookup_client(clienthash);
	if (!client) {
		cifssrv_err("Failed to allocate memory for cifssrv client object\n");
		return -ENOMEM;
	}

	cifssrv_debug("added pipe %p, in client %llu, client %p\n",
			pipe, clienthash, client);
	list_add(&pipe->list, &client->pipelist);

	return 0;
}

static int cifssrv_remove_pipe(__u64 clienthash, int pipetype)
{
	struct cifssrv_pipe *pipe;

	pipe = lookup_pipe(clienthash, pipetype);
	if (!pipe) {
		cifssrv_err("dcerpc pipe of type (%d) not found \n", pipetype);
		return -EINVAL;
	}

	cifssrv_debug("remove pipe %p from clienthash %llu\n", pipe, clienthash);
	/* If need to add logic about cleaning up pipe buffers, ADD HERE */
	list_del(&pipe->list);
	free(pipe);
	return 0;
}

/*
 * once the pipe is available, utilize the code from process_rpc/process_rpc_rsp
 * modify the rpc request/response to use the pipe from above methods
 *
 */
int request_handler(void *msg)
{
	struct cifssrv_pipe *pipe = NULL;
	int nbytes = 0;
	int ret = 0;
	unsigned int pipetype = 0;
	struct nlmsghdr *nlh = (struct nlmsghdr *)msg;
	struct cifssrv_uevent *ev = NLMSG_DATA(nlh);
	__u64 clienthash = ev->server_handle;
	char *obuf;
	int param_len = 0;

	cifssrv_debug("got %u event\n", nlh->nlmsg_type);
	switch (nlh->nlmsg_type) {
	case CIFSSRV_KEVENT_CREATE_PIPE:
		cifssrv_debug("CREATE: on server handle %llu, pipe %u\n",
				ev->server_handle, ev->k.c_pipe.type);
		ret = cifssrv_create_pipe(ev->server_handle, ev->k.c_pipe.type,
					ev->k.c_pipe.codepage);
		if (ret) {
		//TODO:	... prepare pipe create failure netlink msg ...
			cifssrv_debug("CREATE: pipe failed %d\n", ret);
		}
		break;
	case CIFSSRV_KEVENT_DESTROY_PIPE:
		cifssrv_debug("DESTROY: on server handle %llu, pipe %u\n",
				ev->server_handle, ev->k.d_pipe.type);
		ret = cifssrv_remove_pipe(ev->server_handle, ev->k.d_pipe.type);
		if (ret) {
		//TODO:	... prepare pipe removal failure netlink msg...
			cifssrv_debug("DESTROY: pipe failed %d\n", ret);
		}
		break;
	case CIFSSRV_KEVENT_READ_PIPE:
		pipetype = ev->k.r_pipe.type;
		cifssrv_debug("READ: on server handle %llu\n", ev->server_handle);
		pipe = lookup_pipe(clienthash, pipetype);
		if (pipe) {
			nbytes = process_rpc_rsp(pipe, ev->buffer,
					ev->k.r_pipe.out_buflen);
			cifssrv_debug("READ: nbytes %d\n", nbytes);

			if (nbytes <= 0) {
				ret = cifssrv_common_sendmsg(
						CIFSSRV_UEVENT_READ_PIPE_RSP,
						nbytes, ev->server_handle, 0,
						0, 0, NULL, 0);
			} else {
				ret = cifssrv_common_sendmsg(
						CIFSSRV_UEVENT_READ_PIPE_RSP, 0,
						ev->server_handle, 0, nbytes,
						nbytes, ev->buffer, 0);
			}
		} else {
			cifssrv_debug("READ: pipetype %u lookup failed for clienthash %llu\n",
					pipetype, clienthash);
			cifssrv_common_sendmsg(CIFSSRV_UEVENT_READ_PIPE_RSP,
					-ENOENT, ev->server_handle, 0, 0,
					0, NULL, 0);
		}
		cifssrv_debug("READ: response u->k send, on server handle %llu\n",
				ev->server_handle);
		break;

	case CIFSSRV_KEVENT_WRITE_PIPE:
		cifssrv_debug("WRITE: on server handle %llu\n", ev->server_handle);
		pipetype = ev->k.w_pipe.type;
		pipe = lookup_pipe(clienthash, pipetype);
		if (pipe) {
			ret = process_rpc(pipe, ev->buffer);
			if (ret)
				cifssrv_debug("process_rpc: failed ret %d\n", ret);

			ret = cifssrv_common_sendmsg(
					CIFSSRV_UEVENT_WRITE_PIPE_RSP,
					ret, ev->server_handle, 0, ev->buflen,
					0, NULL, 0);
		} else {
			cifssrv_debug("WRITE: pipetype %u lookup failed for clienthash %llu\n",
					pipetype, clienthash);
			ret = cifssrv_common_sendmsg(
					CIFSSRV_UEVENT_WRITE_PIPE_RSP,
					-ENOENT, ev->server_handle, 0, 0, 0,
					NULL, 0);
		}

		cifssrv_debug("WRITE: response u->k send, on server handle %llu\n",
				ev->server_handle);
		break;
	case CIFSSRV_KEVENT_IOCTL_PIPE:
		pipetype = ev->k.i_pipe.type;
		cifssrv_debug("IOCTL: on server handle %llu\n",
				ev->server_handle);

		pipe = lookup_pipe(clienthash, pipetype);
		if (pipe) {
			ret = process_rpc(pipe, ev->buffer);
			if (ret) {
				cifssrv_debug("process_rpc: failed %d\n", ret);
				cifssrv_common_sendmsg(
						CIFSSRV_UEVENT_IOCTL_PIPE_RSP,
						ret, ev->server_handle, 0, 0,
						0, NULL, 0);
				break;
			}

			nbytes = process_rpc_rsp(pipe, ev->buffer,
					ev->k.i_pipe.out_buflen);
			if (nbytes <= 0) {
				cifssrv_debug("process_rpc_rsp: failed nbytes %d\n", nbytes);
				ret = cifssrv_common_sendmsg(
						CIFSSRV_UEVENT_IOCTL_PIPE_RSP,
						nbytes, ev->server_handle, 0, 0,
						0, NULL, 0);
			} else {
				ret = cifssrv_common_sendmsg(
						CIFSSRV_UEVENT_IOCTL_PIPE_RSP,
						0, ev->server_handle, 0, nbytes,
						nbytes, ev->buffer, 0);
			}

		} else {
			ret = cifssrv_common_sendmsg(
					CIFSSRV_UEVENT_IOCTL_PIPE_RSP,
					-ENOENT, ev->server_handle, 0, 0,
					0, NULL, 0);
		}
		break;
	case CIFSSRV_KEVENT_LANMAN_PIPE:
		cifssrv_debug("LANMAN: on server handle %llu\n",
				ev->server_handle);

		ret = cifssrv_create_pipe(ev->server_handle, ev->k.l_pipe.type,
				ev->k.l_pipe.codepage);
		if (ret) {
			cifssrv_debug("CREATE: pipe failed %d\n", ret);
			goto out;
		}

		pipe = lookup_pipe(clienthash, ev->k.l_pipe.type);
		if (!pipe) {
			cifssrv_debug("LANMAN: pipetype %u lookup failed for clienthash %llu\n",
					pipetype, clienthash);
			ret = cifssrv_common_sendmsg(
					CIFSSRV_UEVENT_LANMAN_PIPE_RSP,
					-ENOENT, ev->server_handle, 0, 0,
					0, NULL, 0);
			ret = cifssrv_remove_pipe(clienthash,
					ev->k.l_pipe.type);
			if (ret)
				cifssrv_debug("DESTROY: pipe failed %d\n", ret);
			goto out;
		}

		strncpy(pipe->username, ev->k.l_pipe.username,
				CIFSSRV_USERNAME_LEN - 1);

		obuf = calloc(1, NETLINK_CIFSSRV_MAX_PAYLOAD);
		if (!obuf) {
			cifssrv_debug("failed to allocate memory\n");
			return -ENOMEM;
		}

		nbytes = handle_lanman_pipe(pipe, ev->buffer, obuf, &param_len);
		if (nbytes < 0) {
			ret = cifssrv_common_sendmsg(
					CIFSSRV_UEVENT_LANMAN_PIPE_RSP,
					nbytes, ev->server_handle, 0, 0,
					0, NULL, 0);
		} else {
			ret = cifssrv_common_sendmsg(
					CIFSSRV_UEVENT_LANMAN_PIPE_RSP,
					0, ev->server_handle, 0, nbytes,
					nbytes, obuf, param_len);
		}

		free(obuf);
		ret = cifssrv_remove_pipe(clienthash, ev->k.l_pipe.type);
		if (ret)
			cifssrv_debug("DESTROY: pipe failed %d\n", ret);
		break;
	default:
		cifssrv_err("unknown event %u\n", ev->type);
		ret = -EINVAL;
		break;
	}

out:
	return ret;
}
