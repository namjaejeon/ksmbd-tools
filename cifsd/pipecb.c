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
#include <sys/inotify.h>
#include <limits.h>
#include <pthread.h>

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

/* convert completion filter into inotify mask  */
static unsigned int convert_completion_filter(unsigned int completion_filter)
{
	unsigned int mask = 0;

	/* CHANGE_NOTIFY is only for a directory. */
	mask |= IN_MASK_ADD | IN_ONLYDIR;

	if (completion_filter & FILE_NOTIFY_CHANGE_NAME)
		mask |= IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO;
	if (completion_filter & FILE_NOTIFY_CHANGE_ATTRIBUTES)
		mask |= IN_ATTRIB|IN_MOVED_TO|IN_MOVED_FROM|IN_MODIFY;
	if (completion_filter & FILE_NOTIFY_CHANGE_LAST_WRITE)
		mask |= IN_ATTRIB;
	if (completion_filter & FILE_NOTIFY_CHANGE_LAST_ACCESS)
		mask |= IN_ATTRIB;
	if (completion_filter & FILE_NOTIFY_CHANGE_EA)
		mask |= IN_ATTRIB;
	if (completion_filter & FILE_NOTIFY_CHANGE_SECURITY)
		mask |= IN_ATTRIB;

	return mask;
}

static void fill_noti_info_res(struct cifsd_uevent *ev,
	char inotify_event_buf[],
	struct smb2_inotify_res_info *noti_info_res_buf)
{
	struct inotify_event *event;

	event = (struct inotify_event *) inotify_event_buf;
	cifsd_debug("event mask : %u, event file name : %s\n",
		event->mask, event->name);

	noti_info_res_buf->file_notify_info[0].NextEntryOffset = 0;

	if (event->mask & IN_CREATE)
		noti_info_res_buf->file_notify_info[0].Action =
			FILE_ACTION_ADDED;
	else if (event->mask & IN_DELETE)
		noti_info_res_buf->file_notify_info[0].Action =
			FILE_ACTION_REMOVED;
	else if (event->mask & IN_MOVED_FROM)
		noti_info_res_buf->file_notify_info[0].Action =
			FILE_ACTION_REMOVED;
		/* TODO : add RENAME case */
	else if (event->mask & IN_MOVED_TO)
		noti_info_res_buf->file_notify_info[0].Action =
			FILE_ACTION_ADDED;
		/* TODO : add RENAME case */
	else
		noti_info_res_buf->file_notify_info[0].Action =
			FILE_ACTION_MODIFIED;

	noti_info_res_buf->file_notify_info[0].FileNameLength =
		strlen(event->name) * 2;

	smbConvertToUTF16(noti_info_res_buf->file_notify_info[0].FileName,
		event->name, event->len, (event->len)*2, ev->codepage);

	cifsd_debug("noti_info_res_buf->file_notify_info[0].Action : %d\n",
		noti_info_res_buf->file_notify_info[0].Action);
}

static void send_rsp_ev(struct cifsd_uevent *ev,
	struct smb2_inotify_res_info *noti_info_res_buf)
{
	struct cifsd_uevent rsp_ev;

	memset(&rsp_ev, 0, sizeof(rsp_ev));
	rsp_ev.type = CIFSD_UEVENT_INOTIFY_RESPONSE;
	rsp_ev.server_handle = ev->server_handle;

	cifsd_common_sendmsg(&rsp_ev, (char *)noti_info_res_buf,
		sizeof(struct smb2_inotify_res_info) +
		sizeof(struct FileNotifyInformation) + NAME_MAX);
}

static int handle_inotify_request_event(void *msg)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)msg;
	struct cifsd_uevent *ev = NLMSG_DATA(nlh);
	struct smb2_inotify_req_info *inotify_req_info;
	struct smb2_inotify_res_info *noti_info_res_buf;
	int fd;
	unsigned int mask;
	int wd;
	int num_event;
	const int event_size = (sizeof(struct inotify_event) + NAME_MAX + 1);
	const int BUF_LEN = (10 * event_size);
	char inotify_event_buf[BUF_LEN];

	fd = inotify_init();
	if (fd == -1) {
		cifsd_err("inotify_init failed!\n");
		return -ENOENT;
	}

	inotify_req_info = (struct inotify_req_info *)ev->buffer;
	mask = convert_completion_filter(inotify_req_info->CompletionFilter);

	wd = inotify_add_watch(fd, inotify_req_info->dir_path, mask);
	if (wd == -1) {
		cifsd_err("inotify_add_watch failed!\n");
		return -ENOENT;
	}

	cifsd_debug("%s is being watched with wd[%d]\n",
		inotify_req_info->dir_path, wd);

	for (;;) {
		num_event = read(fd, inotify_event_buf, BUF_LEN);
		if (num_event == 0)
			cifsd_err("num_event is zero\n");
		else if (num_event == -1)
			cifsd_err("inotify read failure\n");
		cifsd_debug("%ld bytes read from inodify fd(%d)\n",
			(long)num_event, fd);

		/*
		 * len == 0 means event occurred on the base directory.
		 * just ignore the event in that case.
		 */
		if (((struct inotify_event *)inotify_event_buf)->len == 0)
			continue;

		noti_info_res_buf = (struct smb2_inotify_res_info *)malloc(
			sizeof(struct smb2_inotify_res_info) +
			sizeof(struct FileNotifyInformation) + NAME_MAX);
		if (!noti_info_res_buf)
			return -ENOMEM;

		fill_noti_info_res(ev, inotify_event_buf, noti_info_res_buf);
		noti_info_res_buf->output_buffer_length =
			sizeof(struct FileNotifyInformation)
			+ noti_info_res_buf->file_notify_info[0].FileNameLength;
		cifsd_debug("noti_info_res_buf->output_buffer_length : %d\n",
			noti_info_res_buf->output_buffer_length);
		send_rsp_ev(ev, noti_info_res_buf);
		inotify_rm_watch(fd, wd);
		free(noti_info_res_buf);
		break;
	}

	return 0;
}

static int make_inotify_handler_thread(struct nlmsghdr *msg)
{
	pthread_t th;
	pthread_attr_t attr;
	int ret = 0;

	ret = pthread_attr_init(&attr);
	if (ret) {
		cifsd_err("pthread_attr_init failed : %d\n", ret);
		goto out;
	}

	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (ret) {
		cifsd_err("pthread_attr_setdetachstate failed : %d\n", ret);
		goto out;
	}

	ret = pthread_create(&th, &attr, handle_inotify_request_event, msg);
	if (ret) {
		cifsd_err("pthread_attr_create failed : %d\n", ret);
		goto out;
	}

	ret = pthread_attr_destroy(&attr);
	if (ret) {
		cifsd_err("pthread_attr_destroy failed : %d\n", ret);
		goto out;
	}

out:
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

	case CIFSD_KEVENT_INOTIFY_REQUEST:
		ret = make_inotify_handler_thread(msg);
		break;

	default:
		cifsd_err("unknown event %u\n", ev->type);
		ret = -EINVAL;
		break;
	}

	return ret;
}
