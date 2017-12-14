/*
 *   cifsd-tools/cifsd/netlink.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "netlink.h"

static int cifsd_sendmsg(struct nl_sock *nlsock, struct cifsd_uevent *eev,
		unsigned int dlen, char *data)
{
	struct nlmsghdr *nlh;
	struct cifsd_uevent *ev;
	struct msghdr msg;
	struct iovec iov;
	int len;

	cifsd_debug("sending %u event\n", eev->type);
	nlh = (struct nlmsghdr *)nlsock->nlsk_send_buf;
	memset(nlh, 0, NETLINK_CIFSD_MAX_BUF);
	nlh->nlmsg_len = NLMSG_SPACE(sizeof(*ev));
	nlh->nlmsg_type = eev->type;
	nlh->nlmsg_pid = getpid();
	memcpy(NLMSG_DATA(nlh), eev, sizeof(*ev));
	ev = (struct cifsd_uevent *)NLMSG_DATA(nlh);

	if (dlen) {
		memcpy(ev->buffer, data, dlen);
		nlh->nlmsg_len += dlen;
	}

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&nlsock->dest_addr;
	msg.msg_namelen = sizeof(nlsock->dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	len = sendmsg(nlsock->nlsk_fd, &msg, 0);
	if (len == -1)
		perror("sendmsg");
	else if (len != nlh->nlmsg_len)
		cifsd_err("partial data send, expected %u, actual %u\n",
				nlh->nlmsg_len, len);
	return len;
}

int cifsd_common_sendmsg(struct nl_sock *nlsock, struct cifsd_uevent *ev,
		char *buf, unsigned int buflen)
{
	int ret;

	if (buflen > NETLINK_CIFSD_MAX_PAYLOAD) {
		cifsd_err("too big(%u) buffer\n", buflen);
		return -1;
	}

	ret = cifsd_sendmsg(nlsock, ev, buflen, buf);
	if (ret < 0)
		cifsd_err("failed to send event %u\n", ev->type);

	return ret;
}

int nl_handle_init_cifsd(struct nl_sock *nlsock)
{
	struct cifsd_uevent ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = CIFSD_UEVENT_INIT_CONNECTION;

	return cifsd_common_sendmsg(nlsock, &ev, NULL, 0);
}

int nl_handle_exit_cifsd(struct nl_sock *nlsock)
{
	struct cifsd_uevent ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = CIFSD_UEVENT_EXIT_CONNECTION;

	return cifsd_common_sendmsg(nlsock, &ev, NULL, 0);
}

static int cifsd_nl_read(struct nl_sock *nlsock,
		char *buf, unsigned int buflen, int flags)
{
	int len;
	struct iovec iov;
	struct msghdr msg;

	iov.iov_base = buf;
	iov.iov_len = buflen;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&nlsock->src_addr;
	msg.msg_namelen = sizeof(nlsock->src_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	len = recvmsg(nlsock->nlsk_fd, &msg, flags);
	if (len == -1)
		perror("recvmsg");
	else if (len != buflen)
		cifsd_err("partial data read, expected %u, actual %u\n",
				buflen, len);
	return len;
}

int nl_handle_event(struct nl_sock *nlsock)
{
	int len;
	struct cifsd_uevent *ev;
	struct nlmsghdr *nlh;

	len = cifsd_nl_read(nlsock, nlsock->nlsk_rcv_buf,
			NLMSG_SPACE(sizeof(struct cifsd_uevent)),
			MSG_PEEK);
	if (len != NLMSG_SPACE(sizeof(struct cifsd_uevent)))
		return -1;
	nlh = (struct nlmsghdr *)nlsock->nlsk_rcv_buf;
	ev = (struct cifsd_uevent *)NLMSG_DATA(nlsock->nlsk_rcv_buf);
	if (len != nlh->nlmsg_len && ev->buflen) {
		len = cifsd_nl_read(nlsock, nlsock->nlsk_rcv_buf,
					nlh->nlmsg_len, MSG_PEEK);
		if (len != nlh->nlmsg_len)
			return -1;
	}

	len = cifsd_nl_read(nlsock, nlsock->nlsk_rcv_buf, nlh->nlmsg_len, 0);
	if (len != nlh->nlmsg_len) {
		cifsd_err("failed to remove data\n");
		return -1;
	}

	return (int)(nlsock->event_handle_cb)(nlsock);
}

struct nl_sock *nl_init()
{
	struct nl_sock *nlsock;

	nlsock = malloc(sizeof(struct nl_sock));
	nlsock->nlsk_rcv_buf = malloc(NETLINK_CIFSD_MAX_BUF);
	if (!nlsock->nlsk_rcv_buf) {
		perror("can't alloc netlink buffer\n");
		return NULL;
	}

	nlsock->nlsk_send_buf = malloc(NETLINK_CIFSD_MAX_BUF);
	if (!nlsock->nlsk_send_buf) {
		perror("can't alloc netlink buffer\n");
		goto free_rcv_buf;
	}

	nlsock->nlsk_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_CIFSD);
	if (nlsock->nlsk_fd < 0) {
		perror("Failed to create netlink socket\n");
		goto free_send_buf;
	}

	memset(&nlsock->src_addr, 0, sizeof(nlsock->src_addr));
	nlsock->src_addr.nl_family = AF_NETLINK;
	nlsock->src_addr.nl_pid = getpid();

	if (bind(nlsock->nlsk_fd, (struct sockaddr *)&nlsock->src_addr,
		sizeof(nlsock->src_addr))) {
		perror("Failed to bind netlink socket\n");
		goto close_sock;
	}

	memset(&nlsock->dest_addr, 0, sizeof(nlsock->dest_addr));
	nlsock->dest_addr.nl_family = AF_NETLINK;
	nlsock->dest_addr.nl_pid = 0; /* kernel */
	return nlsock;

close_sock:
	close(nlsock->nlsk_fd);
free_send_buf:
	free(nlsock->nlsk_send_buf);
free_rcv_buf:
	free(nlsock->nlsk_rcv_buf);
	return NULL;
}

void nl_loop(struct nl_sock *nlsock)
{
	fd_set readfds;
	int ret;

	for (;;) {
		/* add cifsd netlink socket fd to read fd list*/
		FD_ZERO(&readfds);
		FD_SET(nlsock->nlsk_fd, &readfds);

		ret = select(nlsock->nlsk_fd + 1, &readfds, NULL, NULL, NULL);
		if (ret == -1) {
			perror("select");
		} else {
			if (FD_ISSET(nlsock->nlsk_fd, &readfds))
				nl_handle_event(nlsock);
		}
	}
}

int nl_exit(struct nl_sock *nlsock)
{
	if (nlsock->nlsk_fd >= 0)
		close(nlsock->nlsk_fd);

	if (nlsock->nlsk_send_buf)
		free(nlsock->nlsk_send_buf);

	if (nlsock->nlsk_rcv_buf)
		free(nlsock->nlsk_rcv_buf);
	return 0;

}
