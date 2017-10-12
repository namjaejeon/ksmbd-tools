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

static char *nlsk_rcv_buf = NULL;
static char *nlsk_send_buf = NULL;
static int nlsk_fd = -1;
static struct sockaddr_nl src_addr, dest_addr;

extern int request_handler(void *msg);
extern void initialize(void);

static int cifsd_sendmsg(struct cifsd_uevent *eev, unsigned int dlen,
		char *data)
{
	struct nlmsghdr *nlh;
	struct cifsd_uevent *ev;
	struct msghdr msg;
	struct iovec iov;
	int len;

	cifsd_debug("sending %u event\n", eev->type);
	nlh = (struct nlmsghdr *)nlsk_send_buf;
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
	msg.msg_name= (void*)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	len = sendmsg(nlsk_fd, &msg, 0);
	if (len == -1)
		perror("sendmsg");
	else if (len != nlh->nlmsg_len)
		cifsd_err("partial data send, expected %u, actual %u\n",
				nlh->nlmsg_len, len);
	return len;
}

int cifsd_common_sendmsg(struct cifsd_uevent *ev, char *buf,
		unsigned int buflen)
{
	int ret;

	if (buflen > NETLINK_CIFSD_MAX_PAYLOAD) {
		cifsd_err("too big(%u) buffer\n", buflen);
		return -1;
	}

	ret = cifsd_sendmsg(ev, buflen, buf);
	if (ret < 0)
		cifsd_err("failed to send event %u\n", ev->type);

	return ret;
}

static int handle_init_event(void)
{
	struct cifsd_uevent ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = CIFSD_UEVENT_INIT_CONNECTION;

	return cifsd_common_sendmsg(&ev, NULL, 0);
}

static int handle_exit_event(void)
{
	struct cifsd_uevent ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = CIFSD_UEVENT_EXIT_CONNECTION;

	return cifsd_common_sendmsg(&ev, NULL, 0);
}

static int cifsd_nl_read(char *buf, unsigned int buflen, int flags)
{
	int len;
	struct iovec iov;
	struct msghdr msg;

	iov.iov_base = buf;
	iov.iov_len = buflen;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	len = recvmsg(nlsk_fd, &msg, flags);
	if (len == -1)
		perror("recvmsg");
	else if (len != buflen)
		cifsd_err("partial data read, expected %u, actual %u\n",
				buflen, len);

	return len;
}

static int cifsd_handle_event(void)
{
	int len;
	struct cifsd_uevent *ev;
	struct nlmsghdr *nlh;

	len = cifsd_nl_read(nlsk_rcv_buf,
			NLMSG_SPACE(sizeof(struct cifsd_uevent)),
			MSG_PEEK);
	if (len != NLMSG_SPACE(sizeof(struct cifsd_uevent)))
		return -1;

	nlh = (struct nlmsghdr *)nlsk_rcv_buf;
	ev = (struct cifsd_uevent *)NLMSG_DATA(nlsk_rcv_buf);
	if (len != nlh->nlmsg_len && ev->buflen) {
		len = cifsd_nl_read(nlsk_rcv_buf, nlh->nlmsg_len, MSG_PEEK);
		if (len != nlh->nlmsg_len)
			return -1;
	}

	len = cifsd_nl_read(nlsk_rcv_buf, nlh->nlmsg_len, 0);
	if (len != nlh->nlmsg_len)
	{
		cifsd_err("failed to remove data\n");
		return -1;
	}

	return request_handler(nlh);
}

static void cifsd_nl_loop(void)
{
	fd_set readfds;
	int ret;

	for (;;) {
		/* add cifsd netlink socket fd to read fd list*/
		FD_ZERO(&readfds);
		FD_SET(nlsk_fd, &readfds);

		ret = select(nlsk_fd + 1, &readfds, NULL, NULL, NULL);
		if (ret == -1) {
			perror("select");
		}
		else {
			if (FD_ISSET(nlsk_fd, &readfds)) {
				cifsd_handle_event();
			}
		}
	}
}

int cifsd_nl_init(void)
{
	nlsk_rcv_buf = malloc(NETLINK_CIFSD_MAX_BUF);
	if (!nlsk_rcv_buf) {
		perror("can't alloc netlink buffer\n");
		return -1;
	}

	nlsk_send_buf = malloc(NETLINK_CIFSD_MAX_BUF);
	if (!nlsk_send_buf) {
		perror("can't alloc netlink buffer\n");
		goto free_rcv_buf;
	}

	nlsk_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_CIFSD);
	if (nlsk_fd < 0) {
		perror("Failed to create netlink socket\n");
		goto free_send_buf;
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();

	if (bind(nlsk_fd, (struct sockaddr *)&src_addr, sizeof(src_addr))) {
		perror("Failed to bind netlink socket\n");
		goto close_sock;
	}

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; /* kernel */
	return 0;

close_sock:
	close(nlsk_fd);
free_send_buf:
	free(nlsk_send_buf);
free_rcv_buf:
	free(nlsk_rcv_buf);
	return -1;
}

int cifsd_nl_exit(void)
{
	if (nlsk_fd >= 0)
		close(nlsk_fd);

	if (nlsk_send_buf)
		free(nlsk_send_buf);

	if (nlsk_rcv_buf)
		free(nlsk_rcv_buf);
	return 0;
}

int cifsd_netlink_setup(void)
{
	if (cifsd_nl_init())
		return -1;

	initialize();
	handle_init_event();

	cifsd_nl_loop();

	handle_exit_event();
	cifsd_nl_exit();
	return 0;
}
