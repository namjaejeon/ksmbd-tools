/*
 *   cifsd-tools/cifsstat.c
 *
 *   Copyright (C) 2015 Samsung Electronics Co., Ltd.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

#include "cifsd.h"
#include "netlink.h"

/* global definitions */
#define PATH_STATS "/sys/fs/cifsd/stat"
#define BUF_SIZE 4096

#define OPT_SERVER "1"

#define O_SERVER 1
#define O_CLIENT 2

/**
 * readstat() - reads data from cifsd statistics control interface
 * @buf:	destination buffer to copy statistics data
 * @size:	length of statistics data to read
 *
 * Return:	success: length of data copied to dst buffer; fail: -1
 */
int readstat(char *buf, int size)
{
	FILE *fp;
	int rc;

	fp = fopen(PATH_STATS, "r");
	if (!fp) {
		fprintf(stdout, "Not able to open (%s) for read, err(%d)\n",
					PATH_STATS, errno);
		return -1;
	}

	rc = fread(buf, sizeof(char), size, fp);

	fclose(fp);

	return rc;
}

/**
 * setstatopt() - writes data to cifsd statistics control interface
 *	       Needed during read stat, to check if the request is
 *		for server stats or specific client stat
 * @opt:	buffer for setting stat option
 *		"1" in case of server and
 *		valid ip address in case of client
 * @size:	bytes to write as per option
 *
 * Return:	success: 0; fail: -1
 */
int setstatopt(char *opt, int size)
{
	FILE *fp;
	int rc = 0;

	fp = fopen(PATH_STATS, "w");
	if (!fp) {
		fprintf(stdout, "Not able to open (%s) for write, err(%d)\n",
					PATH_STATS, errno);
		return -1;
	}

	if (fwrite(opt, sizeof(char), size, fp) != size) {
		fprintf(stdout, "Failed to set stat (%s) on %s\n",
				opt, PATH_STATS);
		rc = -1;
	}

	fclose(fp);

	return rc;
}

/**
 * getstats() - reads stats from CIFSSRSV sysfs interface
 * @node:    either server/client which object to consider for reading stats
 *
 * Return:	0 on success and -1 on failure
 */

int getstats(char *node)
{
	char *buffer;
	int rc;

	buffer = calloc(BUF_SIZE, sizeof(char));
	if (!buffer) {
		fprintf(stdout,"Failed to allocate memory for stat buffer\n");
		return -1;
	}

	rc = readstat(buffer, BUF_SIZE-1);
	if (rc < 0) {
		fprintf(stdout, "%s : readstat failed, err(%d)\n", node, errno);
		free(buffer);
		return -1;
	} else if (rc == 0)
		fprintf(stdout, "(%s) info not found\n", node);
	else {
		fprintf(stdout, "%s stats:\n", node);
		fprintf(stdout, "%s", buffer);
	}
	free(buffer);
	return 0;
}

/**
 * is_validIP() - utility function to validate IP address
 * @ipaddr:	source buffer containing IP to verify
 *
 * Return:	0 for invalid IP, 1 for valid
 */
int is_validIP(char *ipaddr)
{
	struct sockaddr_in sa;
	int result;
	result = inet_pton(AF_INET, ipaddr, &(sa.sin_addr));
	if (result == 0) {
#ifdef IPV6_SUPPORTED
		result = inet_pton(AF_INET6, ipaddr, &(sa.sin_addr));
#endif
	}
	return result != 0;
}

/**
 * handle_cifsstat_read_event() - get server/client stats using
 *				netlink socket
 * @nlsock:	netlink socket for cifsstat connection
 *
 * Return:	0 on success, otherwise error
 */
static int handle_cifsstat_read_event(struct nl_sock *nlsock)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)nlsock->nlsk_rcv_buf;
	struct cifsd_uevent *ev = NLMSG_DATA(nlh);
	int flag = ev->k.r_stat.flag;
	int err = ev->error;

	if (err < 0) {
		if (flag & O_SERVER)
			cifsd_err("Server stat info: failed, err %d\n", err);

		if (flag & O_CLIENT)
			cifsd_err("CLient stat info: failed, err %d\n", err);
		goto out;
	}

	if (ev->buflen) {
		if (flag & O_SERVER)
			fprintf(stdout, "Server stats:\n%s", ev->buffer);

		if (flag & O_CLIENT)
			fprintf(stdout, "Client stats:\n%s", ev->buffer);
	}

out:
	return err;
}

/**
 * cifsstat_request_handler() - cifsstat netlink command handler
 * @nlsock:	netlink socket for cifsstat connection
 *
 * Return:	0 on success, otherwise error
 */
int cifsstat_request_handler(struct nl_sock *nlsock)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)nlsock->nlsk_rcv_buf;
	struct cifsd_uevent *ev = NLMSG_DATA(nlh);
	int ret = 0;

	cifsd_debug("start cifsstat event\n");
	switch (nlh->nlmsg_type) {
	case CIFSSTAT_UEVENT_READ_STAT_RSP:
		ret = handle_cifsstat_read_event(nlsock);
		break;

	default:
		cifsd_err("unknown event %u\n", ev->type);
		ret = -EINVAL;
		break;
	}
	return ret;
}

/**
 * cifsstat_process_args() - helper function to process cifsd events
 * @nlsock:	for netlink socket communication
 * @ev:		cifsd_uevent for sending request with event type
 * @buf:	containing message to send over netlink socket
 * @buflen:	length of buf
 *
 * Return:	success: 0; fail: -1
 */
int cifsstat_process_args(struct nl_sock *nlsock, struct cifsd_uevent *ev,
	char *buf, int buflen)
{
	if (cifsd_common_sendmsg(nlsock, ev, buf, buflen) < 0) {
		cifsd_err("cifsd event sending failed\n");
		return -1;
	}
	nlsock->event_handle_cb = cifsstat_request_handler;
	return nl_handle_event(nlsock);
}
/**
 * process_args() - helper function to process commandline arguments
 * @flags:	user selected option to process
 * @client:	client IP under request
 * @sz:	length of client IP address
 *
 * Return:	success: 0; fail: -1
 */
int process_args(int flags, char *client, int size)
{
	struct cifsd_uevent ev;
	struct nl_sock *nlsock = nl_init();
	int ret = 0;

	if (!nlsock) {
		cifsd_err("Failed to allocate memory for netlink socket\n");
		return -ENOMEM;
	}

	nl_handle_init_cifsstat(nlsock);
	memset(&ev, 0, sizeof(ev));

	if (flags & O_SERVER) {
		ev.type = CIFSSTAT_UEVENT_READ_STAT;
		ev.k.r_stat.flag = O_SERVER;
		ret = cifsstat_process_args(nlsock, &ev, NULL, 0);
		if (ret < 0)
			cifsd_err("server stat info: failed\n");
		flags &= ~O_SERVER;
	}

	if (flags & O_CLIENT) {
		ev.type = CIFSSTAT_UEVENT_READ_STAT;
		ev.k.r_stat.flag = O_CLIENT;
		strncpy(ev.k.r_stat.statip, client, strlen(client));
		ret = cifsstat_process_args(nlsock, &ev, NULL, 0);
		if (ret < 0)
			cifsd_err("client stat info: failed\n");
		flags &= ~O_CLIENT;
	}

	nl_exit(nlsock);
	return ret;
}

/**
 * usage() - function to show menu options to user
 */
void usage(void)
{
	fprintf(stdout, "cifsd-tools version : %s, date : %s\n"
			"Usage: cifsstat [options]\n"
			"options:\n"
			"	-h help\n"
			"	-s show server stat\n"
			"	-c <client IP> show client stat\n",
			CIFSD_TOOLS_VERSION, CIFSD_TOOLS_DATE);
}

/**
 * main() - entry point of application
 * @argc:	commandline argument count
 * @argv:	commandline argument list
 *
 * Return:	success '0', fail exit with EXIT_FAILURE
 */
int main(int argc, char *argv[])
{
	char client[MAX_IPLEN];
	int flags = 0, opt;

	memset(client, 0, MAX_IPLEN);

	while ((opt = getopt(argc, argv, "hsc:")) != -1) {
		switch (opt) {
			case 's':
				flags |= O_SERVER;
				break;
			case 'c':
				if (is_validIP(optarg)) {
					strncpy(client, optarg, MAX_IPLEN - 1);
					flags |= O_CLIENT;
				} else {
					fprintf(stdout,
							"Invalid client IP, exiting\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 'h':
			default: /* '?' */
				usage();
				exit(EXIT_FAILURE);
		}
	}
	if (process_args(flags, client, strlen(client)) < 0)
		fprintf(stdout, "Unable to process request, try again\n");

	return 0;
}
