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

/* global definitions */
#define PATH_STATS "/sys/fs/cifsd/stat"
#define BUF_SIZE 4096

#ifdef IPV6_SUPPORTED
#define MAX_IPLEN 128
#else
#define MAX_IPLEN 16
#endif


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
 * process_args() - helper function to process commandline arguments
 * @flags:	user selected option to process
 * @client:	client IP under request
 * @sz:	length of client IP address
 *
 * Return:	success: 0; fail: -1
 */
int process_args(int flags, char *client, int size)
{
	if (flags & O_SERVER) {
		if (setstatopt(OPT_SERVER, strlen(OPT_SERVER)))
			return -1;
		if (getstats("Server"))
			return -1;
		flags &= ~O_SERVER;
	}

	if (flags & O_CLIENT) {
		if (setstatopt(client, size))
			return -1;
		if (getstats("Client"))
			return -1;
		flags &= ~O_CLIENT;
	}

	return 0;
}

/**
 * usage() - function to show menu options to user
 */
void usage(void)
{
	fprintf(stdout, "Usage: cifsstat [options]\n"
			"options:\n"
			"	-h help\n"
			"	-s show server stat\n"
			"	-c <client IP> show client stat\n");
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
	if (process_args(flags, client, strlen(client)))
		fprintf(stdout, "Unable to process request, try again\n");

	return 0;
}
