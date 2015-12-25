/*
 *   cifssrv-tools/cifsstat.c
 *
 *   Copyright (C) 2015 Samsung Electronics Co., Ltd.
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

/* global definitions */
#define PATH_CIFSSRV_STAT "/sys/fs/cifssrv/stat"
#define LINESZ 4096
#define MAX_IPLEN 16

#define SERVER_STAT 1
#define CLIENT_STAT 2

/**
 * rstat() - reads data from cifssrv statistics control interface
 * @dst:	destination buffer to copy statistics data
 * @sz:	length of statistics data to read
 *
 * Return:	length of data copied to dst buffer
 */
int rstat(char *dst, int sz)
{
	FILE *fdstat;
	int rc;

	fdstat = fopen(PATH_CIFSSRV_STAT, "r");
	if (!fdstat) {
		fprintf(stdout, "cifssrv not available\n");
		return 0;
	}

	rc = fread(dst, 1, sz, fdstat);

	fclose(fdstat);

	return rc;
}

/**
 * wstat() - writes data to cifssrv statistics control interface
 * @src:	source buffer containing data to write
 * @sz:	length of statistics data write
 *
 * Return:	length of data written to cifssrv interface
 */
int wstat(char *src, int sz)
{
	FILE *fdstat;
	int rc = 1;

	fdstat = fopen(PATH_CIFSSRV_STAT, "w");
	if (!fdstat) {
		fprintf(stdout, "cifssrv not available\n");
		return 0;
	}

	if (fwrite(src, 1, sz, fdstat) != sz) {
		fprintf(stdout, "%d: file operation failed\n", __LINE__);
		rc = 0;
	}

	fclose(fdstat);

	return rc;
}

/**
 * valIP() - utility function to validate IP address
 * @src:	source buffer containing IP to verify
 *
 * Return:	success: "IP address length"; fail: 0
 */
int valIP(char *src)
{
	int len = strnlen(src, MAX_IPLEN);
	char token[5] = ". \t\n";
	int chcnt;
	int dcnt = 0;
	int sz = 0, sz1;
	int i;

	if (len >= MAX_IPLEN)
		return 0;

	while (sz < len && dcnt < 3) {
		sz1 = strcspn(src+sz, token);
		if (!sz1)
			return 0;

		for (i = sz, chcnt = 0; i < sz + sz1; i++) {
			if (src[i] >= 0x30 && src[i] <= 0x39)
				chcnt++;
			else
				return 0;
		}

		if (chcnt <= 3 && src[i] == 0x2e) {
			sz += sz1+1;
			dcnt++;
			continue;
		} else
			return 0;
	}

	if ((dcnt != 3) || (sz == len))
		return 0;

	for (i = sz, chcnt = 0; i < len; i++) {
		if (src[i] >= 0x30 && src[i] <= 0x39)
			chcnt++;
		else
			return 0;
	}

	if (chcnt <= 3)
		return len;

	return 0;
}

/**
 * process_args() - helper function to process commandline arguments
 * @flags:	user selected option to process
 * @client:	client IP under request
 * @sz:	length of client IP address
 *
 * Return:	success: 1; fail: 0
 */
int process_args(int flags, char *client, int sz)
{
	char rbuf[LINESZ];
	char *construct;
	int rc;

	while (flags) {
		if (flags & SERVER_STAT) {
			int len = strlen("SERVER_STAT") + 1;

			construct = malloc(len);
			if (!construct)
				return 0;

			memset(rbuf, 0, LINESZ);
			memset(construct, 0, len);

			strncpy(construct, "SERVER_STAT", len-1);

			if (!wstat(construct, len)) {
				free(construct);
				return 0;
			}
			free(construct);

			memset(rbuf, 0, LINESZ);
			rc = rstat(rbuf, LINESZ-1);
			if (rc < 0) {
				fprintf(stdout, "%d: file operation failed\n",
					__LINE__);
				return 0;
			} else if (rc == 0)
				fprintf(stdout, "server info not found\n");
			else {
				fprintf(stdout, "Server stats\n");
				fprintf(stdout, "%s", rbuf);
			}

			flags &= ~SERVER_STAT;
		}

		if (flags & CLIENT_STAT) {
			int len = strlen("CLIENT_STAT:") + sz + 1;

			construct = malloc(len);
			if (!construct)
				return 0;

			memset(rbuf, 0, LINESZ);
			memset(construct, 0, len);

			strncpy(construct, "CLIENT_STAT:", len-(sz+1));
			strncat(construct, client, sz);

			if (!wstat(construct, len)) {
				free(construct);
				return 0;
			}
			free(construct);

			memset(rbuf, 0, LINESZ);
			rc = rstat(rbuf, LINESZ-1);
			if (rc < 0) {
				fprintf(stdout, "%d: file operation failed\n",
					__LINE__);
				return 0;
			} else if (rc == 0)
				fprintf(stdout, "client-%s stats not found\n",
					client);
			else {
				fprintf(stdout, "Client stats for : %s\n",
					client);
				fprintf(stdout, "%s", rbuf);
			}

			flags &= ~CLIENT_STAT;
		}
	}

	return 1;
}

/**
 * help() - function to show menu options to user
 */
void help(void)
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
 * Return:	success/fail: 0
 */
int main(int argc, char *argv[])
{
	char client[MAX_IPLEN];
	int flags = 0;
	int sz = 0;

	memset(client, 0, MAX_IPLEN);

	if (argc < 2 || !strncmp(argv[1], "-h", 2)) {
		help();
		return 0;
	}

	if (argc > 4) {
		fprintf(stdout, "Too many arguments, exiting\n");
		help();
		return 0;
	}

	if (!strncmp(argv[1], "-s", 2)) {
		if (argc > 3) {
			if (!strncmp(argv[2], "-c", 2)) {
				sz = valIP(argv[3]);
				if (sz > 0) {
					strncpy(client, argv[3], sz);
					flags |= CLIENT_STAT;
				} else {
					fprintf(stdout,
						"Invalid client IP, exiting\n");
					return 0;
				}
			} else {
				fprintf(stdout,
					"Invalid flag combination, exiting\n");
				help();
				return 0;
			}
		}

		flags |= SERVER_STAT;
	} else if (!strncmp(argv[1], "-c", 2)) {
		if (argc < 3) {
			fprintf(stdout, "-c flag requires client IP\n");
			help();
			return 0;
		}

		if (argc > 3) {
			if (!strncmp(argv[3], "-s", 2))
				flags |= SERVER_STAT;
			else {
				fprintf(stdout,
					"Invalid flag combination, exiting\n");
				help();
				return 0;
			}
		}

		sz = valIP(argv[2]);
		if (sz > 0) {
			strncpy(client, argv[2], sz);
			flags |= CLIENT_STAT;
		} else {
			fprintf(stdout, "Invalid client IP, exiting\n");
			return 0;
		}

	}

	if (!process_args(flags, client, sz))
		fprintf(stdout, "Unable to process request, try again\n");

	return 0;
}
