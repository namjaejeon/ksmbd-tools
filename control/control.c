// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>

#include "ksmbdtools.h"
#include "version.h"

static void usage(void)
{
	fprintf(stderr, "Usage: ksmbd.control\n");

	fprintf(stderr, "\t-s | --shutdown\n");
	fprintf(stderr, "\t-d | --debug=all or [smb, auth, etc...]\n");
	fprintf(stderr, "\t-c | --cifsd-version\n");
	fprintf(stderr, "\t-V | --version\n");

	exit(EXIT_FAILURE);
}

static void show_version(void)
{
	printf("ksmbd-tools version : %s\n", KSMBD_TOOLS_VERSION);
	exit(EXIT_FAILURE);
}

static int ksmbd_control_shutdown(void)
{
	int fd, ret;

	fd = open("/sys/class/ksmbd-control/kill_server", O_WRONLY);
	if (fd < 0) {
		pr_err("open failed: %d\n", errno);
		return fd;
	}

	ret = write(fd, "hard", 4);
	if (ret < 0)
		return ret;

	close(fd);
}

static int ksmbd_control_show_version(void)
{
	int fd, ret;
	char ver[255];

	fd = open("/sys/class/ksmbd-control/version", O_RDONLY);
	if (fd < 0) {
		pr_err("open failed: %d\n", errno);
		return fd;
	}

	ret = read(fd, ver, 255);
	if (ret < 0)
		return ret;

	close(fd);
	pr_info("cifsd version : %s\n", ver);
}

static int ksmbd_control_debug(char *cmd)
{
	int fd, ret;
	char buf[255];

	fd = open("/sys/class/ksmbd-control/debug", O_WRONLY);
	if (fd < 0) {
		pr_err("open failed: %d\n", errno);
		return fd;
	}

	ret = write(fd, cmd, strlen(cmd));
	if (ret < 0)
		return ret;
	ret = read(fd, buf, 255);
	if (ret < 0)
		return ret;

	close(fd);

	printf("%s\n", buf);
}

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	int c, cmd = 0;
	char *section;

	set_logger_app_name("ksmbd.control");

	opterr = 0;
	while ((c = getopt(argc, argv, "sd:cV")) != EOF)
		switch (c) {
		case 's':
			ksmbd_control_shutdown();
			break;
		case 'd':
			section = g_strdup(optarg);
			ret = ksmbd_control_debug(section);
			break;
		case 'c':
			ret = ksmbd_control_show_version();
			break;
		case 'V':
			show_version();
			break;
		case '?':
		case 'h':
		default:
			usage();
	}

	return ret;
}
