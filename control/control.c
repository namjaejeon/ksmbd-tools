// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2020 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <getopt.h>
#include <fcntl.h>
#include <errno.h>

#include "ksmbdtools.h"
#include "version.h"

/* From linux/fs/ksmbd/server.c */
static const char *const debug_types[] = {
	"smb", "auth", "vfs",
	"oplock", "ipc", "conn",
	"rdma"
};

static void usage(void)
{
	int i;

	fprintf(stderr, "Usage: ksmbd.control\n");
	fprintf(stderr, "\t-s | --shutdown\n");
	fprintf(stderr, "\t-d | --debug=all or [");
	for (i = 0; i < sizeof(debug_types) / sizeof(debug_types[0]); i++)
		fprintf(stderr, "%s ", debug_types[i]);
	fprintf(stderr, "]\n");
	fprintf(stderr, "\t-c | --ksmbd-version\n");
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

	terminate_ksmbd_daemon();

	fd = open("/sys/class/ksmbd-control/kill_server", O_WRONLY);
	if (fd < 0) {
		pr_err("open failed (%d), is ksmbd.ko loaded?\n", errno);
		return fd;
	}

	ret = write(fd, "hard", 4);
	close(fd);

	if (ret != 4)
		pr_err("failed to send shutdown to ksmbd module\n");

	return ret != 4;
}

static void ksmbd_control_show_version(void)
{
	int fd, ret;
	char ver[255] = {0};

	fd = open("/sys/module/ksmbd/version", O_RDONLY);
	if (fd < 0) {
		pr_err("open failed (%d), is ksmbd.ko loaded?\n", errno);
		return;
	}

	ret = read(fd, ver, 255);
	close(fd);

	if (ret != -1)
		pr_info("ksmbd version : %s\n", ver);
	else
		pr_err("error getting ksmbd version from module\n");
}

static int ksmbd_control_debug(char *type)
{
	int fd, ret;
	char buf[255] = {0};

	fd = open("/sys/class/ksmbd-control/debug", O_RDWR);
	if (fd < 0) {
		pr_err("open failed (%d), is ksmbd.ko loaded?\n", errno);
		return fd;
	}

	ret = write(fd, type, strlen(type));
	if (ret < 0)
		goto out;
	ret = read(fd, buf, 255);
	if (ret < 0)
		goto out;

out:
	if (ret < 0)
		pr_err("read/write failed: %d\n", errno);
	else
		pr_info("%s\n", buf);

	close(fd);
	return ret > 0 ? 0 : ret;
}

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	int c;

	if (argc < 2)
		usage();

	set_logger_app_name("ksmbd.control");

	if (getuid() != 0) {
		pr_err("Please try running as root.\n");
		return ret;
	}

	opterr = 0;
	while ((c = getopt(argc, argv, "sd:cVh")) != EOF)
		switch (c) {
		case 's':
			ret = ksmbd_control_shutdown();
			break;
		case 'd':
			ret = ksmbd_control_debug(optarg);
			break;
		case 'c':
			ksmbd_control_show_version();
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
