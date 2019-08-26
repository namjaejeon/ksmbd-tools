// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2019 Samsung Electronics Co., Ltd.
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

#include <config_parser.h>
#include <cifsdtools.h>

#include <management/share.h>
#include <linux/cifsd_server.h>
#include <share_admin.h>

static char *arg_name;
static char *arg_opts;

enum {
	COMMAND_ADD_SHARE = 1,
	COMMAND_DEL_SHARE,
	COMMAND_UPDATE_SHARE,
};

static void usage(void)
{
	int i;

	fprintf(stderr, "cifsd-tools version : %s\n", CIFSD_TOOLS_VERSION);
	fprintf(stderr, "Usage: cifsshareadd\n");

	fprintf(stderr, "\t-a | --add-share=share\n");
	fprintf(stderr, "\t-d | --del-share=share\n");
	fprintf(stderr, "\t-u | --update-share=share\n");
	fprintf(stderr, "\t-o | --options=\"op1=val1 op2=val2...\"\n");

	fprintf(stderr, "\t-c smb.conf\n");
	fprintf(stderr, "\t-v | --verbose\n");

	fprintf(stderr, "Supported share options:\n");
	for (i = 0; i < CIFSD_SHARE_CONF_MAX; i++)
		fprintf(stderr,"\t%s\n", CIFSD_SHARE_CONF[i]);
	exit(EXIT_FAILURE);
}

static void notify_cifsd_daemon(int command)
{
	char manager_pid[10] = {0, };
	int pid = 0;
	int lock_fd;

	/*
	 * We support only 'add share' at this point.
	 */
	if (command == COMMAND_DEL_SHARE || command == COMMAND_UPDATE_SHARE)
		return;

	lock_fd = open(CIFSD_LOCK_FILE, O_RDONLY);
	if (lock_fd < 0)
		return;

	if (read(lock_fd, &manager_pid, sizeof(manager_pid)) == -1) {
		pr_debug("Unable to read main PID: %s\n", strerr(errno));
		close(lock_fd);
		return;
	}

	close(lock_fd);

	pid = cp_get_group_kv_long_base(manager_pid, 10);

	pr_debug("Send SIGHUP to pid %d\n", pid);
	if (kill(pid, SIGHUP))
		pr_debug("Unable to send signal to pid %d: %s\n",
			 pid, strerr(errno));
}

static int test_access(char *conf)
{
	int fd = open(conf, O_RDWR | O_CREAT, S_IRWXU | S_IRGRP);

	if (fd != -1) {
		close(fd);
		return 0;
	}

	pr_err("%s %s\n", conf, strerr(errno));
	return -EINVAL;
}

static int parse_configs(char *smbconf)
{
	int ret;

	ret = test_access(smbconf);
	if (ret)
		return ret;

	ret = cp_smbconfig_hash_create(smbconf);
	if (ret)
		return ret;
	return 0;
}

static int sanity_check_share_name_simple(char *name)
{
	int sz, i;

	if (!name)
		return -EINVAL;

	sz = strlen(name);
	if (sz < 1)
		return -EINVAL;
	if (sz >= CIFSD_REQ_MAX_SHARE_NAME)
		return -EINVAL;

	if (!cp_key_cmp(name, "global"))
		return -EINVAL;

	for (i = 0; i < sz; i++) {
		if (isalnum(name[i]))
			return 0;
	}
	return -EINVAL;
}

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	char *smbconf = PATH_SMBCONF;
	int c, cmd = 0;

	set_logger_app_name("cifsshareadd");

	opterr = 0;
	while ((c = getopt(argc, argv, "i:a:d:u:p:o:vh")) != EOF)
		switch (c) {
		case 'a':
			arg_name = g_ascii_strdown(optarg, strlen(optarg));
			cmd = COMMAND_ADD_SHARE;
			break;
		case 'd':
			arg_name = g_ascii_strdown(optarg, strlen(optarg));
			cmd = COMMAND_DEL_SHARE;
			break;
		case 'u':
			arg_name = g_ascii_strdown(optarg, strlen(optarg));
			cmd = COMMAND_UPDATE_SHARE;
			break;
		case 'i':
			smbconf = strdup(optarg);
			break;
		case 'o':
			arg_opts = strdup(optarg);
			break;
		case 'v':
			break;
		case '?':
		case 'h':
		default:
			usage();
	}

	if (cmd != COMMAND_DEL_SHARE && !arg_opts) {
		usage();
		return -1;
	}

	if (sanity_check_share_name_simple(arg_name)) {
		pr_err("share name sanity check failure\n");
		goto out;
	}

	if (!smbconf) {
		pr_err("Out of memory\n");
		goto out;
	}

	ret = parse_configs(smbconf);
	if (ret) {
		pr_err("Unable to parse configuration files\n");
		goto out;
	}

	if (cmd == COMMAND_ADD_SHARE)
		ret = command_add_share(smbconf, arg_name, arg_opts);
	if (cmd == COMMAND_DEL_SHARE)
		ret = command_del_share(smbconf, arg_name);
	if (cmd == COMMAND_UPDATE_SHARE)
		ret = command_update_share(smbconf, arg_name, arg_opts);

	if (ret == 0)
		notify_cifsd_daemon(cmd);
out:
	cp_smbconfig_destroy();
	return ret;
}
