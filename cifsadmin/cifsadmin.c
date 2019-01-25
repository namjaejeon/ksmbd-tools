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

#include <config_parser.h>
#include <cifsdtools.h>

#include <management/user.h>
#include <management/share.h>
#include <user_admin.h>

static char *arg_account = NULL;
static char *arg_password = NULL;

enum {
	COMMAND_ADD_USER = 1,
	COMMAND_DEL_USER,
	COMMAND_UPDATE_USER,
};

static void usage(void)
{
	fprintf(stderr, "cifsd-tools version : %s, date : %s\n",
			CIFSD_TOOLS_VERSION,
			CIFSD_TOOLS_DATE);
	fprintf(stderr, "Usage: cifsd_admin\n");

	fprintf(stderr, "\t-a | --add-user=login\n");
	fprintf(stderr, "\t-d | --del-user=login\n");
	fprintf(stderr, "\t-u | --update-user=login\n");
	fprintf(stderr, "\t-p | --password=pass\n");

	fprintf(stderr, "\t-i cifspwd.db | --import-users=cifspwd.db\n");
	fprintf(stderr, "\t-v | --verbose\n");

	exit(EXIT_FAILURE);
}

static void notify_cifsd_daemon(int command)
{
	char manager_pid[10] = {0, };
	int pid = 0;
	int lock_fd;

	/*
	 * We support only add/update user at this point.
	 */
	if (command == COMMAND_DEL_USER)
		return;

	lock_fd = open(CIFSD_LOCK_FILE, O_RDONLY);
	if (lock_fd < 0) {
		pr_debug("Unalde to read lock file: %s\n", strerror(errno));
		return;
	}

	if (read(lock_fd, &manager_pid, sizeof(manager_pid)) == -1) {
		pr_debug("Unable to read main PID: %s\n", strerror(errno));
		return;
	}

	close(lock_fd);

	pid = cp_get_group_kv_long_base(manager_pid, 10);

	pr_debug("Send SIGHUP to pid %d\n", pid);
	if (kill(pid, SIGHUP))
		pr_debug("Unable to send siangl to pid %d: %s\n",
			 pid, strerror(errno));
}

static int test_access(char *conf)
{
	int fd = open(conf, O_RDWR | O_CREAT, S_IRWXU | S_IRGRP);

	if (fd != -1) {
		close(fd);
		return 0;
	}

	pr_err("%s %s\n", conf, strerror(errno));
	return -EINVAL;
}

static int parse_configs(char *pwddb)
{
	int ret;

	ret = test_access(pwddb);
	if (ret)
		return ret;

	ret = cp_parse_pwddb(pwddb);
	if (ret)
		return ret;
	return 0;
}

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	char *pwddb = PATH_PWDDB;
	int c, cmd = 0;

	set_logger_app_name("cifsdadmin");

	opterr = 0;
	while ((c = getopt(argc, argv, "c:i:a:d:u:p:vh")) != EOF)
		switch (c) {
		case 'a':
			arg_account = strdup(optarg);
			cmd = COMMAND_ADD_USER;
			break;
		case 'd':
			arg_account = strdup(optarg);
			cmd = COMMAND_DEL_USER;
			break;
		case 'u':
			arg_account = strdup(optarg);
			cmd = COMMAND_UPDATE_USER;
			break;
		case 'p':
			arg_password = strdup(optarg);
			break;
		case 'i':
			pwddb = strdup(optarg);
			break;
		case 'v':
			break;
		case '?':
		case 'h':
		default:
			usage();
	}

	if (!pwddb) {
		pr_err("Out of memory\n");
		goto out;
	}

	ret = usm_init();
	if (ret) {
		pr_err("Failed to init user management\n");
		goto out;
	}

	ret = shm_init();
	if (ret) {
		pr_err("Failed to init net share management\n");
		goto out;
	}

	ret = parse_configs(pwddb);
	if (ret) {
		pr_err("Unable to parse configuration files\n");
		goto out;
	}

	if (cmd == COMMAND_ADD_USER)
		ret = command_add_user(pwddb, arg_account, arg_password);
	if (cmd == COMMAND_DEL_USER)
		ret = command_del_user(pwddb, arg_account);
	if (cmd == COMMAND_UPDATE_USER)
		ret = command_update_user(pwddb, arg_account, arg_password);

	if (ret == 0)
		notify_cifsd_daemon(cmd);
out:
	shm_destroy();
	usm_destroy();
	return ret;
}
