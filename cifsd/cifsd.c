/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
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

#include <cifsdtools.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#include <config_parser.h>

#include <ipc.h>
#include <rpc.h>
#include <worker.h>
#include <management/user.h>
#include <management/share.h>
#include <management/session.h>
#include <management/tree_conn.h>

static pid_t worker_pid;
static int lock_fd;
static char *pwddb = PATH_PWDDB;
static char *smbconf = PATH_SMBCONF;

#define LOCK_FILE "/tmp/cifsd.lock"

extern const char * const sys_siglist[];
typedef int (*worker_fn)(void);

static void usage(void)
{
	fprintf(stderr, "cifsd-tools version : %s, date : %s\n",
		CIFSD_TOOLS_VERSION,
		CIFSD_TOOLS_DATE);
	fprintf(stderr, "Usage: cifsd\n");
	fprintf(stderr, "\t-c smb.conf | --config=smb.conf\n");
	fprintf(stderr, "\t-i cifspwd.db | --import-users=cifspwd.db\n");
	fprintf(stderr, "\t-n | --nodetach\n");
	fprintf(stderr, "\t-s systemd service mode | --systemd\n");

	exit(EXIT_FAILURE);
}

static int create_lock_file()
{
	lock_fd = open(LOCK_FILE, O_CREAT | O_EXCL,
			S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
	if (lock_fd < 0)
		return -EINVAL;

	if (flock(lock_fd, LOCK_EX | LOCK_NB) != 0)
		return -EINVAL;

	return 0;
}

static void delete_lock_file()
{
	flock(lock_fd, LOCK_UN);
	close(lock_fd);
	remove(LOCK_FILE);
}

static int wait_group_kill(int signo)
{
	pid_t pid;
	int status;

	while (kill(worker_pid, signo) != 0) {
		pr_err("can't execute kill: %s\n", strerror(errno));
		sleep(1);
	}

	while (1) {
		pid = waitpid(-1, &status, 0);
		if (pid != 0) {
			pr_debug("detected pid %d termination\n", pid);
			break;
		}
		sleep(1);
	}
	return 0;
}

static int setup_signal_handler(int signo, sighandler_t handler)
{
	int status;
	sigset_t full_set;
	struct sigaction act;

	sigfillset(&full_set);
	memset(&act, 0, sizeof(act));

	act.sa_handler = handler;
	act.sa_mask = full_set;

	status = sigaction(signo, &act, NULL);
	if (status != 0)
		pr_err("Unable to register %s signal handler: %s",
				sys_siglist[signo], strerror(errno));
	return status;
}

static int setup_signals(sighandler_t handler)
{
	if (setup_signal_handler(SIGINT, handler) != 0)
		return -EINVAL;

	if (setup_signal_handler(SIGTERM, handler) != 0)
		return -EINVAL;

	if (setup_signal_handler(SIGABRT, handler) != 0)
		return -EINVAL;

	if (setup_signal_handler(SIGQUIT, handler) != 0)
		return -EINVAL;

	if (setup_signal_handler(SIGHUP, handler) != 0)
		return -EINVAL;

	return 0;
}

static int parse_configs(char *pwddb, char *smbconf)
{
	int ret;

	ret = cp_parse_pwddb(pwddb);
	if (ret)
		return ret;

	ret = cp_parse_smbconf(smbconf);
	if (ret)
		return ret;

	if (pwddb != PATH_PWDDB)
		free(pwddb);
	if (smbconf!= PATH_SMBCONF)
		free(smbconf);
	return 0;
}

static void worker_process_free(void)
{
	/*
	 * NOTE, this is the final release, we don't look at ref_count
	 * values. User management should be destroyed last.
	 */
	ipc_destroy();
	rpc_destroy();
	wp_destroy();
	sm_destroy();
	shm_destroy();
	usm_destroy();
}

static void child_sig_handler(int signo)
{
	pr_err("Child received signal: %d (%s)\n",
		signo, sys_siglist[signo]);
	worker_process_free();
	exit(EXIT_SUCCESS);
}

static void manager_sig_handler(int signo)
{
	setup_signals(SIG_DFL);
	wait_group_kill(signo);
	pr_info("Exiting. Bye!\n");
	delete_lock_file();
	kill(0, SIGINT);
}

static int worker_process_init(void)
{
	int ret;

	setup_signals(child_sig_handler);
	set_logger_app_name("cifsd-worker");

	ret = usm_init();
	if (ret)
		goto out;

	ret = shm_init();
	if (ret)
		goto out;

	ret = parse_configs(pwddb, smbconf);
	if (ret)
		goto out;

	ret = sm_init();
	if (ret)
		goto out;

	ret = wp_init();
	if (ret)
		goto out;

	ret = rpc_init();
	if (ret)
		goto out;

	ret = ipc_init();
	if (ret)
		goto out;

	ret = ipc_receive_loop();

out:
	worker_process_free();
	return ret;
}

static pid_t start_worker_process(worker_fn fn)
{
	int status = 0;
	pid_t __pid;

	__pid = fork();
	if (__pid < 0) {
		pr_err("Can't fork child process: `%s'\n", strerror(errno));
		return -EINVAL;
	}
	if (__pid == 0) {
		status = fn();
		exit(status);
	}
	return __pid;
}

static int manager_process_init(void)
{
	int ret;

	setup_signals(manager_sig_handler);
	pr_logger_init(PR_LOGGER_SYSLOG);

	if (daemon(0, 0) != 0) {
		pr_err("Daemonization failed\n");
		goto out;
	}

	worker_pid = start_worker_process(worker_process_init);
	if (worker_pid < 0)
		goto out;

	while (1) {
		int status;
		pid_t child;

		child = waitpid(-1, &status, 0);
		pr_err("WARNING: child process exited abnormally: %d\n",
				child);
		if (child == -1) {
			pr_err("waitpid() returned error code: %s\n",
				strerror(errno));
			goto out;
		}

		/* Ratelimit automatic restarts */
		sleep(1);
		worker_pid = start_worker_process(worker_process_init);
		if (worker_pid < 0)
			goto out;
	}
out:
	delete_lock_file();
	kill(0, SIGTERM);
	return ret;
}

static int manager_systemd_service(void)
{
	pid_t __pid;

	__pid = start_worker_process(manager_process_init);
	if (__pid < 0)
		return -EINVAL;

	return 0;
}

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	int no_detach = 0;
	int systemd_service = 0;
	int c;

	set_logger_app_name("cifsd-manager");
	memset(&global_conf, 0x00, sizeof(struct smbconf_global));

	opterr = 0;
	while ((c = getopt(argc, argv, "c:i:snh")) != EOF)
		switch (c) {
		case 'c':
			smbconf = strdup(optarg);
			break;
		case 'i':
			pwddb = strdup(optarg);
			break;
		case 'n':
			no_detach = 1;
			break;
		case 's':
			systemd_service = 1;
			break;
		case '?':
		case 'h':
		default:
			usage();
	}

	if (!smbconf || !pwddb) {
		pr_err("Out of memory\n");
		exit(EXIT_FAILURE);
	}

	if (create_lock_file()) {
		pr_err("Failed to create lock file: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	setup_signals(manager_sig_handler);

	if (no_detach) {
		pr_logger_init(PR_LOGGER_STDIO);
		return worker_process_init();
	}

	if (!systemd_service)
		return manager_process_init();
	return manager_systemd_service();
}
