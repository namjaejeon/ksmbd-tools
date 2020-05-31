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

#include "config_parser.h"
#include "ksmbdtools.h"
#include "management/user.h"
#include "management/share.h"
#include "user_admin.h"
#include "linux/ksmbd_server.h"
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

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	int c, cmd = 0;

	set_logger_app_name("ksmbd.control");

	opterr = 0;
	while ((c = getopt(argc, argv, "sd:cV")) != EOF)
		switch (c) {
		case 's':
			arg_account = g_strdup(optarg);
			cmd = COMMAND_ADD_USER;
			break;
		case 'd':
			arg_account = g_strdup(optarg);
			cmd = COMMAND_DEL_USER;
			break;
		case 'c':
			arg_account = g_strdup(optarg);
			cmd = COMMAND_UPDATE_USER;
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
