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

#ifndef __CIFSDTOOLS_H__
#define __CIFSDTOOLS_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

struct smbconf_global {
	int			map_to_guest;
	char			*guest_account;

	char			*server_string;
	char			*work_group;
	char			*netbios_name;
	char			*server_min_protocol;
	char			*server_max_protocol;
	int			server_signing;
	int			sessions_cap;
};

extern struct smbconf_global global_conf;

#define CIFSD_CONF_MAP_TO_GUEST_NEVER		(0)
#define CIFSD_CONF_MAP_TO_GUEST_BAD_USER	(1 << 0)
#define CIFSD_CONF_MAP_TO_GUEST_BAD_PASSWORD	(1 << 1)
#define CIFSD_CONF_MAP_TO_GUEST_BAD_UID		(1 << 2)

#define CIFSD_CONF_DEFAULT_NETBIOS_NAME	"CIFSD SERVER"
#define CIFSD_CONF_DEFAULT_SERVER_STRING	"CIFSD"
#define CIFSD_CONF_DEFAULT_WORK_GROUP		"WORKGROUP"

#define CIFSD_CONF_DEFAULT_GUEST_ACCOUNT	"nobody"
#define CIFSD_CONF_FALLBACK_GUEST_ACCOUNT	"ftp"

#define CIFSD_CONF_DEFAULT_SESS_CAP	1024

#define PATH_PWDDB	"/etc/cifs/cifsdpwd.db"
#define PATH_SMBCONF	"/etc/cifs/smb.conf"

#define CIFSD_HEALTH_START	0
#define CIFSD_HEALTH_RUNNING	1

static int cifsd_health_status;

#define TRACING_DUMP_NL_MSG	0

#define ARRAY_SIZE(X) (sizeof(X) / sizeof((X)[0]))

//---------------------------------------------------------------//
#define LOGAPP		"[%s/%d]:"
#define PRERR		LOGAPP" ERROR: "
#define PRINF		LOGAPP" INFO: "
#define PRDEBUG		LOGAPP" DEBUG: "

#define PR_ERROR	0
#define PR_INFO		1
#define PR_DEBUG	2

static int log_level = PR_DEBUG;

#define PR_LOGGER_STDIO         0
#define PR_LOGGER_SYSLOG        1

extern void set_logger_app_name(const char *an);
extern const char *get_logger_app_name(void);
extern void __pr_log(int level, const char *fmt,...);
extern void pr_logger_init(int flags);

#define pr_log(l, f, ...)						\
	do {								\
		if ((l) <= log_level)					\
			__pr_log((l), (f), get_logger_app_name(),	\
					getpid(),			\
					##__VA_ARGS__);			\
	} while (0)

#define pr_debug(f,...)	\
	pr_log(PR_DEBUG, PRDEBUG f, ##__VA_ARGS__)
#define pr_info(f,...)	\
	pr_log(PR_INFO, PRINF f, ##__VA_ARGS__)
#define pr_err(f,...)	\
	pr_log(PR_ERROR, PRERR f, ##__VA_ARGS__)
//---------------------------------------------------------------//

void pr_hex_dump(const void *mem, size_t sz);

char *base64_encode(unsigned char *src, size_t srclen);
unsigned char *base64_decode(char const *src, size_t *dstlen);

#endif /* __CIFSDTOOLS_H__ */
