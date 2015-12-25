/*
 *   cifssrv-tools/cifsmgr.h
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
#ifndef _CIFSMGR_H
#define _CIFSMGR_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <pwd.h>
#include <termios.h>
#include <signal.h>
#include <iconv.h>
#include <errno.h>

/* process flags */
#define AM_ROOT 0x1
#define VERBOSE 0x2
#define CONFIG_CIFSSRV 0x4
#define ADD_USR 0x8
#define RM_USR 0x10
#define QRY_USR 0x20
#define IMPORT_USR_DB 0x40
#define LIST_SHARES 0x80
#define SHOW_SHARE 0x100

/* error codes */
#define CIFS_SUCCESS 0x0
#define CIFS_FAIL 0x1
#define CIFS_NONE_USR 0x2
#define CIFS_CONF_FAIL 0x3
#define CIFS_AUTH_FAIL 0x4

#define COPY_UCS2_CHAR(dest, src) (((unsigned char *)(dest))[0] =\
		((unsigned char *)(src))[0], ((unsigned char *)(dest))[1] =\
		((unsigned char *)(src))[1], (dest))

#ifdef CIFSMGR_DEBUG
	#define PATH_PWDDB "./cifspwd.db"
	#define PATH_SHARECONF	"./cifsshare.conf"
#else
	#define PATH_PWDDB "/etc/cifs/cifspwd.db"
	#define PATH_SHARECONF	"/etc/cifs/cifsshare.conf"
#endif

#define PATH_CIFSSRV_CONFIG "/sys/fs/cifssrv/config"
#define PATH_CIFSSRV_SHARE "/sys/fs/cifssrv/share"
#define PATH_CIFSSRV_USR "/sys/fs/cifssrv/user"

#define CIFS_NTHASH_SIZE 16
#define MAX_NT_PWD_LEN 129
#define PAGE_SZ 4096
#define LINESZ 512
#define SMALLSZ 100
#define MD4_BLOCK_WORDS	16
#define MD4_HASH_WORDS	4

struct md4_ctx {
	unsigned int hash[MD4_HASH_WORDS];
	unsigned int block[MD4_BLOCK_WORDS];
	unsigned long long byte_count;
};

/* forward declarations */
int md4_init(struct md4_ctx *);
int md4_update(struct md4_ctx *, const unsigned char *, unsigned int);
int md4_final(struct md4_ctx *, unsigned char *);

#endif /* _CIFSMGR_H */
