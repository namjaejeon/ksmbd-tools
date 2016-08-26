/*
 *   cifssrv-tools/include/cifssrv.h
 *
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
#ifndef __CIFSSRV_HEADER_H
#define __CIFSSRV_HEADER_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
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

#include "list.h"
#include "nterr.h"
#include "error.h"

#define F_VERBOSE 0x20

/* error codes */
#define CIFS_SUCCESS 0x0
#define CIFS_FAIL 0x1
#define CIFS_NONE_USR 0x2
#define CIFS_CONF_FAIL 0x3
#define CIFS_AUTH_FAIL 0x4

#define PATH_PWDDB "/etc/cifs/cifspwd.db"
#define PATH_SHARECONF "/etc/cifs/smb.conf"

#define PATH_CIFSSRV_CONFIG "/sys/fs/cifssrv/config"
#define PATH_CIFSSRV_SHARE "/sys/fs/cifssrv/share"
#define PATH_CIFSSRV_USR "/sys/fs/cifssrv/user"

#define UNICODE_LEN(x) (x * 2)

#define CIFS_NTHASH_SIZE 16
#define MAX_NT_PWD_LEN 129
#define PAGE_SZ 4096
#define LINESZ 512
#define SMALLSZ 100

#define CIFS_MAX_MSGSIZE 65536
#define MAX_CIFS_HDR_SIZE 0x78 //default for SMB2, SMB limit is 0x58
#define RESP_BUF_SIZE (CIFS_MAX_MSGSIZE + MAX_CIFS_HDR_SIZE)


#define CIFSSRV_MAJOR_VERSION 1
#define CIFSSRV_MINOR_VERSION 0

#define CIFSSRV_CODEPAGE_LEN    32
#define CIFSSRV_USERNAME_LEN	33

enum cifssrv_pipe_type {
	SRVSVC,
	WINREG,
	LANMAN,
	MAX_PIPE
};

struct cifssrv_pipe_table {
        char pipename[32];
        unsigned int pipetype;
};

#define INVALID_PIPE   0xFFFFFFFF

struct cifssrv_pipe {
        struct list_head list;
        int id;
        char *data;
        int pkt_type;
        unsigned int pipe_type;
        int opnum;
        char *buf;
        int datasize;
        int sent;
	char codepage[CIFSSRV_CODEPAGE_LEN];
	char username[CIFSSRV_USERNAME_LEN];
};

struct cifssrvd_client_info {
        struct list_head list;
        __u64 hash;
	void *local_nls; // To be replaced with actual encoding logic
        struct list_head pipelist;
};

/* max string size for share and parameters */
#define SHARE_MAX_NAME_LEN      100
#define SHARE_MAX_COMMENT_LEN   100

#define MAX_SERVER_NAME_LEN	100
#define MAX_SERVER_WRKGRP_LEN	100

#define STR_IPC		"IPC$"
#define STR_SRV_NAME	"CIFSSRV SERVER"
#define STR_WRKGRP	"WORKGROUP"

struct share_config {
	char *comment;
	char *allow_hosts;
	char *deny_hosts;
	char *invalid_users;
	char *read_list;
	char *valid_users;
	unsigned long attr;
	unsigned int max_connections;
};

struct cifssrv_share {
	char    *path;
	__u16   tid;
	int     tcount;
	char    *sharename;
	struct share_config config;

	/* global list of shares */
	struct list_head list;
};

extern struct list_head cifssrv_share_list;
extern int cifssrv_num_shares;

char *guestAccountName;
//char *server_string;
//char *workgroup;
char *netbios_name;


struct cifssrv_usr {
        char    *name;
#if 0
        char    passkey[CIFS_NTHASH_SIZE];
        kuid_t  uid;
        kgid_t  gid;
        __le32  sess_uid;
        bool    guest;
        /* global list of cifssrv users */
        struct  list_head list;
        __u16   vuid;
        /* how many server have this user */
        int     ucount;
        /* unsigned int capabilities; what for */
#endif
};

int vflags;

#define cifssrv_debug(fmt, ...)                         \
	do {                                                    \
		if (vflags)					\
			printf("%s:%d: " fmt,                           \
				__func__, __LINE__, ##__VA_ARGS__);     \
	} while (0)

#define cifssrv_err(fmt, ...)                                   \
	do {                                                    \
		printf("%s:%d: " fmt,                           \
				__func__, __LINE__, ##__VA_ARGS__);     \
	} while (0)

int init_2_strings(const char *src, char **str1, char **str2, int len);
int readline(FILE *fp, char **buf, int *isEOF, int check);
int get_entry(int fd, char **buf, int *isEOF);
void tlws(char *src, char *dst, int *sz);

int process_rpc_rsp(struct cifssrv_pipe *pipe, char *data_buf, int size);
int process_rpc(struct cifssrv_pipe *pipe, char *data);
int handle_lanman_pipe(struct cifssrv_pipe *pipe, char *in_data,
		char *out_data, int *param_len);

int smbConvertToUTF16(__le16 *target, char *source, int slen,
                int targetlen, const char *codepage);
char *smb_strndup_from_utf16(char *src, const int maxlen,
                const int is_unicode, const char *codepage);

#define __constant_cpu_to_le64(x) ((__le64)(__u64)(x))
#define __constant_le64_to_cpu(x) ((__u64)(__le64)(x))
#define __cpu_to_le64(x) ((__u64)(x))
#define __le64_to_cpu(x) ((__le64)(x))
#define __cpu_to_le32(x) ((__u32)(x))
#define __le32_to_cpu(x) ((__le32)(x))
#define __cpu_to_le16(x) ((__u16)(x))
#define __le16_to_cpu(x) ((__le16)(x))
#define __cpu_to_be64(x) (__swab64((x)))
#define __be64_to_cpu(x) __swab64((__be64)(x))
#define __cpu_to_be32(x) (__swab32((x)))
#define __be32_to_cpu(x) __swab32((__be32)(x))
#define __cpu_to_be16(x) (__swab16((x)))
#define __be16_to_cpu(x) __swab16((__be16)(x))

#define cpu_to_le32(x)	__cpu_to_le32(x)
#define cpu_to_le16(x)	__cpu_to_le16(x)
#define le32_to_cpu(x)	__le32_to_cpu(x)
#define le16_to_cpu(x)	__le16_to_cpu(x)


/*
 *  * Size of encrypted user password in bytes
 *   */
#define CIFS_ENCPWD_SIZE (16)

/*
 *  * Size of the crypto key returned on the negotiate SMB in bytes
 *   */
#define CIFS_CRYPTO_KEY_SIZE (8)

/*
 *  * Size of the ntlm client response
 *   */
#define CIFS_AUTH_RESP_SIZE (24)

/*
 *  * Size of the session key (crypto key encrypted with the password
 *   */
#define CIFS_SESS_KEY_SIZE (16)

#endif
