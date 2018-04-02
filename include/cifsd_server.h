/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@sourceforge.net
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

#ifndef _LINUX_CIFSD_SERVER_H
#define _LINUX_CIFSD_SERVER_H

#include <sys/types.h>
#include <asm/types.h>

#define CIFSD_TOOLS_NETLINK	30

#define CIFSD_VERSION	"0.0.1"

#ifndef __packed
#define __packed			__attribute__ ((packed));
#endif

struct cifsd_introduction {
	__u32	pid;
	__s8	version[8];
} __packed;

struct cifsd_login_request {
	__u64	handle;
	__s8	account[256];
} __packed;

struct cifsd_login_response {
	__u64	handle;
	__u16	status;
	__u16	hash_sz;
	__s8	hash[256];
} __packed;

struct cifsd_tree_connect_request {
	__u64	handle;
	__s8	account[256];
	__s8	share[256];
	__s8	host[256];
} __packed;

struct cifsd_tree_connect_response {
	__u64	handle;
	__u32	status;
	__u32	connection_flags;
	__u64	connection_id;
} __packed;

struct cifsd_tree_disconnect_request {
	__u64	connect_id;
} __packed;

struct cifsd_logout_request {
	__u64	handle;
} __packed;

enum cifsd_event {
	CIFSD_EVENT_INTRODUCTION		= 1,
	CIFSD_EVENT_LOGIN_REQUEST,
	CIFSD_EVENT_LOGIN_RESPONSE,

	CIFSD_EVENT_TREE_CONNECT_REQUEST,
	CIFSD_EVENT_TREE_CONNECT_RESPONSE,

	CIFSD_EVENT_TREE_DISCONNECT_REQUEST,

	CIFSD_EVENT_LOGOUT_REQUEST
};

enum CIFSD_LOGIN_STATUS {
	CIFSD_LOGIN_STATUS_OK			= 64,
	CIFSD_LOGIN_STATUS_INVALID,
	CIFSD_LOGIN_STATUS_UNKNOWN_USER,
};

enum CIFSD_TREE_CONN_STATUS {
	CIFSD_TREE_CONN_STATUS_OK		= 128,
	CIFSD_TREE_CONN_STATUS_NOMEM,
	CIFSD_TREE_CONN_STATUS_NO_SHARE,
	CIFSD_TREE_CONN_STATUS_NO_USER,
	CIFSD_TREE_CONN_STATUS_INVALID_USER,
	CIFSD_TREE_CONN_STATUS_HOST_DENIED,
	CIFSD_TREE_CONN_STATUS_CONN_EXIST,
	CIFSD_TREE_CONN_STATUS_ERROR,
};

#define CIFSD_TREE_CONN_FLAG_GUEST_ACCOUNT	(1 << 0)
#define CIFSD_TREE_CONN_FLAG_READ_ONLY		(1 << 1)
#define CIFSD_TREE_CONN_FLAG_ADMIN_ACCOUNT	(1 << 3)

#endif /* _LINUX_CIFSD_SERVER_H */
