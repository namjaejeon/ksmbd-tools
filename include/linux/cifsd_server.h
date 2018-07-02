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

#ifndef _LINUX_CIFSD_SERVER_H
#define _LINUX_CIFSD_SERVER_H

#include <linux/types.h>

#define CIFSD_GENL_NAME      "CIFSD_GENL"
#define CIFSD_GENL_VERSION    0x01

#ifndef __packed
#define __packed			__attribute__ ((packed));
#endif

struct cifsd_startup_shutdown {
	__s8	reserved[8];
} __packed;

struct cifsd_login_request {
	__u32	handle;
	__s8	account[64];
} __packed;

struct cifsd_login_response {
	__u32	handle;
	__u16	status;
	__u16	hash_sz;
	__s8	hash[64];
} __packed;

struct cifsd_tree_connect_request {
	__u32	handle;
	__u32	flags;
	__s8	account[64];
	__s8	share[64];
	__s8	peer_addr[64];
} __packed;

struct cifsd_tree_connect_response {
	__u32	handle;
	__u32	status;
	__u32	connection_flags;
	__u64	connection_id;
} __packed;

struct cifsd_tree_disconnect_request {
	__u64	connection_id;
} __packed;

struct cifsd_logout_request {
	__s8	account[64];
} __packed;

/* This also used as NETLINK attribute type value. */
enum cifsd_event {
	CIFSD_EVENT_UNSPEC			= 0,
	CIFSD_EVENT_STARTING_UP,
	CIFSD_EVENT_SHUTTING_DOWN,

	CIFSD_EVENT_LOGIN_REQUEST,
	CIFSD_EVENT_LOGIN_RESPONSE,

	CIFSD_EVENT_TREE_CONNECT_REQUEST,
	CIFSD_EVENT_TREE_CONNECT_RESPONSE,

	CIFSD_EVENT_TREE_DISCONNECT_REQUEST,

	CIFSD_EVENT_LOGOUT_REQUEST,

	CIFSD_EVENT_MAX
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
	CIFSD_TREE_CONN_STATUS_TOO_MANY_CONNS,
	CIFSD_TREE_CONN_STATUS_ERROR,
};

/*
 * Tree connect response flags
 */
#define CIFSD_TREE_CONN_FLAG_GUEST_ACCOUNT	(1 << 0)
#define CIFSD_TREE_CONN_FLAG_READ_ONLY		(1 << 1)
#define CIFSD_TREE_CONN_FLAG_ADMIN_ACCOUNT	(1 << 2)

/*
 * Tree connect request flags
 */
#define CIFSD_TREE_CONN_FLAG_REQUEST_SMB1	(0)
#define CIFSD_TREE_CONN_FLAG_REQUEST_IPV6	(1 << 0)
#define CIFSD_TREE_CONN_FLAG_REQUEST_SMB2	(1 << 1)

#endif /* _LINUX_CIFSD_SERVER_H */
