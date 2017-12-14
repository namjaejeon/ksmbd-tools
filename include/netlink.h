/*
 *   cifsd-tools/cifsd/netlink.h
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

#ifndef __CIFSD_TOOLS_NETLINK_H
#define __CIFSD_TOOLS_NETLINK_H

#include <linux/netlink.h>
#include "cifsd.h"

#ifdef IPV6_SUPPORTED
#define MAX_IPLEN 128
#else
#define MAX_IPLEN 16
#endif

#define NETLINK_CIFSD		31
#define NETLINK_CIFSD_MAX_PAYLOAD	4096
#define NETLINK_CIFSD_MAX_BUF         (sizeof(struct nlmsghdr) +      \
					sizeof(struct cifsd_uevent) + \
					NETLINK_CIFSD_MAX_PAYLOAD)

#define NETLINK_REQ_INIT        0x00
#define NETLINK_REQ_SENT        0x01
#define NETLINK_REQ_RECV        0x02
#define NETLINK_REQ_COMPLETED   0x04

/* Completion Filter flags for Notify */
#define FILE_NOTIFY_CHANGE_FILE_NAME	0x00000001
#define FILE_NOTIFY_CHANGE_DIR_NAME	0x00000002
#define FILE_NOTIFY_CHANGE_NAME		0x00000003
#define FILE_NOTIFY_CHANGE_ATTRIBUTES	0x00000004
#define FILE_NOTIFY_CHANGE_SIZE		0x00000008
#define FILE_NOTIFY_CHANGE_LAST_WRITE	0x00000010
#define FILE_NOTIFY_CHANGE_LAST_ACCESS	0x00000020
#define FILE_NOTIFY_CHANGE_CREATION	0x00000040
#define FILE_NOTIFY_CHANGE_EA		0x00000080
#define FILE_NOTIFY_CHANGE_SECURITY	0x00000100
#define FILE_NOTIFY_CHANGE_STREAM_NAME	0x00000200
#define FILE_NOTIFY_CHANGE_STREAM_SIZE	0x00000400
#define FILE_NOTIFY_CHANGE_STREAM_WRITE	0x00000800

/* SMB2 Notify Action Flags */
#define FILE_ACTION_ADDED		0x00000001
#define FILE_ACTION_REMOVED		0x00000002
#define FILE_ACTION_MODIFIED		0x00000003
#define FILE_ACTION_RENAMED_OLD_NAME	0x00000004
#define FILE_ACTION_RENAMED_NEW_NAME	0x00000005
#define FILE_ACTION_ADDED_STREAM	0x00000006
#define FILE_ACTION_REMOVED_STREAM	0x00000007
#define FILE_ACTION_MODIFIED_STREAM	0x00000008
#define FILE_ACTION_REMOVED_BY_DELETE	0x00000009

enum cifsd_uevent_e {
	CIFSD_UEVENT_UNKNOWN		= 0,

	/* down events: userspace to kernel space */
	CIFSD_UEVENT_INIT_CONNECTION	= 10,
	CIFSD_UEVENT_READ_PIPE_RSP,
	CIFSD_UEVENT_WRITE_PIPE_RSP,
	CIFSD_UEVENT_IOCTL_PIPE_RSP,
	CIFSD_UEVENT_LANMAN_PIPE_RSP,
	CIFSD_UEVENT_EXIT_CONNECTION,
	CIFSD_UEVENT_INOTIFY_RESPONSE,
	CIFSD_UEVENT_CONFIG_USER_RSP,
	CIFSD_UEVENT_CONFIG_SHARE_RSP,

	CIFSADMIN_UEVENT_INIT_CONNECTION,
	CIFSADMIN_UEVENT_QUERY_USER_RSP,
	CIFSADMIN_UEVENT_REMOVE_USER_RSP,

	CIFSSTAT_UEVENT_INIT_CONNECTION,
	CIFSSTAT_UEVENT_READ_STAT,
	CIFSSTAT_UEVENT_READ_STAT_RSP,

	/* up events: kernel space to userspace */
	CIFSD_KEVENT_CREATE_PIPE	= 100,
	CIFSD_KEVENT_READ_PIPE,
	CIFSD_KEVENT_WRITE_PIPE,
	CIFSD_KEVENT_IOCTL_PIPE,
	CIFSD_KEVENT_LANMAN_PIPE,
	CIFSD_KEVENT_DESTROY_PIPE,
	CFISD_KEVENT_USER_DAEMON_EXIST,
	CIFSD_KEVENT_INOTIFY_REQUEST,
	CIFSD_KEVENT_EARLY_INIT,
	CIFSD_KEVENT_CONFIG_USER,
	CIFSD_KEVENT_CONFIG_SHARE,

	CIFSADMIN_KEVENT_QUERY_USER,
	CIFSADMIN_KEVENT_REMOVE_USER,
};

struct cifsd_uevent {
	unsigned int	type; /* k/u events type */
	int		error; /* carries interface or resource errors */
	__u64		server_handle;
	unsigned int	buflen;
	unsigned int	pipe_type;
	char   codepage[CIFSD_CODEPAGE_LEN];
	union {
		/* messages u -> k */
		unsigned int	nt_status;
		struct msg_init_conn {
			unsigned int	unused;
		} i_conn;
		struct msg_exit_conn {
			unsigned int	unused;
		} e_conn;
		struct msg_read_pipe_response {
			unsigned int	read_count;
		} r_pipe_rsp;
		struct msg_write_pipe_response {
			unsigned int	write_count;
		} w_pipe_rsp;
		struct msg_ioctl_pipe_response {
			unsigned int	data_count;
		} i_pipe_rsp;
		struct msg_lanman_pipe_response {
			unsigned int    data_count;
			unsigned int    param_count;
		} l_pipe_rsp;
		struct msg_read_stat_response {
			unsigned int    unused;
		} r_stat_rsp;
		struct msg_user_query_response {
			unsigned int    unused;
		} u_query_rsp;
		struct msg_user_del_response {
			unsigned int    unused;
		} u_del_rsp;
	} u;

	union {
		/* messages k -> u */
		struct msg_create_pipe {
			__u64		id;
			char   codepage[CIFSD_CODEPAGE_LEN];
		} c_pipe;
		struct msg_destroy_pipe {
			__u64		id;
		} d_pipe;
		struct msg_read_pipe {
			__u64		id;
			unsigned int	out_buflen;
		} r_pipe;
		struct msg_write_pipe {
			__u64		id;
		} w_pipe;
		struct msg_ioctl_pipe {
			__u64		id;
			unsigned int	out_buflen;
		} i_pipe;
		struct msg_lanman_pipe {
			unsigned int    out_buflen;
			char    codepage[CIFSD_CODEPAGE_LEN];
			char    username[CIFSD_USERNAME_LEN];
		} l_pipe;
		struct msg_read_stat {
			__u64		flag;
			char		statip[MAX_IPLEN];
		} r_stat;
		struct msg_user_query {
			char		username[CIFSD_USERNAME_LEN];
		} u_query;
		struct msg_user_del {
			char		username[CIFSD_USERNAME_LEN];
		} u_del;
	} k;
	char buffer[0];
};

struct smb2_inotify_req_info {
	__le16 watch_tree_flag;
	__le32 CompletionFilter;
	__u32 path_len;
	char dir_path[];
};

struct FileNotifyInformation {
	__le32 NextEntryOffset;
	__le32 Action;
	__le32 FileNameLength;
	__le16 FileName[];
};

struct smb2_inotify_res_info {
	__u32 output_buffer_length;
	struct FileNotifyInformation file_notify_info[];
};

struct nl_sock {
	char *nlsk_rcv_buf;
	char *nlsk_send_buf;
	int nlsk_fd;
	struct sockaddr_nl src_addr;
	struct sockaddr_nl dest_addr;
	int (*event_handle_cb)(struct nl_sock *nlsock);
};

/* List of connected clients */
struct list_head cifsd_clients;
struct list_head cifsd_notify_clients;
int cifsd_common_sendmsg(struct nl_sock *nlsock, struct cifsd_uevent *ev,
		char *buf, unsigned int buflen);
int cifsd_netlink_setup(struct nl_sock *nlsock);

/* Netlink Interface*/
struct nl_sock *nl_init();
int nl_handle_event(struct nl_sock *nlsock);
void nl_loop(struct nl_sock *nlsock);
int nl_exit(struct nl_sock *nlsock);

int nl_handle_early_init_cifsd(struct nl_sock *nlsock);
int nl_handle_init_cifsd(struct nl_sock *nlsock);
int nl_handle_exit_cifsd(struct nl_sock *nlsock);
int nl_handle_init_cifsstat(struct nl_sock *nlsock);
int nl_handle_init_cifsadmin(struct nl_sock *nlsock);

#endif /* __CIFSD_TOOLS_NETLINK_H */
