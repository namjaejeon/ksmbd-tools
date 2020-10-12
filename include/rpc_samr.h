/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#ifndef __KSMBD_RPC_SAMR_H__
#define __KSMBD_RPC_SAMR_H__

#include <smbacl.h>

struct ksmbd_rpc_command;
struct ksmbd_rpc_pipe;

struct connect_handle {
	int handle;
	int rid;
	char *domain_name;
	struct ksmbd_user *user;
	struct smb_sid sid;
};

int rpc_samr_read_request(struct ksmbd_rpc_pipe *pipe,
			  struct ksmbd_rpc_command *resp,
			  int max_resp_sz);

int rpc_samr_write_request(struct ksmbd_rpc_pipe *pipe);

#endif /* __KSMBD_RPC_SRVSVC_H__ */
