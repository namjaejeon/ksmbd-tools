/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#ifndef __KSMBD_RPC_LSARPC_H__
#define __KSMBD_RPC_LSARPC_H__

#include <smbacl.h>

struct ksmbd_rpc_command;
struct ksmbd_rpc_pipe;

struct policy_handle {
	int handle;
	struct ksmbd_user *user;
};

struct lsarpc_names_info {
	int type;
	char domain_name[256];
	struct smb_sid sid;
	struct ksmbd_user *user;
};

int rpc_lsarpc_read_request(struct ksmbd_rpc_pipe *pipe,
			  struct ksmbd_rpc_command *resp,
			  int max_resp_sz);

int rpc_lsarpc_write_request(struct ksmbd_rpc_pipe *pipe);

#endif /* __KSMBD_RPC_LSARPC_H__ */
