// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#ifndef __CIFSD_RPC_WKSSVC_H__
#define __CIFSD_RPC_WKSSVC_H__

struct cifsd_rpc_command;
struct cifsd_rpc_pipe;

int rpc_wkssvc_read_request(struct cifsd_rpc_pipe *pipe,
			    struct cifsd_rpc_command *resp,
			    int max_resp_sz);

int rpc_wkssvc_write_request(struct cifsd_rpc_pipe *pipe);

#endif /* __CIFSD_RPC_WKSSVC_H__ */
