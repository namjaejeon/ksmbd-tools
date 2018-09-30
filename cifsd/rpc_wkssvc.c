// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <memory.h>
#include <endian.h>
#include <glib.h>
#include <errno.h>
#include <linux/cifsd_server.h>

#include <management/share.h>

#include <rpc.h>
#include <rpc_wkssvc.h>
#include <cifsdtools.h>

int rpc_wkssvc_read_request(struct cifsd_rpc_pipe *pipe,
			    struct cifsd_rpc_command *resp,
			    int max_resp_sz)
{
	return CIFSD_RPC_ENOTIMPLEMENTED;
}

int rpc_wkssvc_write_request(struct cifsd_rpc_pipe *pipe)
{
	return CIFSD_RPC_ENOTIMPLEMENTED;
}
