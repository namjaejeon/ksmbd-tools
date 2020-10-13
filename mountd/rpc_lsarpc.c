// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2020 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <memory.h>
#include <endian.h>
#include <glib.h>
#include <pwd.h>
#include <errno.h>
#include <linux/ksmbd_server.h>

#include <management/user.h>

#include <rpc.h>
#include <rpc_samr.h>
#include <smbacl.h>
#include <ksmbdtools.h>

#define LSARPC_OPNUM_DS_ROLE_GET_PRIMARY_DOMAIN_INFO	0

static int lsarpc_get_primary_domain_info_invoke(struct ksmbd_rpc_pipe *pipe)
{
	pr_err("%s : %d\n", __func__, __LINE__);

	return KSMBD_RPC_OK;
}

static int lsarpc_get_primary_domain_info_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	pr_err("%s : %d\n", __func__, __LINE__);

	return KSMBD_RPC_OK;
}

static int lsarpc_invoke(struct ksmbd_rpc_pipe *pipe)
{
	int ret = KSMBD_RPC_ENOTIMPLEMENTED;

	pr_err("%s : %d\n", __func__, __LINE__);
	switch (pipe->dce->req_hdr.opnum) {
	case LSARPC_OPNUM_DS_ROLE_GET_PRIMARY_DOMAIN_INFO:
		ret = lsarpc_get_primary_domain_info_invoke(pipe);
		break;
	default:
		pr_err("LSARPC: unsupported INVOKE method %d\n",
		       pipe->dce->req_hdr.opnum);
		break;
	}
	pr_err("%s : %d\n", __func__, __LINE__);

	return ret;
}

static int lsarpc_return(struct ksmbd_rpc_pipe *pipe,
			 struct ksmbd_rpc_command *resp,
			 int max_resp_sz)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int ret;
	int status = KSMBD_RPC_ENOTIMPLEMENTED;

	pr_err("%s : %d\n", __func__, __LINE__);
	/*
	 * Reserve space for response NDR header. We don't know yet if
	 * the payload buffer is big enough. This will determine if we
	 * can set DCERPC_PFC_FIRST_FRAG|DCERPC_PFC_LAST_FRAG or if we
	 * will have a multi-part response.
	 */
	dce->offset = sizeof(struct dcerpc_header);
	dce->offset += sizeof(struct dcerpc_response_header);
	pipe->num_processed = 0;

	switch (dce->req_hdr.opnum) {
	case LSARPC_OPNUM_DS_ROLE_GET_PRIMARY_DOMAIN_INFO:
		status = lsarpc_get_primary_domain_info_return(pipe);
		break;
		break;
	default:
		pr_err("LSARPC: unsupported RETURN method %d\n",
			dce->req_hdr.opnum);
		ret = KSMBD_RPC_EBAD_FUNC;
		break;
	}

	if (rpc_restricted_context(dce->rpc_req))
		status = KSMBD_RPC_EACCESS_DENIED;

	/*
	 * [out] DWORD Return value/code
	 */
	ndr_write_int32(dce, status);
	dcerpc_write_headers(dce, status);

	dce->rpc_resp->payload_sz = dce->offset;
	pr_err("%s : %d\n", __func__, __LINE__);
	return ret;
}

int rpc_lsarpc_read_request(struct ksmbd_rpc_pipe *pipe,
			    struct ksmbd_rpc_command *resp,
			    int max_resp_sz)
{
	pr_err("%s : %d\n", __func__, __LINE__);
	return lsarpc_return(pipe, resp, max_resp_sz);
}

int rpc_lsarpc_write_request(struct ksmbd_rpc_pipe *pipe)
{
	pr_err("%s : %d\n", __func__, __LINE__);
	return lsarpc_invoke(pipe);
}
