/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __KSMBD_RPC_NDR_H__
#define __KSMBD_RPC_NDR_H__

struct ksmbd_dcerpc;
struct ksmbd_rpc_pipe;

int rpc_ndr64_available(void);
int rpc_ndr_decode_request(struct ksmbd_rpc_pipe *pipe);
int rpc_ndr_encode_response(struct ksmbd_dcerpc *dce);
void rpc_ndr_cleanup(struct ksmbd_dcerpc *dce);

#endif /* __KSMBD_RPC_NDR_H__ */
