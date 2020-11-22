// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2020 LG Electronics
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include "ksmbdtools.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>

#include <linux/ksmbd_server.h>
#include <management/spnego.h>
#include "spnego_mech.h"

static struct spnego_mech_ctx mech_ctxs[SPNEGO_MAX_MECHS];

static struct spnego_mech_ctx *get_mech(int mech_type)
{
	if (mech_type >= SPNEGO_MAX_MECHS)
		return NULL;
	return &mech_ctxs[mech_type];
}

int spnego_init(void)
{
	struct spnego_mech_ctx *mech_ctx;
	int i;

	for (i = 0; i < SPNEGO_MAX_MECHS; i++) {
		if (mech_ctxs[i].ops->setup &&
				mech_ctxs[i].ops->setup(&mech_ctxs[i])) {
			pr_err("Failed to init Kerberos\n");
			goto out_err;
		}
	}

	return 0;
out_err:
	for (; i >= 0; i--) {
		if (mech_ctxs[i].ops->cleanup)
			mech_ctxs[i].ops->cleanup(&mech_ctxs[i]);
	}
	return -ENOTSUP;
}

void spnego_destroy(void)
{
	int i;

	for (i = 0; i < SPNEGO_MAX_MECHS; i++) {
		if (mech_ctxs[i].ops->cleanup)
			mech_ctxs[i].ops->cleanup(&mech_ctxs[i]);
	}
}

static int decode_negTokenInit(unsigned char *negToken, int token_len,
			int *mech_type, unsigned char **krb5_ap_req,
			unsigned int *req_len)
{
}

static int encode_negTokenTarg(char *in_blob, int in_len,
			const unsigned long *oid, int oid_len,
			char **out_blob, int *out_len)
{
}

int spnego_handle_authen_request(struct ksmbd_spnego_authen_request *req,
			struct ksmbd_spnego_auth_out *auth_out)
{
	struct spnego_mech_ctx *mech_ctx;
	unsigned char *mech_token;
	int token_len, mech_type;
	int retval = 0;

	if (decode_negTokenInit(req->spnego_blob, (int)req->spnego_blob_len,
				&mech_type, &mech_token, &token_len)) {
		pr_info("Error decoding negTokenInit\n");
		return -EINVAL;
	}

	mech_ctx = get_mech(mech_type);
	if (!mech_ctx) {
		retval = -ENOTSUP;
		pr_info("Not support Kerberos\n");
		goto out;
	}

	if (mech_ctx->ops->handle_authen(mech_ctx,
				mech_token, token_len,
				auth_out, encode_negTokenTarg)) {
		retval = -EPERM;
		pr_info("Error authenticate\n");
		goto out;
	}
out:
	return retval;
}
