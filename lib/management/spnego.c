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
#include <asn1.h>
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

static int compare_oid(unsigned long *oid1, unsigned int oid1len,
		    unsigned long *oid2, unsigned int oid2len)
{
	unsigned int i;

	if (oid1len != oid2len)
		return 1;

	for (i = 0; i < oid1len; i++) {
		if (oid1[i] != oid2[i])
			return 1;
	}
	return 0;
}

static bool is_supported_mech(unsigned long *oid, unsigned int len,
			int *mech_type)
{
	*mech_type = SPNEGO_MAX_MECHS;
	return false;
}

static int decode_asn1_header(struct asn1_ctx *ctx, unsigned char **end,
		unsigned int cls, unsigned int con, unsigned int tag)
{
	unsigned int d_cls, d_con, d_tag;

	if (asn1_header_decode(ctx, end, &d_cls, &d_con, &d_tag) == 0 ||
		(d_cls != cls || d_con != con || d_tag != tag))
		return -EINVAL;
	return 0;
}

static int decode_negTokenInit(unsigned char *negToken, int token_len,
			int *mech_type, unsigned char **krb5_ap_req,
			unsigned int *req_len)
{
	struct asn1_ctx ctx;
	unsigned char *end, *mech_types_end, *id;
	unsigned long *oid = NULL;
	unsigned int len;

	asn1_open(&ctx, negToken, token_len);

	/* GSSAPI header */
	if (decode_asn1_header(&ctx, &end, ASN1_APL, ASN1_CON, ASN1_EOC)) {
		pr_debug("Error decoding SPNEGO application tag\n");
		return -EINVAL;
	}

	/* SPNEGO oid */
	if (decode_asn1_header(&ctx, &end, ASN1_UNI, ASN1_PRI, ASN1_OJI) ||
			asn1_oid_decode(&ctx, end, &oid, &len) == 0 ||
			compare_oid(oid, len, SPNEGO_OID, SPNEGO_OID_LEN)) {
		pr_debug("Error decoding SPNEGO oid\n");
		free(oid);
		return -EINVAL;
	}
	free(oid);

	/* negoTokenInit */
	if (decode_asn1_header(&ctx, &end, ASN1_CTX, ASN1_CON, 0) ||
			decode_asn1_header(&ctx, &end,
				ASN1_UNI, ASN1_CON, ASN1_SEQ)) {
		pr_debug("Error decoding negTokenInit tag\n");
		return -EINVAL;
	}

	/* mechTypes */
	if (decode_asn1_header(&ctx, &end, ASN1_CTX, ASN1_CON, 0) ||
			decode_asn1_header(&ctx, &end,
				ASN1_UNI, ASN1_CON, ASN1_SEQ)) {
		pr_debug("Error decoding mechTypes tag\n");
		return -EINVAL;
	}

	mech_types_end = end;
	if (decode_asn1_header(&ctx, &end, ASN1_UNI, ASN1_PRI, ASN1_OJI) ||
			asn1_oid_decode(&ctx, end, &oid, &len) == 0) {
		pr_debug("Error decoding Kerberos oids\n");
		return -EINVAL;
	}

	if (!is_supported_mech(oid, len, mech_type)) {
		free(oid);
		pr_debug("Not support mechanism\n");
		return -EINVAL;
	}
	free(oid);

	ctx.pointer = mech_types_end;
	/* mechToken */
	if (decode_asn1_header(&ctx, &end, ASN1_CTX, ASN1_CON, 2) ||
			decode_asn1_header(&ctx, &end,
				ASN1_UNI, ASN1_PRI, ASN1_OTS)) {
		pr_debug("Error decoding krb5_blob\n");
		return -EINVAL;
	}

	if (decode_asn1_header(&ctx, &end, ASN1_APL, ASN1_CON, ASN1_EOC)) {
		pr_debug("Error decoding GSSAPI application tag\n");
		return -EINVAL;
	}

	/* Kerberos 5 oid */
	if (decode_asn1_header(&ctx, &end, ASN1_UNI, ASN1_PRI, ASN1_OJI)) {
		pr_debug("Error decoding Kerberos oid tag\n");
		return -EINVAL;
	}

	if (asn1_oid_decode(&ctx, end, &oid, &len) == 0 ||
			compare_oid(oid, len, KRB5_OID,
				ARRAY_SIZE(KRB5_OID))) {
		pr_debug("not Kerberos OID\n");
		free(oid);
		return -EINVAL;
	}
	free(oid);

	/* AP_REQ id */
	if (asn1_read(&ctx, &id, 2) == 0 || id[0] != 1 || id[1] != 0) {
		if (id)
			free(id);
		pr_debug("Error decoding AP_REQ id\n");
		return -EINVAL;
	}
	free(id);

	/* AP_REQ */
	*req_len = (unsigned int)(ctx.end - ctx.pointer);
	*krb5_ap_req = ctx.pointer;
	return 0;
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
