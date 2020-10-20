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
#include <rpc_lsarpc.h>
#include <smbacl.h>
#include <ksmbdtools.h>

#define LSARPC_OPNUM_DS_ROLE_GET_PRIMARY_DOMAIN_INFO	0
#define LSARPC_OPNUM_OPEN_POLICY2			44
#define LSARPC_OPNUM_QUERY_INFO_POLICY			7
#define LSARPC_OPNUM_LOOKUP_SID2			57
#define LSARPC_OPNUM_LOOKUP_NAMES3			68
#define LSARPC_OPNUM_CLOSE				0

#define DS_ROLE_STANDALONE_SERVER	2
#define DS_ROLE_BASIC_INFORMATION	1

#define LSA_POLICY_INFO_ACCOUNT_DOMAIN	5

static int lsarpc_get_primary_domain_info_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int level;

	level = ndr_read_int16(dce);
	if (level != DS_ROLE_BASIC_INFORMATION)
		return KSMBD_RPC_EBAD_FUNC; 

	return KSMBD_RPC_OK;
}

static int lsarpc_get_primary_domain_info_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int i;
	char domain_string[256];

	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // ref pointer
	ndr_write_int16(dce, 1); // count
	ndr_write_int16(dce, 0);
	ndr_write_int16(dce, DS_ROLE_STANDALONE_SERVER); // role
	ndr_write_int16(dce, 0);
	ndr_write_int32(dce, 0); // flags
	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // ref pointer
	ndr_write_int32(dce, 0); // NULL pointer : Pointer to Dns Domain
	ndr_write_int32(dce, 0); // NULL pointer : Pointer to Forest

	/* NULL Domain guid */
	for (i = 0; i < 16; i++)
		ndr_write_int8(dce, 0);
	
	gethostname(domain_string, 256);
	ndr_write_vstring(dce, domain_string); // domain string

	return KSMBD_RPC_OK;
}

static int lsarpc_open_policy2_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;

	/* write connect handle */
	ndr_write_int64(dce, (__u64)(pipe->id + 1));
	ndr_write_int64(dce, (__u64)(pipe->id + 1));
	ndr_write_int32(dce, 0);
	return KSMBD_RPC_OK;
}

static int lsarpc_query_info_policy_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	unsigned long long id;
	int level;

	id = ndr_read_int64(dce);
	ndr_read_int64(dce);
	ndr_read_int32(dce);
	if (id != pipe->id + 1)
		return KSMBD_RPC_EBAD_FID;

	level = ndr_read_int16(dce);
	if (level != LSA_POLICY_INFO_ACCOUNT_DOMAIN)
		return KSMBD_RPC_EBAD_FUNC; 

	return KSMBD_RPC_OK;
}

int lsarpc_ndr_write_vstring(struct ksmbd_dcerpc *dce, char *value)
{
	gchar *out;
	gsize bytes_read = 0;
	gsize bytes_written = 0;

	size_t raw_len;
	char *raw_value = value;
	int charset = KSMBD_CHARSET_UTF16LE;
	int ret;

	if (!value)
		raw_value = "";
	raw_len = strlen(raw_value);

	if (!(dce->flags & KSMBD_DCERPC_LITTLE_ENDIAN))
		charset = KSMBD_CHARSET_UTF16BE;

	if (dce->flags & KSMBD_DCERPC_ASCII_STRING)
		charset = KSMBD_CHARSET_UTF8;

	out = ksmbd_gconvert(raw_value,
			     raw_len,
			     charset,
			     KSMBD_CHARSET_DEFAULT,
			     &bytes_read,
			     &bytes_written);
	if (!out)
		return -EINVAL;

	ret = ndr_write_int32(dce, raw_len + 1);
	ret |= ndr_write_int32(dce, 0);
	ret |= ndr_write_int32(dce, raw_len);
	ret |= ndr_write_bytes(dce, out, bytes_written);
	auto_align_offset(dce);

	g_free(out);
	return ret;
}

static int lsarpc_query_info_policy_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	char domain_string[256];
	struct smb_sid sid;
	int len;

	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // ref pointer
	ndr_write_int16(dce, LSA_POLICY_INFO_ACCOUNT_DOMAIN); // level
	ndr_write_int16(dce, 0);

	/* Account Domain */
	gethostname(domain_string, 256); // domain string
	len = strlen(domain_string);
	ndr_write_int16(dce, (len+1)*2); // length
	ndr_write_int16(dce, len*2); // size
	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // ref pointer

	/* Pointer to Sid */
	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers);
	lsarpc_ndr_write_vstring(dce, domain_string); // domain string
	smb_init_domain_sid(&sid);
	ndr_write_int32(dce, sid.num_subauth); // count
	smb_write_sid(dce, &sid); // sid

	return KSMBD_RPC_OK;
}

static int lsarpc_lookup_sid2_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	unsigned long long id;
	unsigned int num_sid, i;

	id = ndr_read_int64(dce);
	ndr_read_int64(dce);
	ndr_read_int32(dce);
	if (id != pipe->id + 1)
		return KSMBD_RPC_EBAD_FID;

	num_sid = ndr_read_int32(dce);
	ndr_read_int32(dce); // ref pointer 
	ndr_read_int32(dce); // max count

	for (i = 0; i < num_sid; i++)
		ndr_read_int32(dce); // ref pointer

	for (i = 0; i < num_sid; i++) {
		struct user_info *ui;
		struct passwd *passwd;
		int rid;

		ui = malloc(sizeof(struct user_info));
		if (!ui)
			break;

		ndr_read_int32(dce); // max count
		smb_read_sid(dce, &ui->sid); // sid
		ui->sid.num_subauth--;
		rid = ui->sid.sub_auth[ui->sid.num_subauth];
		passwd = getpwuid(rid);
		if (!passwd) {
			free(ui);
			continue;
		}

		ui->user = usm_lookup_user(passwd->pw_name);
		if (!ui->user)
			break;

		if (get_sid_info(&ui->sid, &ui->type, ui->domain_name) < 0);
			break;

		pipe->entries = g_array_append_val(pipe->entries, ui);
		pipe->num_entries++;
	}

	return KSMBD_RPC_OK;
}

static int lsarpc_lookup_sid2_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int i;

	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // ref pointer
	ndr_write_int32(dce, pipe->num_entries); // count

	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // ref pointer
	ndr_write_int32(dce, pipe->num_entries); // max count

	for (i = 0; i < pipe->num_entries; i++) {
		struct user_info *ui;
		int max_cnt, actual_cnt;

		ui = (struct user_info *)g_array_index(pipe->entries, gpointer, i);
		actual_cnt = strlen(ui->domain_name);
		max_cnt = actual_cnt + 1;
		ndr_write_int32(dce, actual_cnt * 2); // length
		ndr_write_int32(dce, max_cnt * 2); // size
		dce->num_pointers++;
		ndr_write_int32(dce, dce->num_pointers); /* ref pointer for domain name*/
		dce->num_pointers++;
		ndr_write_int32(dce, dce->num_pointers); /* ref pointer for sid*/
	}

	for (i = 0; i < pipe->num_entries; i++) {
		struct user_info *ui;

		ui = (struct user_info *)g_array_index(pipe->entries, gpointer, i);
		ndr_write_vstring(dce, ui->domain_name); // domain string
		ndr_write_int32(dce, ui->sid.num_subauth); // count
		smb_write_sid(dce, &ui->sid); // sid
	}

	/* Pointer to Names */	
	ndr_write_int32(dce, pipe->num_entries); // count
	dce->num_pointers++; // ref pointer
	ndr_write_int32(dce, dce->num_pointers);
	ndr_write_int32(dce, pipe->num_entries); // max count

	for (i = 0; i < pipe->num_entries; i++) {
		struct user_info *ui;
		int len;

		ui = (struct user_info *)g_array_index(pipe->entries, gpointer, i);
		ndr_write_int16(dce, ui->type); // sid type
		ndr_write_int16(dce, 0);
		len = strlen(ui->user->name);
		ndr_write_int16(dce, len); // length
		ndr_write_int16(dce, len); // size
		dce->num_pointers++; // ref pointer
		ndr_write_int32(dce, dce->num_pointers);
		ndr_write_int32(dce, i); // sid index
		ndr_write_int32(dce, 0); // unknown
	}

	for (i = 0; i < pipe->num_entries; i++) {
		struct user_info *ui;

		ui = (struct user_info *)g_array_index(pipe->entries, gpointer, i);
		ndr_write_vstring(dce, ui->user->name); // username
		ndr_write_int32(dce, ui->sid.num_subauth); // count
		smb_write_sid(dce, &ui->sid); // sid
	}
	
	ndr_write_int32(dce, pipe->num_entries); // count

	return KSMBD_RPC_OK;
}

static int lsarpc_lookup_names3_invoke(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct ndr_uniq_char_ptr username;
	unsigned long long id;
	int num_names, i;

	id = ndr_read_int64(dce);
	ndr_read_int64(dce);
	ndr_read_int32(dce);
	if (id != pipe->id + 1)
		return KSMBD_RPC_EBAD_FID;

	num_names = ndr_read_int32(dce); // num names
	ndr_read_int32(dce); // max count

	for (i = 0; i < num_names; i++) {	
		struct user_info *ui;
		char *name;

		ui = malloc(sizeof(struct user_info));
		if (!ui)
			break;
		ndr_read_int16(dce); // length
		ndr_read_int16(dce); // size
		ndr_read_uniq_vsting_ptr(dce, &username);
		if (strstr(STR_VAL(username), "\\")) {
			strtok(STR_VAL(username), "\\");
			name = strtok(NULL, "\\");
		}

		ui->user = usm_lookup_user(name);
		if (!ui->user)
			break;
		pipe->entries = g_array_append_val(pipe->entries, ui);
		pipe->num_entries++;
		smb_init_domain_sid(&ui->sid);
	}

	return KSMBD_RPC_OK;
}

static int lsarpc_lookup_names3_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int len, i;
	char domain_string[256];
	struct smb_sid sid;

	/* Domain list */
	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // ref pointer

	ndr_write_int32(dce, 1); // domain count
	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // ref pointer
	ndr_write_int32(dce, 32); // max size
	ndr_write_int32(dce, 1); // max count

	gethostname(domain_string, 256);
	len = strlen(domain_string);
	ndr_write_int16(dce, len*2); // domain string length
	ndr_write_int16(dce, (len+1)*2); // domain string size

	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // domain string ref pointer
	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // sid ref pointer
	lsarpc_ndr_write_vstring(dce, domain_string); // domain string
	smb_init_domain_sid(&sid);
	ndr_write_int32(dce, sid.num_subauth); // sid auth count
	smb_write_sid(dce, &sid); // sid

	ndr_write_int32(dce, pipe->num_entries); // count
	dce->num_pointers++;
	ndr_write_int32(dce, dce->num_pointers); // sid ref id
	ndr_write_int32(dce, pipe->num_entries); // count
	
	for (i = 0; i < pipe->num_entries; i++) {
		ndr_write_int16(dce, SID_TYPE_USER); // sid type
		ndr_write_int16(dce, 0);
		dce->num_pointers++;
		ndr_write_int32(dce, dce->num_pointers); // ref pointer
		ndr_write_int32(dce, i); // sid index
		ndr_write_int32(dce, 0);
	}

	for (i = 0; i < pipe->num_entries; i++) {
		struct user_info *ui;

		ui = (struct user_info *)g_array_index(pipe->entries, gpointer, i);
		ndr_write_int32(dce, ++ui->sid.num_subauth); // sid auth count
		smb_write_sid(dce, &ui->sid); // sid
		ndr_write_int32(dce, ui->user->uid); // rid
	}

	ndr_write_int32(dce, pipe->num_entries);

	return KSMBD_RPC_OK;
}

static int lsarpc_close_return(struct ksmbd_rpc_pipe *pipe)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	struct policy_handle *ph;
	unsigned long long id;
	int i;

	for (i = 0; i < pipe->num_entries; i++) {
		gpointer entry;

		entry = g_array_index(pipe->entries, gpointer, i);
		pipe->entries = g_array_remove_index(pipe->entries, i);
		free(entry);
	}

	ndr_write_int64(dce, 0);
	ndr_write_int64(dce, 0);
	ndr_write_int32(dce, 0);
}

static int lsarpc_invoke(struct ksmbd_rpc_pipe *pipe)
{
	int ret = KSMBD_RPC_ENOTIMPLEMENTED;

	switch (pipe->dce->req_hdr.opnum) {
	case LSARPC_OPNUM_DS_ROLE_GET_PRIMARY_DOMAIN_INFO || LSARPC_OPNUM_CLOSE:
		if (pipe->dce->hdr.frag_length == 26)
			ret = lsarpc_get_primary_domain_info_invoke(pipe);
		else
			ret = KSMBD_RPC_OK;
		break;
	case LSARPC_OPNUM_OPEN_POLICY2:
		break;
	case LSARPC_OPNUM_QUERY_INFO_POLICY:
		ret = lsarpc_query_info_policy_invoke(pipe);
		break;
	case LSARPC_OPNUM_LOOKUP_SID2:
		ret = lsarpc_lookup_sid2_invoke(pipe);
		break;
	case LSARPC_OPNUM_LOOKUP_NAMES3:
		ret = lsarpc_lookup_names3_invoke(pipe);
		break;
	default:
		pr_err("LSARPC: unsupported INVOKE method %d, alloc_hint : %d\n",
		       pipe->dce->req_hdr.opnum, pipe->dce->req_hdr.alloc_hint);
		break;
	}

	return ret;
}

static int lsarpc_return(struct ksmbd_rpc_pipe *pipe,
			 struct ksmbd_rpc_command *resp,
			 int max_resp_sz)
{
	struct ksmbd_dcerpc *dce = pipe->dce;
	int status = KSMBD_RPC_ENOTIMPLEMENTED;

	dce->offset = sizeof(struct dcerpc_header);
	dce->offset += sizeof(struct dcerpc_response_header);

	switch (dce->req_hdr.opnum) {
	case LSARPC_OPNUM_DS_ROLE_GET_PRIMARY_DOMAIN_INFO || LSARPC_OPNUM_CLOSE:
		if (dce->hdr.frag_length == 26)
			status = lsarpc_get_primary_domain_info_return(pipe);
		else
			status = lsarpc_close_return(pipe);
		break;
	case LSARPC_OPNUM_OPEN_POLICY2:
		status = lsarpc_open_policy2_return(pipe);
		break;
	case LSARPC_OPNUM_QUERY_INFO_POLICY:
		status = lsarpc_query_info_policy_return(pipe);
		break;
	case LSARPC_OPNUM_LOOKUP_SID2:
		status = lsarpc_lookup_sid2_return(pipe);
		break;
	case LSARPC_OPNUM_LOOKUP_NAMES3:
		status = lsarpc_lookup_names3_return(pipe);
		break;
	default:
		pr_err("LSARPC: unsupported RETURN method %d\n",
			dce->req_hdr.opnum);
		status = KSMBD_RPC_EBAD_FUNC;
		break;
	}

	/*
	 * [out] DWORD Return value/code
	 */
	ndr_write_int32(dce, status);
	dcerpc_write_headers(dce, status);

	dce->rpc_resp->payload_sz = dce->offset;
	return status;
}

int rpc_lsarpc_read_request(struct ksmbd_rpc_pipe *pipe,
			    struct ksmbd_rpc_command *resp,
			    int max_resp_sz)
{
	return lsarpc_return(pipe, resp, max_resp_sz);
}

int rpc_lsarpc_write_request(struct ksmbd_rpc_pipe *pipe)
{
	return lsarpc_invoke(pipe);
}
