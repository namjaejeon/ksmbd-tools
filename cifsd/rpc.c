/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
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

#include <memory.h>
#include <endian.h>
#include <glib.h>
#include <errno.h>
#include <linux/cifsd_server.h>

#include <management/share.h>

#include <rpc.h>
#include <cifsdtools.h>

static GHashTable	*pipes_table;
static GRWLock		pipes_table_lock;

/*
 * We need a proper DCE RPC (ndr/ndr64) parser. And we also need a proper
 * IDL support...
 * Maybe someone smart and cool enough can do it for us. The one you can
 * find here is just a very simple implementation, which sort of works for
 * us, but we do realize that it sucks.
 *
 * Documentation:
 *
 * http://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagfcjh_39
 * https://msdn.microsoft.com/en-us/library/cc243858.aspx
 */

#define SHARE_TYPE_TEMP			0x40000000
#define SHARE_TYPE_HIDDEN		0x80000000

#define SHARE_TYPE_DISKTREE		0
#define SHARE_TYPE_DISKTREE_TEMP	(SHARE_TYPE_DISKTREE|SHARE_TYPE_TEMP)
#define SHARE_TYPE_DISKTREE_HIDDEN	(SHARE_TYPE_DISKTREE|SHARE_TYPE_HIDDEN)
#define SHARE_TYPE_PRINTQ 		1
#define SHARE_TYPE_PRINTQ_TEMP		(SHARE_TYPE_PRINTQ|SHARE_TYPE_TEMP)
#define SHARE_TYPE_PRINTQ_HIDDEN	(SHARE_TYPE_PRINTQ|SHARE_TYPE_HIDDEN)
#define SHARE_TYPE_DEVICE		2
#define SHARE_TYPE_DEVICE_TEMP		(SHARE_TYPE_DEVICE|SHARE_TYPE_TEMP)
#define SHARE_TYPE_DEVICE_HIDDEN	(SHARE_TYPE_DEVICE|SHARE_TYPE_HIDDEN)
#define SHARE_TYPE_IPC			3
#define SHARE_TYPE_IPC_TEMP		(SHARE_TYPE_IPC|SHARE_TYPE_TEMP)
#define SHARE_TYPE_IPC_HIDDEN		(SHARE_TYPE_IPC|SHARE_TYPE_HIDDEN)

#define PAYLOAD_HEAD(d)	((d)->payload + (d)->offset)

#define __ALIGN(x, a)							\
	({								\
		typeof(x) ret = (x);					\
		if (((x) & ((typeof(x))(a) - 1)) != 0)			\
			ret = __ALIGN_MASK(x, (typeof(x))(a) - 1);	\
		ret;							\
	})

#define __ALIGN_MASK(x, mask)	(((x) + (mask)) & ~(mask))

#define SRVSVC_OPNUM_SHARE_ENUM_ALL	15
#define SRVSVC_OPNUM_GET_SHARE_INFO	16

static void align_offset(struct cifsd_dcerpc *dce)
{
	if (dce->flags & CIFSD_DCERPC_ALIGN8) {
		dce->offset = __ALIGN(dce->offset, 8);
	} else if (dce->flags & CIFSD_DCERPC_ALIGN4) {
		dce->offset = __ALIGN(dce->offset, 4);
	}
}

static int try_realloc_payload(struct cifsd_dcerpc *dce, size_t data_sz)
{
	char *n;

	if (dce->offset < dce->payload_sz - data_sz)
		return 0;

	if (dce->flags & CIFSD_DCERPC_FIXED_PAYLOAD_SZ) {
		pr_err("DCE RPC: fixed payload buffer overflow\n");
		return -ENOMEM;
	}

	n = realloc(dce->payload, dce->payload_sz + 4096);
	if (!n)
		return -ENOMEM;

	dce->payload = n;
	dce->payload_sz += 4096;
	memset(dce->payload + dce->offset, 0, dce->payload_sz - dce->offset);
	return 0;
}

#define NDR_WRITE_INT(name, type, be, le)				\
static int ndr_write_##name(struct cifsd_dcerpc *dce, type value)	\
{									\
	if (try_realloc_payload(dce, sizeof(value)))			\
		return -ENOMEM;						\
									\
	if (dce->flags & CIFSD_DCERPC_LITTLE_ENDIAN)			\
		*PAYLOAD_HEAD(dce) = le(value);				\
	else								\
		*PAYLOAD_HEAD(dce) = be(value);				\
									\
	dce->offset += sizeof(value);					\
	align_offset(dce);						\
	return 0;							\
}

NDR_WRITE_INT(int16, __s16, htobe16, htole16);
NDR_WRITE_INT(int32, __s32, htobe32, htole32);
NDR_WRITE_INT(int64, __s64, htobe64, htole64);

#define NDR_READ_INT(name, type, be, le)				\
static type ndr_read_##name(struct cifsd_dcerpc *dce)			\
{									\
	type ret;							\
									\
	if (dce->flags & CIFSD_DCERPC_LITTLE_ENDIAN)			\
		ret = le(*PAYLOAD_HEAD(dce));				\
	else								\
		ret = be(*PAYLOAD_HEAD(dce));				\
									\
	dce->offset += sizeof(type);					\
	align_offset(dce);						\
	return ret;							\
}

NDR_READ_INT(int16, __s16, htobe16, htole16);
NDR_READ_INT(int32, __s32, htobe32, htole32);
NDR_READ_INT(int64, __s64, htobe64, htole64);

static int ndr_write_union(struct cifsd_dcerpc *dce, int value)
{
	int ret;

	/*
	 * For a non-encapsulated union, the discriminant is marshalled into
	 * the transmitted data stream twice: once as the field or parameter,
	 * which is referenced by the switch_is construct, in the procedure
	 * argument list; and once as the first part of the union
	 * representation.
	 */
	ret = ndr_write_int32(dce, value);
	if (ret)
		return ret;
	return ndr_write_int32(dce, value);
}

static int ndr_read_union(struct cifsd_dcerpc *dce)
{
	/*
	 * We need to read 2 __s32 ints and move offset twice
	 */
	int ret = ndr_read_int32(dce);
	if (ndr_read_int32(dce) != ret)
		pr_err("NDR: union level and switch mismatch %d\n", ret);
	return ret;
}

static int ndr_write_bytes(struct cifsd_dcerpc *dce, void *value, size_t sz)
{
	if (try_realloc_payload(dce, sizeof(short)))
		return -ENOMEM;

	memcpy(PAYLOAD_HEAD(dce), value, sz);
	dce->offset += sz;
	align_offset(dce);
	return 0;
}

static int ndr_read_bytes(struct cifsd_dcerpc *dce, void *value, size_t sz)
{
	memcpy(value, PAYLOAD_HEAD(dce), sz);
	dce->offset += sz;
	return 0;
}

static int ndr_write_vstring(struct cifsd_dcerpc *dce, char *value)
{
	gchar *out;
	gsize bytes_read = 0;
	gsize bytes_written = 0;
	GError *err = NULL;

	size_t raw_len, conv_len;
	char *raw_value = value;
	char *conv_value;
	char *charset = CHARSET_UTF16LE;
	int ret;

	if (!value)
		raw_value = "";
	raw_len = strlen(raw_value);

	if (!(dce->flags & CIFSD_DCERPC_LITTLE_ENDIAN))
		charset = CHARSET_UTF16BE;

	if (dce->flags & CIFSD_DCERPC_ASCII_STRING)
		charset = CHARSET_UTF8;

	out = g_convert(raw_value,
			raw_len,
			charset,
			CHARSET_DEFAULT,
			&bytes_read,
			&bytes_written,
			&err);

	if (err) {
		pr_err("Can't convert string: %s\n", err->message);
		g_error_free(err);
		return -EINVAL;
	}

	/*
	 * NDR represents a conformant and varying string as an ordered
	 * sequence of representations of the string elements, preceded
	 * by three unsigned long integers. The first integer gives the
	 * maximum number of elements in the string, including the terminator.
	 * The second integer gives the offset from the first index of the
	 * string to the first index of the actual subset being passed.
	 * The third integer gives the actual number of elements being
	 * passed, including the terminator.
	 */
	ret = ndr_write_int32(dce, bytes_written / 2);
	ret |= ndr_write_int32(dce, 0);
	ret |= ndr_write_int32(dce, bytes_written / 2);
	ret |= ndr_write_bytes(dce, out, bytes_written);
out:
	g_free(out);
	return ret;
}

static char *ndr_read_vstring(struct cifsd_dcerpc *dce)
{
	gchar *out;
	gsize bytes_read = 0;
	gsize bytes_written = 0;
	GError *err = NULL;

	size_t raw_len;
	char *charset = CHARSET_UTF16LE;
	int ret;

	raw_len = ndr_read_int32(dce);
	ndr_read_int32(dce); /* read in offset */
	ndr_read_int32(dce);

	if (!(dce->flags & CIFSD_DCERPC_LITTLE_ENDIAN))
		charset = CHARSET_UTF16BE;

	if (dce->flags & CIFSD_DCERPC_ASCII_STRING)
		charset = CHARSET_UTF8;

	if (raw_len == 0) {
		out = strdup("");
		return out;
	}

	out = g_convert(PAYLOAD_HEAD(dce),
			raw_len * 2,
			CHARSET_DEFAULT,
			charset,
			&bytes_read,
			&bytes_written,
			&err);

	if (err) {
		pr_err("Can't convert string: %s\n", err->message);
		g_error_free(err);
		return NULL;
	}

	dce->offset += raw_len * 2;
	align_offset(dce);
	return out;
}

static void ndr_read_vstring_ptr(struct cifsd_dcerpc *dce,
				 struct ndr_char_ptr *ctr)
{
	ctr->ptr = ndr_read_vstring(dce);
}

static void ndr_read_uniq_vsting_ptr(struct cifsd_dcerpc *dce,
				     struct ndr_uniq_char_ptr *ctr)
{
	ctr->ref_id = ndr_read_int32(dce);
	if (ctr->ref_id == 0) {
		ctr->ptr = 0;
		return;
	}
	ctr->ptr = ndr_read_vstring(dce);
}

static void ndr_read_ptr(struct cifsd_dcerpc *dce,
			 struct ndr_ptr *ctr)
{
	ctr->ptr = ndr_read_int32(dce);
}

static void ndr_read_uniq_ptr(struct cifsd_dcerpc *dce,
			      struct ndr_uniq_ptr *ctr)
{
	ctr->ref_id = ndr_read_int32(dce);
	if (ctr->ref_id = 0) {
		ctr->ptr = 0;
		return;
	}
	ctr->ptr = ndr_read_int32(dce);
}

static int __max_entries(struct cifsd_dcerpc *dce, struct cifsd_rpc_pipe *pipe)
{
	int current_size, i;

	if (!(dce->flags & CIFSD_DCERPC_FIXED_PAYLOAD_SZ))
		return pipe->num_entries;

	if (!dce->entry_size) {
		pr_err("No ->entry_size() callback was provided\n");
		return 0;
	}

	current_size = 0;
	for (i = 0; i < pipe->num_entries; i++) {
		gpointer entry;

		entry = g_array_index(pipe->entries,  gpointer, i);
		current_size += dce->entry_size(dce, entry);

		if (current_size < 4 * dce->payload_sz / 5)
			continue;
		return i;
	}

	return pipe->num_entries;
}

static int ndr_write_array_of_structs(struct cifsd_dcerpc *dce,
				      struct cifsd_rpc_pipe *pipe)
{
	int current_size;
	int max_entry_nr;
	int i, ret, has_more_data = 0;

	/*
	 * In the NDR representation of a structure that contains a
	 * conformant and varying array, the maximum counts for dimensions
	 * of the array are moved to the beginning of the structure, but
	 * the offsets and actual counts remain in place at the end of the
	 * structure, immediately preceding the array elements.
	 */

	max_entry_nr = __max_entries(dce, pipe);
	if (max_entry_nr != pipe->num_entries)
		has_more_data = CIFSD_DCERPC_ERROR_MORE_DATA;

	/*
	 * ARRAY representation [per dimension]
	 *    max_count
	 *    offset
	 *    actual_count
	 *    element representation [1..N]
	 *    actual elements [1..N]
	 */
	ndr_write_int32(dce, max_entry_nr);
	ndr_write_int32(dce, 1);
	ndr_write_int32(dce, max_entry_nr);

	if (max_entry_nr == 0) {
		pr_err("DCERPC: can't fit any data, buffer is too small\n");
		return CIFSD_DCERPC_ERROR_INVALID_LEVEL;
	}

	for (i = 0; i < max_entry_nr; i++) {
		gpointer entry;

		entry = g_array_index(pipe->entries,  gpointer, i);
		ret = dce->entry_rep(dce, entry);

		if (ret != 0)
			return CIFSD_DCERPC_ERROR_INVALID_LEVEL;
	}

	for (i = 0; i < max_entry_nr; i++) {
		gpointer entry;

		entry = g_array_index(pipe->entries,  gpointer, i);
		ret = dce->entry_data(dce, entry);

		if (ret != 0)
			return CIFSD_DCERPC_ERROR_INVALID_LEVEL;
	}

	if (pipe->entry_processed) {
		for (i = 0; i < max_entry_nr; i++)
			pipe->entry_processed(pipe, 0);
	}
	return has_more_data;
}

static int __share_type(struct cifsd_share *share)
{
	if (test_share_flag(share, CIFSD_SHARE_FLAG_PIPE))
		return SHARE_TYPE_IPC;
	if (!g_ascii_strncasecmp(share->name, "IPC", strlen("IPC")))
		return SHARE_TYPE_IPC;
	return SHARE_TYPE_DISKTREE;
}

static int __share_entry_size_ctr0(struct cifsd_dcerpc *dce, gpointer entry)
{
	struct cifsd_share *share = entry;

	return strlen(share->name) * 2 + 4 * sizeof(__u32);
}

static int __share_entry_size_ctr1(struct cifsd_dcerpc *dce, gpointer entry)
{
	struct cifsd_share *share = entry;
	int sz;

	sz = strlen(share->name) * 2 + strlen(share->comment) * 2;
	sz += 9 * sizeof(__u32);
	return sz;
}

/*
 * Embedded Reference Pointers
 *
 * An embedded reference pointer is represented in two parts, a 4 octet
 * value in place and a possibly deferred representation of the referent.
 */
static int __share_entry_rep_ctr0(struct cifsd_dcerpc *dce, gpointer entry)
{
	struct cifsd_share *share = entry;

	return ndr_write_int32(dce, 1); /* ref pointer */
}

static int __share_entry_rep_ctr1(struct cifsd_dcerpc *dce, gpointer entry)
{
	struct cifsd_share *share = entry;
	int ret;

	ret = ndr_write_int32(dce, 1); /* ref pointer */
	ret |= ndr_write_int32(dce, __share_type(share));
	ret |= ndr_write_int32(dce, 1); /* ref pointer */
	return ret;
}

static int __share_entry_data_ctr0(struct cifsd_dcerpc *dce, gpointer entry)
{
	struct cifsd_share *share = entry;

	return ndr_write_vstring(dce, share->name);
}

static int __share_entry_data_ctr1(struct cifsd_dcerpc *dce, gpointer entry)
{
	struct cifsd_share *share = entry;
	int ret;

	ret = ndr_write_vstring(dce, share->name);
	ret |= ndr_write_vstring(dce, share->comment);
	return ret;
}

static int __share_entry_processed(struct cifsd_rpc_pipe *pipe, int i)
{
	struct cifsd_share *share;

	share = g_array_index(pipe->entries,  gpointer, i);
	pipe->entries = g_array_remove_index(pipe->entries, i);
	pipe->num_entries--;
	put_cifsd_share(share);
}

static void __enum_all_shares(gpointer key, gpointer value, gpointer user_data)
{
	struct cifsd_rpc_pipe *pipe = (struct cifsd_rpc_pipe *)user_data;
	struct cifsd_share *share = (struct cifsd_share *)value;

	if (!get_cifsd_share(share))
		return;

	pipe->entries = g_array_append_val(pipe->entries, share);
	pipe->num_entries++;
}

static int srvsvc_share_enum_all_invoke(struct cifsd_rpc_pipe *pipe)
{
	for_each_cifsd_share(__enum_all_shares, pipe);
	pipe->entry_processed = __share_entry_processed;
	return 0;
}

static int srvsvc_share_get_info_invoke(struct cifsd_rpc_pipe *pipe,
					struct srvsvc_share_info_request *hdr)
{
	struct cifsd_share *share;

	share = shm_lookup_share(hdr->share_name.ptr);
	if (!share)
		return -EINVAL;

	pipe->entries = g_array_append_val(pipe->entries, share);
	pipe->num_entries++;
	pipe->entry_processed = __share_entry_processed;
	return 0;
}

struct cifsd_rpc_pipe *rpc_pipe_lookup(unsigned int id)
{
	struct cifsd_rpc_pipe *pipe;

	g_rw_lock_reader_lock(&pipes_table_lock);
	pipe = g_hash_table_lookup(pipes_table, &id);
	g_rw_lock_reader_unlock(&pipes_table_lock);

	return pipe;
}

struct cifsd_rpc_pipe *rpc_pipe_alloc_bind(unsigned int id)
{
	struct cifsd_rpc_pipe *pipe = rpc_pipe_alloc();
	int ret;

	if (!pipe)
		return NULL;

	pipe->id = id;
	g_rw_lock_writer_lock(&pipes_table_lock);
	ret = g_hash_table_insert(pipes_table, &(pipe->id), pipe);
	g_rw_lock_writer_unlock(&pipes_table_lock);

	if (!ret) {
		pipe->id = (unsigned int)-1;
		rpc_pipe_free(pipe);
		pipe = NULL;
	}
	return pipe;
}

struct cifsd_rpc_pipe *rpc_pipe_alloc(void)
{
	struct cifsd_rpc_pipe *pipe = malloc(sizeof(struct cifsd_rpc_pipe));

	if (!pipe)
		return NULL;

	memset(pipe, 0x00, sizeof(struct cifsd_rpc_pipe));
	pipe->id = -1;
	pipe->entries = g_array_new(0, 0, sizeof(void *));
	if (!pipe->entries) {
		rpc_pipe_free(pipe);
		return NULL;
	}
	return pipe;
}

static void __rpc_pipe_free(struct cifsd_rpc_pipe *pipe)
{
	if (pipe->entry_processed) {
		while (pipe->num_entries)
			pipe->entry_processed(pipe, 0);
	}

	if (pipe->dce)
		dcerpc_free(pipe->dce);
	g_array_free(pipe->entries, 0);
	free(pipe);
}

void rpc_pipe_free(struct cifsd_rpc_pipe *pipe)
{
	if (pipe->id != (unsigned int)-1) {
		g_rw_lock_writer_lock(&pipes_table_lock);
		g_hash_table_remove(pipes_table, &(pipe->id));
		g_rw_lock_writer_unlock(&pipes_table_lock);
	}

	__rpc_pipe_free(pipe);
}

void dcerpc_free(struct cifsd_dcerpc *dce)
{
	if (!(dce->flags & CIFSD_DCERPC_EXTERNAL_PAYLOAD))
		free(dce->payload);
	free(dce);
}

struct cifsd_dcerpc *dcerpc_alloc(unsigned int flags, int sz)
{
	struct cifsd_dcerpc *dce;

	dce = malloc(sizeof(struct cifsd_dcerpc));
	if (!dce)
		return NULL;

	memset(dce, 0x00, sizeof(struct cifsd_dcerpc));
	dce->payload = malloc(sz);
	if (!dce->payload) {
		free(dce);
		return NULL;
	}

	memset(dce->payload, sz, 0x00);
	dce->payload_sz = sz;
	dce->flags = flags;

	if (sz == CIFSD_DCERPC_MAX_PREFERRED_SIZE)
		dce->flags &= ~CIFSD_DCERPC_FIXED_PAYLOAD_SZ;
	return dce;
}

struct cifsd_dcerpc *dcerpc_ext_alloc(unsigned int flags,
				      void *payload,
				      int payload_sz)
{
	struct cifsd_dcerpc *dce;

	dce = malloc(sizeof(struct cifsd_dcerpc));
	if (!dce)
		return NULL;

	memset(dce, 0x00, sizeof(struct cifsd_dcerpc));
	dce->payload = payload;
	dce->payload_sz = payload_sz;

	dce->flags = flags;
	dce->flags |= CIFSD_DCERPC_EXTERNAL_PAYLOAD;
	dce->flags |= CIFSD_DCERPC_FIXED_PAYLOAD_SZ;
	return dce;
}

static int srvsvc_parse_share_info_req(struct cifsd_dcerpc *dce,
				       struct srvsvc_share_info_request *hdr)
{
	ndr_read_uniq_vsting_ptr(dce, &hdr->server_name);

	if (dce->req_hdr.opnum == SRVSVC_OPNUM_SHARE_ENUM_ALL) {
		int ptr;

		hdr->level = ndr_read_int32(dce);
		ndr_read_int32(dce); // read switch selector
		ndr_read_int32(dce); // read container pointer ref id
		ndr_read_int32(dce); // read container array size
		ptr = ndr_read_int32(dce); // read container array pointer
					   // it should be null
		if (ptr != 0x00) {
			pr_err("SRVSVC: container array pointer is %p\n",
				ptr);
			return -EINVAL;
		}
		hdr->max_size = ndr_read_int32(dce);
		ndr_read_uniq_ptr(dce, &hdr->payload_handle);
		return 0;
	}

	if (dce->req_hdr.opnum == SRVSVC_OPNUM_GET_SHARE_INFO) {
		ndr_read_vstring_ptr(dce, &hdr->share_name);
		hdr->level = ndr_read_int32(dce);
		return 0;
	}

	return -ENOTSUP;
}

static int rpc_parse_dcerpc_hdr(struct cifsd_dcerpc *dce,
				struct dcerpc_header *hdr)
{
	/* Common Type Header for the Serialization Stream */

	ndr_read_bytes(dce, &hdr->rpc_vers, sizeof(hdr->rpc_vers));
	ndr_read_bytes(dce, &hdr->rpc_vers_minor, sizeof(hdr->rpc_vers_minor));
	ndr_read_bytes(dce, &hdr->ptype, sizeof(hdr->ptype));
	ndr_read_bytes(dce, &hdr->pfc_flags, sizeof(hdr->pfc_flags));
	/*
	 * This common type header MUST be presented by using
	 * little-endian format in the octet stream. The first
	 * byte of the common type header MUST be equal to 1 to
	 * indicate level 1 of type serialization.
	 *
	 * Type serialization version 1 can use either a little-endian
	 * or big-endian integer and floating-pointer byte order but
	 * MUST use the IEEE floating-point format representation and
	 * ASCII character format. See the following figure.
	 */
	ndr_read_bytes(dce, &hdr->packed_drep, sizeof(hdr->packed_drep));

	if (hdr->packed_drep[0] == DCERPC_SERIALIZATION_TYPE2) {
		pr_err("DCERPC: unsupported serialization type %d\n",
				hdr->packed_drep[0]);
		return -EINVAL;
	}

	dce->flags |= CIFSD_DCERPC_ALIGN4;
	dce->flags |= CIFSD_DCERPC_LITTLE_ENDIAN;
	if (hdr->packed_drep[1] != DCERPC_SERIALIZATION_LITTLE_ENDIAN)
		dce->flags &= ~CIFSD_DCERPC_LITTLE_ENDIAN;

	hdr->frag_length = ndr_read_int16(dce);
	hdr->auth_length = ndr_read_int16(dce);
	hdr->call_id = ndr_read_int32(dce);

	return 0;
}

static int rpc_parse_dcerpc_request_hdr(struct cifsd_dcerpc *dce,
					struct dcerpc_request_header *hdr)
{
	hdr->alloc_hint = ndr_read_int32(dce);
	hdr->context_id = ndr_read_int16(dce);
	hdr->opnum = ndr_read_int16(dce);
	return 0;
}

static int srvsvc_share_info_invoke(struct cifsd_dcerpc *dce)
{
	struct cifsd_rpc_pipe *pipe;
	int ret = -ENOTSUP;

	if (srvsvc_parse_share_info_req(dce, &dce->req))
		return -EINVAL;

	pipe = rpc_pipe_lookup(dce->rpc_req->handle);
	if (!pipe)
		return -EINVAL;

	if (pipe->dce) {
		pr_err("SRVSVC: pipe already has associated DCE\n");
		dcerpc_free(pipe->dce);
	}

	pipe->dce = dce;
	pipe->entry_processed = __share_entry_processed;

	if (dce->req_hdr.opnum == SRVSVC_OPNUM_GET_SHARE_INFO)
		ret = srvsvc_share_get_info_invoke(pipe, &dce->req);
	if (dce->req_hdr.opnum == SRVSVC_OPNUM_SHARE_ENUM_ALL)
		ret = srvsvc_share_enum_all_invoke(pipe);
	return ret;
}

static int srvsvc_invoke(struct cifsd_rpc_command *req,
			 struct cifsd_rpc_command *resp)
{
	struct cifsd_dcerpc *dce;
	int ret = -ENOTSUP;

	dce = dcerpc_ext_alloc(CIFSD_DCERPC_LITTLE_ENDIAN|CIFSD_DCERPC_ALIGN4,
			       req->payload,
			       req->payload_sz);
	if (!dce)
		return -EINVAL;

	dce->rpc_req = req;
	dce->rpc_resp = resp;

	ret = rpc_parse_dcerpc_hdr(dce, &dce->hdr);
	ret |= rpc_parse_dcerpc_request_hdr(dce, &dce->req_hdr);
	if (ret) {
		dcerpc_free(dce);
		return ret;
	}

	switch (dce->req_hdr.opnum) {
	case DCERPC_PTYPE_RPC_BIND:
		pr_err("SRVSVC: BIND: %d\n", dce->hdr.ptype);
		ret = 0;
		break;
	case SRVSVC_OPNUM_SHARE_ENUM_ALL:
	case SRVSVC_OPNUM_GET_SHARE_INFO:
		ret = srvsvc_share_info_invoke(dce);
		break;
	default:
		pr_err("SRVSVC: unsupported method %d\n",
			dce->req_hdr.opnum);
		dcerpc_free(dce);
		break;
	}

	return ret;
}

static int srvsvc_share_info_return(struct cifsd_rpc_pipe *pipe,
				    struct cifsd_dcerpc *dce)
{
	int ret, payload_offset;

	/*
	 * Reserve space for response NDR header. We don't know yet if
	 * the payload buffer is big enough. This will determine if we
	 * can set DCERPC_PFC_FIRST_FRAG|DCERPC_PFC_LAST_FRAG or if we
	 * will have a multi-part response.
	 */
	dce->offset = sizeof(struct dcerpc_header);

	if (dce->req.level == 0) {
		dce->entry_size = __share_entry_size_ctr0;
		dce->entry_rep = __share_entry_rep_ctr0;
		dce->entry_data = __share_entry_data_ctr0;
	} else if (dce->req.level == 1) {
		dce->entry_size = __share_entry_size_ctr1;
		dce->entry_rep = __share_entry_rep_ctr1;
		dce->entry_data = __share_entry_data_ctr1;
	} else {
		ret = CIFSD_DCERPC_ERROR_INVALID_LEVEL;
		goto out;
	}

	ndr_write_union(dce, dce->req.level);
	ndr_write_int32(dce, pipe->num_entries);

	ret = ndr_write_array_of_structs(dce, pipe);

	payload_offset = dce->offset;
	dce->offset = 0;

	dce->hdr.ptype = DCERPC_PTYPE_RPC_RESPONSE;
	dce->hdr.pfc_flags = DCERPC_PFC_FIRST_FRAG | DCERPC_PFC_LAST_FRAG;
	if (ret == CIFSD_DCERPC_ERROR_MORE_DATA)
		dce->hdr.pfc_flags = 0;

	ndr_write_bytes(dce, &dce->hdr, sizeof(dce->hdr));
	dce->offset = payload_offset;
out:
	/*
	 * [out] DWORD* TotalEntries
	 * [out, unique] DWORD* ResumeHandle
	 * [out] DWORD Return value/code
	 */
	ndr_write_int32(dce, pipe->num_entries);
	if (ret == CIFSD_DCERPC_ERROR_MORE_DATA)
		ndr_write_int32(dce, 0x01);
	else
		ndr_write_int32(dce, 0x00);
	ndr_write_int32(dce, ret);

	return ret;
}

static int srvsvc_return(struct cifsd_rpc_command *req,
			 struct cifsd_rpc_command *resp,
			 int max_resp_sz)
{
	struct cifsd_rpc_pipe *pipe;
	struct cifsd_dcerpc *dce;
	int ret = -ENOTSUP;

	pipe = rpc_pipe_lookup(req->handle);
	if (!pipe || pipe->dce) {
		pr_err("SRVSVC: no pipe or pipe has no associated DCE\n");
		return -EINVAL;
	}

	dce = pipe->dce;
	if (dce->req.max_size < (unsigned int)max_resp_sz)
		max_resp_sz = dce->req.max_size;
	dce->rpc_resp = resp;
	dce->payload = resp->payload;
	dce->payload_sz = max_resp_sz;

	switch (dce->req_hdr.opnum) {
	case DCERPC_PTYPE_RPC_BIND:
		pr_err("SRVSVC: BIND: %d\n", dce->hdr.ptype);
		ret = 0;
		break;
	case SRVSVC_OPNUM_SHARE_ENUM_ALL:
	case SRVSVC_OPNUM_GET_SHARE_INFO:
		ret = srvsvc_share_info_return(pipe, dce);
		break;
	default:
		pr_err("SRVSVC: unsupported method %d\n",
			dce->req_hdr.opnum);
		break;
	}
	return ret;
}

int rpc_srvsvc_request(struct cifsd_rpc_command *req,
		       struct cifsd_rpc_command *resp,
		       int max_resp_sz)
{
	if (req->flags & CIFSD_RPC_COMMAND_METHOD_INVOKE)
		return srvsvc_invoke(req, resp);

	return srvsvc_return(req, resp, max_resp_sz);
}

int rpc_init(void)
{
	pipes_table = g_hash_table_new(g_int_hash, g_int_equal);
	if (!pipes_table)
		return -ENOMEM;
	g_rw_lock_init(&pipes_table_lock);
	return 0;
}

static void free_hash_entry(gpointer k, gpointer s, gpointer user_data)
{
	__rpc_pipe_free(s);
}

static void __clear_pipes_table(void)
{
	g_rw_lock_writer_lock(&pipes_table_lock);
	g_hash_table_foreach(pipes_table, free_hash_entry, NULL);
	g_rw_lock_writer_unlock(&pipes_table_lock);
}

void rpc_destroy(void)
{
	__clear_pipes_table();
	g_hash_table_destroy(pipes_table);
	g_rw_lock_clear(&pipes_table_lock);
}
