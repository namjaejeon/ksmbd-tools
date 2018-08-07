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
 * Version 2.0 data representation protocol
 *
 * UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860
 * VERSION: 2
 */
static struct dcerpc_syntax known_syntaxes[] = {
	{
		.uuid.time_low = 0x8a885d04,
		.uuid.time_mid = 0x1ceb,
		.uuid.time_hi_and_version = 0x11c9,
		.uuid.clock_seq = {0x9f, 0xe8},
		.uuid.node = {0x8, 0x0, 0x2b, 0x10, 0x48, 0x60},
		.ver_major = 0x2,
		.ver_minor = 0x0,
	},
};

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

static void align_offset(struct cifsd_dcerpc *dce, size_t n)
{
	dce->offset = __ALIGN(dce->offset, n);
}

static void auto_align_offset(struct cifsd_dcerpc *dce)
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

	if (dce->offset + data_sz < dce->payload_sz)
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

static __u8 noop_int8(__u8 v)
{
	return v;
}

#define htobe_n noop_int8
#define htole_n noop_int8
#define betoh_n noop_int8
#define letoh_n noop_int8

#define NDR_WRITE_INT(name, type, be, le)				\
static int ndr_write_##name(struct cifsd_dcerpc *dce, type value)	\
{									\
	type ret;							\
									\
	if (try_realloc_payload(dce, sizeof(value)))			\
		return -ENOMEM;						\
									\
	align_offset(dce, sizeof(type));				\
	if (dce->flags & CIFSD_DCERPC_LITTLE_ENDIAN)			\
		*(type *)PAYLOAD_HEAD(dce) = le(value);			\
	else								\
		*(type *)PAYLOAD_HEAD(dce) = be(value);			\
	dce->offset += sizeof(value);					\
	return 0;							\
}

NDR_WRITE_INT( int8,  __u8, htobe_n, htole_n);
NDR_WRITE_INT(int16, __u16, htobe16, htole16);
NDR_WRITE_INT(int32, __u32, htobe32, htole32);
NDR_WRITE_INT(int64, __u64, htobe64, htole64);

#define NDR_READ_INT(name, type, be, le)				\
static type ndr_read_##name(struct cifsd_dcerpc *dce)			\
{									\
	type ret;							\
									\
	align_offset(dce, sizeof(type));				\
	if (dce->flags & CIFSD_DCERPC_LITTLE_ENDIAN)			\
		ret = le(*(type *)PAYLOAD_HEAD(dce));			\
	else								\
		ret = be(*(type *)PAYLOAD_HEAD(dce));			\
	dce->offset += sizeof(type);					\
	return ret;							\
}

NDR_READ_INT( int8,  __u8, betoh_n, letoh_n);
NDR_READ_INT(int16, __u16, be16toh, le16toh);
NDR_READ_INT(int32, __u32, be32toh, le32toh);
NDR_READ_INT(int64, __u64, be64toh, le64toh);

/*
 * For a non-encapsulated union, the discriminant is marshalled into
 * the transmitted data stream twice: once as the field or parameter,
 * which is referenced by the switch_is construct, in the procedure
 * argument list; and once as the first part of the union
 * representation.
 */
#define NDR_WRITE_UNION(dce,name,value)				\
	({							\
		int ret;					\
								\
		ret = ndr_write_##name(dce, value);		\
		ret |= ndr_write_##name(dce, value);		\
								\
		ret;						\
	 })

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

	align_offset(dce, 2);
	memcpy(PAYLOAD_HEAD(dce), value, sz);
	dce->offset += sz;
	return 0;
}

static int ndr_read_bytes(struct cifsd_dcerpc *dce, void *value, size_t sz)
{
	align_offset(dce, 2);
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
	raw_len = strlen(raw_value) + 1;

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
	ret = ndr_write_int32(dce, raw_len);
	ret |= ndr_write_int32(dce, 0);
	ret |= ndr_write_int32(dce, raw_len);
	ret |= ndr_write_bytes(dce, out, bytes_written);
	auto_align_offset(dce);
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
	auto_align_offset(dce);
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
	int i, ret = CIFSD_RPC_COMMAND_OK;

	/*
	 * In the NDR representation of a structure that contains a
	 * conformant and varying array, the maximum counts for dimensions
	 * of the array are moved to the beginning of the structure, but
	 * the offsets and actual counts remain in place at the end of the
	 * structure, immediately preceding the array elements.
	 */

	max_entry_nr = __max_entries(dce, pipe);
	if (max_entry_nr != pipe->num_entries)
		ret = CIFSD_RPC_COMMAND_ERROR_MORE_DATA;

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
		return CIFSD_RPC_COMMAND_ERROR_BAD_DATA;
	}

	for (i = 0; i < max_entry_nr; i++) {
		gpointer entry;

		entry = g_array_index(pipe->entries,  gpointer, i);
		if (dce->entry_rep(dce, entry))
			return CIFSD_RPC_COMMAND_ERROR_BAD_DATA;
	}

	for (i = 0; i < max_entry_nr; i++) {
		gpointer entry;

		entry = g_array_index(pipe->entries,  gpointer, i);
		if (dce->entry_data(dce, entry))
			return CIFSD_RPC_COMMAND_ERROR_BAD_DATA;
	}

	if (pipe->entry_processed) {
		for (i = 0; i < max_entry_nr; i++)
			pipe->entry_processed(pipe, 0);
	}
	return ret;
}

static struct cifsd_rpc_pipe *rpc_pipe_lookup(unsigned int id)
{
	struct cifsd_rpc_pipe *pipe;

	g_rw_lock_reader_lock(&pipes_table_lock);
	pipe = g_hash_table_lookup(pipes_table, &id);
	g_rw_lock_reader_unlock(&pipes_table_lock);

	return pipe;
}

static void dcerpc_free(struct cifsd_dcerpc *dce)
{
	if (!(dce->flags & CIFSD_DCERPC_EXTERNAL_PAYLOAD))
		free(dce->payload);
	free(dce);
}

static struct cifsd_dcerpc *dcerpc_alloc(unsigned int flags, int sz)
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

static struct cifsd_dcerpc *dcerpc_ext_alloc(unsigned int flags,
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

static void dcerpc_downgrade_to_ext(struct cifsd_dcerpc *dce,
				    void *payload,
				    size_t sz)
{
	dce->payload = payload;
	dce->payload_sz = sz;
	dce->offset = 0;
	dce->flags |= CIFSD_DCERPC_EXTERNAL_PAYLOAD;
	dce->flags |= CIFSD_DCERPC_FIXED_PAYLOAD_SZ;
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

static void rpc_pipe_free(struct cifsd_rpc_pipe *pipe)
{
	if (pipe->id != (unsigned int)-1) {
		g_rw_lock_writer_lock(&pipes_table_lock);
		g_hash_table_remove(pipes_table, &(pipe->id));
		g_rw_lock_writer_unlock(&pipes_table_lock);
	}

	__rpc_pipe_free(pipe);
}

static struct cifsd_rpc_pipe *rpc_pipe_alloc(void)
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

static struct cifsd_rpc_pipe *rpc_pipe_alloc_bind(unsigned int id)
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

int rpc_init(void)
{
	pipes_table = g_hash_table_new(g_int_hash, g_int_equal);
	if (!pipes_table)
		return -ENOMEM;
	g_rw_lock_init(&pipes_table_lock);
	return 0;
}

void rpc_destroy(void)
{
	__clear_pipes_table();
	g_hash_table_destroy(pipes_table);
	g_rw_lock_clear(&pipes_table_lock);
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

static int dcerpc_hdr_write(struct cifsd_dcerpc *dce,
			    struct dcerpc_header *hdr)
{
	ndr_write_int8(dce, hdr->rpc_vers);
	ndr_write_int8(dce, hdr->rpc_vers_minor);
	ndr_write_int8(dce, hdr->ptype);
	ndr_write_int8(dce, hdr->pfc_flags);
	ndr_write_bytes(dce, &hdr->packed_drep, sizeof(hdr->packed_drep));
	ndr_write_int16(dce, hdr->frag_length);
	ndr_write_int16(dce, hdr->auth_length);
	ndr_write_int32(dce, hdr->call_id);
	return 0;
}

static int dcerpc_hdr_read(struct cifsd_dcerpc *dce,
			   struct dcerpc_header *hdr)
{
	/* Common Type Header for the Serialization Stream */

	hdr->rpc_vers = ndr_read_int8(dce);
	hdr->rpc_vers_minor = ndr_read_int8(dce);
	hdr->ptype = ndr_read_int8(dce);
	hdr->pfc_flags = ndr_read_int8(dce);
	/*
	 * This common type header MUST be presented by using
	 * little-endian format in the octet stream. The first
	 * byte of the common type header MUST be equal to 1 to
	 * indicate level 1 of type serialization.
	 *
	 * Type serialization version 1 can use either a little-endian
	 * or big-endian integer and floating-pointer byte order but
	 * MUST use the IEEE floating-point format representation and
	 * ASCII character format.
	 */
	ndr_read_bytes(dce, &hdr->packed_drep, sizeof(hdr->packed_drep));

//	if (hdr->packed_drep[0] == DCERPC_SERIALIZATION_TYPE2) {
//		pr_err("DCERPC: unsupported serialization type %d\n",
//				hdr->packed_drep[0]);
//		return -EINVAL;
//	}

	dce->flags |= CIFSD_DCERPC_ALIGN4;
	dce->flags |= CIFSD_DCERPC_LITTLE_ENDIAN;
	if (hdr->packed_drep[0] != DCERPC_SERIALIZATION_LITTLE_ENDIAN)
		dce->flags &= ~CIFSD_DCERPC_LITTLE_ENDIAN;

	hdr->frag_length = ndr_read_int16(dce);
	hdr->auth_length = ndr_read_int16(dce);
	hdr->call_id = ndr_read_int32(dce);
	return 0;
}

static int dcerpc_response_hdr_write(struct cifsd_dcerpc *dce,
				     struct dcerpc_response_header *hdr)
{
	ndr_write_int32(dce, hdr->alloc_hint);
	ndr_write_int16(dce, hdr->context_id);
	ndr_write_int8(dce, hdr->cancel_count);
	auto_align_offset(dce);
	return 0;
}

static int dcerpc_request_hdr_read(struct cifsd_dcerpc *dce,
				   struct dcerpc_request_header *hdr)
{
	hdr->alloc_hint = ndr_read_int32(dce);
	hdr->context_id = ndr_read_int16(dce);
	hdr->opnum = ndr_read_int16(dce);
	return 0;
}

static int __dcerpc_read_syntax(struct cifsd_dcerpc *dce,
				struct dcerpc_syntax *syn)
{
	syn->uuid.time_low = ndr_read_int32(dce);
	syn->uuid.time_mid = ndr_read_int16(dce);
	syn->uuid.time_hi_and_version = ndr_read_int16(dce);
	ndr_read_bytes(dce, syn->uuid.clock_seq, sizeof(syn->uuid.clock_seq));
	ndr_read_bytes(dce, syn->uuid.node, sizeof(syn->uuid.node));
	syn->ver_major = ndr_read_int16(dce);
	syn->ver_minor = ndr_read_int16(dce);
	return 0;
}

static int __dcerpc_write_syntax(struct cifsd_dcerpc *dce,
				 struct dcerpc_syntax *syn)
{
	ndr_write_int32(dce, syn->uuid.time_low);
	ndr_write_int16(dce, syn->uuid.time_mid);
	ndr_write_int16(dce, syn->uuid.time_hi_and_version);
	ndr_write_bytes(dce, syn->uuid.clock_seq, sizeof(syn->uuid.clock_seq));
	ndr_write_bytes(dce, syn->uuid.node, sizeof(syn->uuid.node));
	ndr_write_int16(dce, syn->ver_major);
	ndr_write_int16(dce, syn->ver_minor);
	return 0;
}

static void srvsvc_bind_req_free(struct dcerpc_bind_request *hdr)
{
	int i;

	for (i = 0; i < hdr->num_contexts; i++)
		free(hdr->list->transfer_syntaxes);
	free(hdr->list);
	hdr->list = NULL;
}

static int srvsvc_parse_bind_req(struct cifsd_dcerpc *dce,
				 struct dcerpc_bind_request *hdr)
{
	int i, j;

	hdr->max_xmit_frag_sz = ndr_read_int16(dce);
	hdr->max_recv_frag_sz = ndr_read_int16(dce);
	hdr->assoc_group_id = ndr_read_int32(dce);
	hdr->list = NULL;
	hdr->num_contexts = ndr_read_int8(dce);
	auto_align_offset(dce);

	if (!hdr->num_contexts)
		return 0;

	hdr->list = malloc(hdr->num_contexts * sizeof(struct dcerpc_context));
	if (!hdr->list)
		return -ENOMEM;

	for (i = 0; i < hdr->num_contexts; i++) {
		struct dcerpc_context *ctx = &hdr->list[i];

		ctx->id = ndr_read_int16(dce);
		ctx->num_syntaxes = ndr_read_int8(dce);
		if (!ctx->num_syntaxes) {
			pr_err("BIND: zero syntaxes provided\n");
			return -EINVAL;
		}

		__dcerpc_read_syntax(dce, &ctx->abstract_syntax);

		ctx->transfer_syntaxes = malloc(ctx->num_syntaxes *
						sizeof(struct dcerpc_syntax));
		if (!ctx->transfer_syntaxes)
			return -ENOMEM;
		for (j = 0; j < ctx->num_syntaxes; j++)
			__dcerpc_read_syntax(dce, &ctx->transfer_syntaxes[j]);
	}
	return CIFSD_RPC_COMMAND_OK;
}

static int srvsvc_bind_invoke(struct cifsd_rpc_pipe *pipe)
{
	struct cifsd_dcerpc *dce;
	int ret;

	dce = pipe->dce;
	if (srvsvc_parse_bind_req(dce, &dce->bi_req))
		return CIFSD_RPC_COMMAND_ERROR_BAD_DATA;

	pipe->entry_processed = NULL;
	return CIFSD_RPC_COMMAND_OK;
}

static int srvsvc_bind_nack_return(struct cifsd_rpc_pipe *pipe)
{
	struct cifsd_dcerpc *dce = pipe->dce;
	int i, payload_offset;

	dce->offset = sizeof(struct dcerpc_header);

	ndr_write_int16(dce,
			DCERPC_BIND_NAK_REASON_PROTOCOL_VERSION_NOT_SUPPORTED);
	ndr_write_int8(dce, ARRAY_SIZE(known_syntaxes));
	auto_align_offset(dce);

	for (i = 0; i < ARRAY_SIZE(known_syntaxes); i++) {
		ndr_write_int8(dce, known_syntaxes[i].ver_major);
		ndr_write_int8(dce, known_syntaxes[i].ver_minor);
	}

	payload_offset = dce->offset;
	dce->offset = 0;

	dce->hdr.ptype = DCERPC_PTYPE_RPC_BINDNACK;
	dce->hdr.pfc_flags = DCERPC_PFC_FIRST_FRAG | DCERPC_PFC_LAST_FRAG;
	dce->hdr.frag_length = payload_offset;
	dcerpc_hdr_write(dce, &dce->hdr);

	dce->offset = payload_offset;
	dce->rpc_resp->payload_sz = dce->offset;
	return CIFSD_RPC_COMMAND_OK;
}

static int srvsvc_bind_ack_return(struct cifsd_rpc_pipe *pipe,
				  int syntax_idx)
{
	struct cifsd_dcerpc *dce = pipe->dce;
	int num_trans, i, payload_offset;
	char *addr;

	dce->offset = sizeof(struct dcerpc_header);

	ndr_write_int16(dce, dce->bi_req.max_xmit_frag_sz);
	ndr_write_int16(dce, dce->bi_req.max_recv_frag_sz);
	ndr_write_int32(dce, dce->bi_req.assoc_group_id);

	if (dce->rpc_req->flags & CIFSD_RPC_COMMAND_SRVSVC_METHOD_INVOKE)
		addr = "\\PIPE\\srvsvc";
	else if (dce->rpc_req->flags & CIFSD_RPC_COMMAND_WKSSVC_METHOD_INVOKE)
		addr = "\\PIPE\\wkssvc";
	else
		return CIFSD_RPC_COMMAND_ERROR_BAD_FUNC;

	ndr_write_int16(dce, strlen(addr));
	ndr_write_bytes(dce, addr, strlen(addr));
	align_offset(dce, 4); /* [flag(NDR_ALIGN4)]    DATA_BLOB _pad1; */

	num_trans = 1;
	ndr_write_int8(dce, num_trans);
	align_offset(dce, 2);

	ndr_write_int16(dce, DCERPC_BIND_ACK_RESULT_ACCEPT);
	NDR_WRITE_UNION(dce, int16, DCERPC_BIND_ACK_REASON_NOT_SPECIFIED);
	__dcerpc_write_syntax(dce, &known_syntaxes[syntax_idx]);

	payload_offset = dce->offset;
	dce->offset = 0;

	dce->hdr.ptype = DCERPC_PTYPE_RPC_BINDACK;
	dce->hdr.pfc_flags = DCERPC_PFC_FIRST_FRAG | DCERPC_PFC_LAST_FRAG;
	dce->hdr.frag_length = payload_offset;
	dcerpc_hdr_write(dce, &dce->hdr);

	dce->offset = payload_offset;
	dce->rpc_resp->payload_sz = dce->offset;
	return CIFSD_RPC_COMMAND_OK;
}

static int compare_transfer_syntaxes(struct dcerpc_syntax *a,
				     struct dcerpc_syntax *b)
{
	if (a->uuid.time_low != b->uuid.time_low)
		return -1;
	if (a->uuid.time_mid != b->uuid.time_mid)
		return -1;
	if (a->uuid.time_hi_and_version != b->uuid.time_hi_and_version)
		return -1;
	if (memcmp(a->uuid.clock_seq,
		   b->uuid.clock_seq,
		   sizeof(a->uuid.clock_seq)))
		return -1;
	if (memcmp(a->uuid.node,
		   b->uuid.node,
		   sizeof(a->uuid.node)))
		return -1;
	if (a->ver_major != b->ver_major)
		return -1;
	return 0;
}

static int srvsvc_bind_return(struct cifsd_rpc_pipe *pipe)
{
	struct cifsd_dcerpc *dce = pipe->dce;
	int i, j, k, syntax_idx = -1;

	for (i = 0; i < dce->bi_req.num_contexts; i++) {
		for (j = 0; j < dce->bi_req.list[i].num_syntaxes; j++) {
			for (k = 0; k < ARRAY_SIZE(known_syntaxes); k++) {
				static struct dcerpc_syntax *a;
				static struct dcerpc_syntax *b;

				a = &known_syntaxes[k];
				b = &dce->bi_req.list[i].transfer_syntaxes[j];
				if (!compare_transfer_syntaxes(a, b)) {
					syntax_idx = k;
					break;
				}
			}
		}
	}

	if (syntax_idx == -1) {
		pr_err("Unsupported transfer syntax\n");
		return srvsvc_bind_nack_return(pipe);
	}

	return srvsvc_bind_ack_return(pipe, syntax_idx);
}

static int srvsvc_share_info_invoke(struct cifsd_rpc_pipe *pipe)
{
	struct cifsd_dcerpc *dce;
	int ret;

	dce = pipe->dce;
	if (srvsvc_parse_share_info_req(dce, &dce->si_req))
		return CIFSD_RPC_COMMAND_ERROR_BAD_DATA;

	pipe->entry_processed = __share_entry_processed;

	if (dce->req_hdr.opnum == SRVSVC_OPNUM_GET_SHARE_INFO)
		ret = srvsvc_share_get_info_invoke(pipe, &dce->si_req);
	if (dce->req_hdr.opnum == SRVSVC_OPNUM_SHARE_ENUM_ALL)
		ret = srvsvc_share_enum_all_invoke(pipe);
	return ret;
}

static int srvsvc_write_headers(struct cifsd_dcerpc *dce,
				int method_status)
{
	int payload_offset;

	payload_offset = dce->offset;
	dce->offset = 0;

	dce->hdr.ptype = DCERPC_PTYPE_RPC_RESPONSE;
	dce->hdr.pfc_flags = DCERPC_PFC_FIRST_FRAG | DCERPC_PFC_LAST_FRAG;
	dce->hdr.frag_length = payload_offset;
	if (method_status == CIFSD_RPC_COMMAND_ERROR_MORE_DATA)
		dce->hdr.pfc_flags = 0;
	dcerpc_hdr_write(dce, &dce->hdr);

	/* cast req_hdr to resp_hdr and NULL out lower 2 bytes */
	dce->req_hdr.opnum = 0;
	dce->resp_hdr.cancel_count = 0;
	dce->resp_hdr.alloc_hint = payload_offset;
	dcerpc_response_hdr_write(dce, &dce->resp_hdr);

	dce->offset = payload_offset;
	return 0;
}

static int srvsvc_share_info_return(struct cifsd_rpc_pipe *pipe)
{
	struct cifsd_dcerpc *dce = pipe->dce;
	int ret = CIFSD_RPC_COMMAND_OK, status = 0;

	/*
	 * Reserve space for response NDR header. We don't know yet if
	 * the payload buffer is big enough. This will determine if we
	 * can set DCERPC_PFC_FIRST_FRAG|DCERPC_PFC_LAST_FRAG or if we
	 * will have a multi-part response.
	 */
	dce->offset = sizeof(struct dcerpc_header);
	dce->offset += sizeof(struct dcerpc_response_header);

	if (dce->si_req.level == 0) {
		dce->entry_size = __share_entry_size_ctr0;
		dce->entry_rep = __share_entry_rep_ctr0;
		dce->entry_data = __share_entry_data_ctr0;
	} else if (dce->si_req.level == 1) {
		dce->entry_size = __share_entry_size_ctr1;
		dce->entry_rep = __share_entry_rep_ctr1;
		dce->entry_data = __share_entry_data_ctr1;
	} else {
		ret = CIFSD_RPC_COMMAND_ERROR_INVALID_LEVEL;
		goto out;
	}

	NDR_WRITE_UNION(dce, int32, dce->si_req.level);
	ndr_write_int32(dce, pipe->num_entries);

	status = ndr_write_array_of_structs(dce, pipe);
out:
	/*
	 * [out] DWORD* TotalEntries
	 * [out, unique] DWORD* ResumeHandle
	 * [out] DWORD Return value/code
	 */
	ndr_write_int32(dce, pipe->num_entries);
	if (status == CIFSD_RPC_COMMAND_ERROR_MORE_DATA)
		ndr_write_int32(dce, 0x01);
	else
		ndr_write_int32(dce, 0x00);
	ndr_write_int32(dce, status);

	if (ret == CIFSD_RPC_COMMAND_OK)
		srvsvc_write_headers(dce, status);

	dce->rpc_resp->payload_sz = dce->offset;
	return ret;
}

static int srvsvc_invoke(struct cifsd_rpc_command *req,
			 struct cifsd_rpc_command *resp)
{
	struct cifsd_rpc_pipe *pipe;
	struct cifsd_dcerpc *dce;
	int ret;

	pipe = rpc_pipe_lookup(req->handle);
	if (!pipe)
		return CIFSD_RPC_COMMAND_ERROR_NOMEM;

	dce = dcerpc_ext_alloc(CIFSD_DCERPC_LITTLE_ENDIAN|CIFSD_DCERPC_ALIGN4,
			       req->payload,
			       req->payload_sz);
	if (!dce) {
		rpc_pipe_free(pipe);
		return CIFSD_RPC_COMMAND_ERROR_NOMEM;
	}

	pipe->dce = dce;
	dce->rpc_req = req;
	dce->rpc_resp = resp;

	ret = dcerpc_hdr_read(dce, &dce->hdr);
	if (dce->hdr.ptype == DCERPC_PTYPE_RPC_BIND)
		return srvsvc_bind_invoke(pipe);

	if (dce->hdr.ptype != DCERPC_PTYPE_RPC_REQUEST)
		return CIFSD_RPC_COMMAND_ERROR_NOTIMPLEMENTED;

	ret |= dcerpc_request_hdr_read(dce, &dce->req_hdr);
	if (ret) {
		dcerpc_free(dce);
		return CIFSD_RPC_COMMAND_ERROR_BAD_DATA;
	}

	switch (dce->req_hdr.opnum) {
	case SRVSVC_OPNUM_SHARE_ENUM_ALL:
	case SRVSVC_OPNUM_GET_SHARE_INFO:
		ret = srvsvc_share_info_invoke(pipe);
		break;
	default:
		pr_err("SRVSVC: unsupported method %d\n",
			dce->req_hdr.opnum);
		ret = CIFSD_RPC_COMMAND_ERROR_NOTIMPLEMENTED;
		rpc_pipe_free(pipe);
		break;
	}

	return ret;
}

static int srvsvc_return(struct cifsd_rpc_command *req,
			 struct cifsd_rpc_command *resp,
			 int max_resp_sz)
{
	struct cifsd_rpc_pipe *pipe;
	struct cifsd_dcerpc *dce;
	int ret;

	pipe = rpc_pipe_lookup(req->handle);
	if (!pipe || !pipe->dce) {
		pr_err("SRVSVC: no pipe or pipe has no associated DCE [%d]\n",
			req->handle);
		return CIFSD_RPC_COMMAND_ERROR_BAD_FID;
	}

	dce = pipe->dce;
	dce->rpc_resp = resp;
	dcerpc_downgrade_to_ext(dce, resp->payload, max_resp_sz);

	if (dce->hdr.ptype == DCERPC_PTYPE_RPC_BIND)
		return srvsvc_bind_return(pipe);

	if (dce->hdr.ptype != DCERPC_PTYPE_RPC_REQUEST)
		return CIFSD_RPC_COMMAND_ERROR_NOTIMPLEMENTED;

	switch (dce->req_hdr.opnum) {
	case SRVSVC_OPNUM_SHARE_ENUM_ALL:
	case SRVSVC_OPNUM_GET_SHARE_INFO:
		if (dce->si_req.max_size < (unsigned int)max_resp_sz)
			max_resp_sz = dce->si_req.max_size;
		dce->rpc_resp = resp;
		dcerpc_downgrade_to_ext(dce, resp->payload, max_resp_sz);

		ret = srvsvc_share_info_return(pipe);
		break;
	default:
		pr_err("SRVSVC: unsupported method %d\n",
			dce->req_hdr.opnum);
		ret = CIFSD_RPC_COMMAND_ERROR_BAD_FUNC;
		break;
	}
	return ret;
}

int rpc_srvsvc_request(struct cifsd_rpc_command *req,
		       struct cifsd_rpc_command *resp,
		       int max_resp_sz)
{
	if (req->flags & CIFSD_RPC_COMMAND_METHOD_RETURN)
		return srvsvc_return(req, resp, max_resp_sz);

	return srvsvc_invoke(req, resp);
}

int rpc_ioctl_request(struct cifsd_rpc_command *req,
		      struct cifsd_rpc_command *resp,
		      int max_resp_sz)
{
	int ret = CIFSD_RPC_COMMAND_ERROR_NOTIMPLEMENTED;

	if (req->flags & CIFSD_RPC_COMMAND_SRVSVC_METHOD_INVOKE) {
		ret = srvsvc_invoke(req, resp);
		if (ret == CIFSD_RPC_COMMAND_OK)
			ret = srvsvc_return(req, resp, max_resp_sz);
	}

	if (req->flags & CIFSD_RPC_COMMAND_WKSSVC_METHOD_INVOKE) {
		ret = CIFSD_RPC_COMMAND_ERROR_NOTIMPLEMENTED;
	}

	return ret;
}

int rpc_read_request(struct cifsd_rpc_command *req,
		     struct cifsd_rpc_command *resp,
		     int max_resp_sz)
{
	int ret = CIFSD_RPC_COMMAND_ERROR_NOTIMPLEMENTED;

	if (req->flags & CIFSD_RPC_COMMAND_SRVSVC_METHOD_INVOKE)
		ret = srvsvc_return(req, resp, max_resp_sz);

	if (req->flags & CIFSD_RPC_COMMAND_WKSSVC_METHOD_INVOKE)
		ret = CIFSD_RPC_COMMAND_ERROR_NOTIMPLEMENTED;
	return ret;
}

int rpc_write_request(struct cifsd_rpc_command *req,
		      struct cifsd_rpc_command *resp,
		      int max_resp_sz)
{
	int ret = CIFSD_RPC_COMMAND_ERROR_NOTIMPLEMENTED;

	if (req->flags & CIFSD_RPC_COMMAND_SRVSVC_METHOD_INVOKE)
		ret = srvsvc_invoke(req, resp);

	if (req->flags & CIFSD_RPC_COMMAND_WKSSVC_METHOD_INVOKE)
		ret = CIFSD_RPC_COMMAND_ERROR_NOTIMPLEMENTED;
	return ret;
}

int rpc_open_request(struct cifsd_rpc_command *req,
		     struct cifsd_rpc_command *resp)
{
	struct cifsd_rpc_pipe *pipe;

	pipe = rpc_pipe_lookup(req->handle);
	if (pipe) {
		pr_err("RPC: pipe ID collision: %d\n", req->handle);
		return -EEXIST;
	}

	pipe = rpc_pipe_alloc_bind(req->handle);
	if (!pipe)
		return -ENOMEM;
	return CIFSD_RPC_COMMAND_OK;
}

int rpc_close_request(struct cifsd_rpc_command *req,
		      struct cifsd_rpc_command *resp)
{
	struct cifsd_rpc_pipe *pipe;

	pipe = rpc_pipe_lookup(req->handle);
	if (pipe) {
		rpc_pipe_free(pipe);
		return 0;
	} else {
		pr_err("RPC: unknown pipe ID: %d\n", req->handle);
	}
	return CIFSD_RPC_COMMAND_OK;
}
