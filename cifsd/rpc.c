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
#include <glib.h>
#include <errno.h>
#include <linux/cifsd_server.h>

#include <rpc.h>
#include <cifsdtools.h>


/*
 * RPC
 *
 * Server Service Remote Protocol
 */
struct srvsvc_share_info0 {
	__u16				*shi0_netname;
};

struct srvsvc_share_container0 {
	__u32 				entries_read;
	struct srvsvc_share_info0	*buffer;
};

struct srvsvc_share_info1 {
	__u16				*shi1_netname;
	__u32				shi1_type;
	__u16				*shi1_remark;
};

struct srvsvc_share_container1 {
	__u32				entries_read;
	struct srvsvc_share_info1	*buffer;
};

struct srvsvc_share_container {
	__u32					level;
	union {
		struct srvsvc_share_container0	level0;
		struct srvsvc_share_container1	level1;
	} share_info;
};

#define PAYLOAD_HEAD(d)	((d)->payload + (d)->offset)

#define __ALIGN(x, a)		__ALIGN_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_MASK(x, mask)	(((x) + (mask)) & ~(mask))

static int try_realloc_payload(struct cifsd_dcerpc *dce, size_t data_sz)
{
	char *n;

	if (dce->offset < dce->payload_sz - data_sz)
		return 0;

	n = realloc(dce->payload, 2 * dce->payload_sz);
	if (!n)
		return -ENOMEM;
	dce->payload = n;
	return 0;
}

static int dcerpc_write_int16(struct cifsd_dcerpc *dce, short value)
{
	if (try_realloc_payload(dce, sizeof(short)))
		return -ENOMEM;

	if (dce->flags & CIFSD_DCERPC_LITTLE_ENDIAN)
		*(__le16 *)PAYLOAD_HEAD(dce) = (__le16)value;
	else
		*(short *)PAYLOAD_HEAD(dce) = value;

	dce->offset += sizeof(short);
	if (dce->flags & CIFSD_DCERPC_ALIGN4)
		dce->offset = __ALIGN(dce->offset, 4);
	if (dce->flags & CIFSD_DCERPC_ALIGN8)
		dce->offset = __ALIGN(dce->offset, 8);
	return 0;
}

static int dcerpc_write_int32(struct cifsd_dcerpc *dce, int value)
{
	if (try_realloc_payload(dce, sizeof(short)))
		return -ENOMEM;

	if (dce->flags & CIFSD_DCERPC_LITTLE_ENDIAN)
		*(__le32 *)PAYLOAD_HEAD(dce) = (__le32)value;
	else
		*(int *)PAYLOAD_HEAD(dce) = value;

	dce->offset += sizeof(int);
	if (dce->flags & CIFSD_DCERPC_ALIGN8)
		dce->offset = __ALIGN(dce->offset, 8);
	return 0;
}

static int dcerpc_write_int64(struct cifsd_dcerpc *dce, long long value)
{
	if (try_realloc_payload(dce, sizeof(short)))
		return -ENOMEM;

	if (dce->flags & CIFSD_DCERPC_LITTLE_ENDIAN)
		*(__le64*)PAYLOAD_HEAD(dce) = (__le64)value;
	else
		*(long long*)PAYLOAD_HEAD(dce) = value;

	dce->offset += sizeof(long long);
	return 0;
}

static int dcerpc_write_union(struct cifsd_dcerpc *dce, int value)
{
	int ret;

	/*
	 * For a non-encapsulated union, the discriminant is marshalled into
	 * the transmitted data stream twice: once as the field or parameter,
	 * which is referenced by the switch_is construct, in the procedure
	 * argument list; and once as the first part of the union
	 * representation.
	 */
	ret = dcerpc_write_int32(dce, value);
	if (ret)
		return ret;
	return dcerpc_write_int32(dce, value);
}

static int dcerpc_write_bytes(struct cifsd_dcerpc *dce, void *value, size_t sz)
{
	if (try_realloc_payload(dce, sizeof(short)))
		return -ENOMEM;

	memcpy(PAYLOAD_HEAD(dce), value, sz);
	dce->offset += sz;
	return 0;
}


static int dcerpc_write_vstring(struct cifsd_dcerpc *dce, char *value)
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

	if (!(dce->flags & CIFSD_DCERPC_LITTLE_ENDIAN))
		charset = CHARSET_UTF16BE;

	raw_len = strlen(raw_value);
	if (dce->flags & CIFSD_DCERPC_ASCII_STRING) {
		charset = CHARSET_UTF8;
	}

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
	ret = dcerpc_write_int32(dce, bytes_written / 2);
	ret |= dcerpc_write_int32(dce, 0);
	ret |= dcerpc_write_int32(dce, bytes_written / 2);
	ret |= dcerpc_write_bytes(dce, out, bytes_written);

	if (dce->flags & CIFSD_DCERPC_ALIGN4)
		dce->offset = __ALIGN(dce->offset, 4);
	if (dce->flags & CIFSD_DCERPC_ALIGN8)
		dce->offset = __ALIGN(dce->offset, 8);

out:
	g_free(out);
	return ret;
}

int cifsd_rpc_share_enum_all(void)
{

}

void cifsd_dcerpc_free(struct cifsd_dcerpc *dce)
{
	free(dce->payload);
	free(dce);
}

struct cifsd_dcerpc *cifsd_dcerpc_allocate(unsigned int flags,
					   size_t default_sz)
{
	struct cifsd_dcerpc *dce;

	dce = malloc(sizeof(struct cifsd_dcerpc));
	if (!dce)
		return NULL;

	memset(dce, 0x00, sizeof(struct cifsd_dcerpc));
	dce->payload = malloc(default_sz);
	if (!dce->payload) {
		free(dce);
		return NULL;
	}

	dce->payload_sz = default_sz;
	return dce;
}
