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

#ifndef __CIFSD_RPC_H__
#define __CIFSD_RPC_H__

#include <linux/types.h>

#define CIFSD_DCERPC_LITTLE_ENDIAN	(1 << 0)
#define CIFSD_DCERPC_ALIGN2		(1 << 1)
#define CIFSD_DCERPC_ALIGN4		(1 << 2)
#define CIFSD_DCERPC_ALIGN8		(1 << 3)
#define CIFSD_DCERPC_ASCII_STRING	(1 << 4)
#define CIFSD_DCERPC_FIXED_PAYLOAD_SZ	(1 << 5)
#define CIFSD_DCERPC_EXTERNAL_PAYLOAD	(1 << 6)

#define CIFSD_DCERPC_MAX_PREFERRED_SIZE -1

#define CHARSET_UTF16LE			"UTF16LE"
#define CHARSET_UTF16BE			"UTF16BE"
#define CHARSET_UTF8			"UTF8"
#define CHARSET_DEFAULT			CHARSET_UTF8

#define CIFSD_DCERPC_ERROR_MORE_DATA		0x000000EA
#define CIFSD_DCERPC_ERROR_INVALID_LEVEL	0x0000007C

#define DCERPC_PTYPE_RPC_REQUEST	0x00
#define DCERPC_PTYPE_RPC_PING		0x01
#define DCERPC_PTYPE_RPC_RESPONSE	0x02
#define DCERPC_PTYPE_RPC_FAULT		0x03
#define DCERPC_PTYPE_RPC_WORKING	0x04
#define DCERPC_PTYPE_RPC_NOCALL		0x05
#define DCERPC_PTYPE_RPC_REJECT		0x06
#define DCERPC_PTYPE_RPC_ACK		0x07
#define DCERPC_PTYPE_RPC_CL_CANCEL	0x08
#define DCERPC_PTYPE_RPC_FACK		0x09
#define DCERPC_PTYPE_RPC_CANCEL_ACK	0x0A
#define DCERPC_PTYPE_RPC_BIND		0x0B
#define DCERPC_PTYPE_RPC_BINDACK	0x0C
#define DCERPC_PTYPE_RPC_BINDNACK	0x0D
#define DCERPC_PTYPE_RPC_ALTCONT	0x0E
#define DCERPC_PTYPE_RPC_ALTCONTRESP	0x0F
#define DCERPC_PTYPE_RPC_AUTH3		0x10
#define DCERPC_PTYPE_RPC_SHUTDOWN	0x11
#define DCERPC_PTYPE_RPC_CO_CANCEL	0x12
#define DCERPC_PTYPE_RPC_ORPHANED	0x13

#define DCERPC_PFC_FIRST_FRAG	0x01  /* First fragment */
#define DCERPC_PFC_LAST_FRAG	0x02  /* Last fragment */
#define DCERPC_PFC_PENDING_CANCEL	0x04  /* Cancel was pending at sender */
#define DCERPC_PFC_RESERVED_1	0x08
#define DCERPC_PFC_CONC_MPX	0x10  /* supports concurrent multiplexing
                                        * of a single connection. */
#define DCERPC_PFC_DID_NOT_EXECUTE	0x20  /* only meaningful on `fault' packet;
                                        * if true, guaranteed call did not
                                        * execute. */
#define DCERPC_PFC_MAYBE		0x40  /* `maybe' call semantics requested */
#define DCERPC_PFC_OBJECT_UUID	0x80  /* if true, a non-nil object UUID
                                        * was specified in the handle, and
                                        * is present in the optional object
                                        * field. If false, the object field
                                        * is omitted. */

#define DCERPC_SERIALIZATION_TYPE1		1
#define DCERPC_SERIALIZATION_TYPE2		2
#define DCERPC_SERIALIZATION_LITTLE_ENDIAN	0x11
#define DCERPC_SERIALIZATION_BIG_ENDIAN		0x00

struct dcerpc_header {
	/* start 8-octet aligned */

	/* common fields */
	__u8	rpc_vers;            /* 00:01 RPC version */
	__u8	rpc_vers_minor;      /* 01:01 minor version */
	__u8	ptype;               /* 02:01 bind PDU */
	__u8	pfc_flags;           /* 03:01 flags */
	__s8	packed_drep[4];      /* 04:04 NDR data rep format label*/
	__u16	frag_length;         /* 08:02 total length of fragment */
	__u16	auth_length;         /* 10:02 length of auth_value */
	__u32	call_id;             /* 12:04 call identifier */

	/* end common fields */
};

struct dcerpc_request_header {
	__u32 alloc_hint;
	__u16 context_id;
	__u16 opnum;
	/*
	 * SWITCH dcerpc_object object;
	 * PAYLOAD_BLOB;
	 */
};

struct srvsvc_rpc_request {
	struct dcerpc_header		dce_hdr;
	struct dcerpc_request_header	dce_req_hdr;
	void				*srvsvc_req;
};

/*
 * So how this is expected to work. First, you need to obtain a snapshot
 * of the data that you want to push to the wire. The data snapshot goes
 * to cifsd_rpc_pipe. Then you perform a protocol specific transformation
 * of the data snapshot. The transformed data goes to a specific protocol
 * dependent structure, e.g. cifsd_dcerpc for DCERPC (ndr/ndr64). Then you
 * write the transformed data snapshot to the wire.
 */

struct cifsd_rpc_pipe {
	unsigned int		id;

	int 			num_entries;
	GArray			*entries;

	/*
	 * Tell pipe that we processed the entry and won't need it
	 * anymore so it can remove/drop it.
	 */
	int			(*entry_processed)(struct cifsd_rpc_pipe *,
						   int i);
};

struct cifsd_dcerpc {
	unsigned int		flags;
	size_t			offset;
	size_t			payload_sz;
	char			*payload;
	unsigned int		num_pointers;
	/*
	 * Find out the estimated entry size under the given container level
	 * restriction
	 */
	int			(*entry_size)(struct cifsd_dcerpc *,
					      gpointer entry);
	/*
	 * Entry representation under the given container level
	 * restriction for array representation
	 */
	int			(*entry_rep)(struct cifsd_dcerpc *,
					      gpointer entry);
	/*
	 * Entry data under the given container level restriction
	 * for array representation
	 */
	int			(*entry_data)(struct cifsd_dcerpc *,
					      gpointer entry);
};

/*
 * http://pubs.opengroup.org/onlinepubs/9629399/chap14.htm
 *
 * We refer to pointers that are parameters in remote procedure calls as
 * top-level pointers and we refer to pointers that are elements of arrays,
 * members of structures, or members of unions as embedded pointers.
 *
 *  NDR represents a null full pointer as an unsigned long integer with the
 *  value 0 (zero).
 *  NDR represents the first instance in a octet stream of a non-null full
 *  pointer in two parts: the first part is a non-zero unsigned long integer
 *  that identifies the referent; the second part is the representation of
 *  the referent. NDR represents subsequent instances in the same octet
 *  stream of the same pointer only by the referent identifier.
 */
struct ndr_ptr {
	__u32	ptr;
};

struct ndr_uniq_ptr {
	__u32	ref_id;
	__u32	ptr;
};

struct ndr_char_ptr {
	char	*ptr;
};

struct ndr_uniq_char_ptr {
	__u32	ref_id;
	char	*ptr;
};

struct srvsvc_share_info_request {
	int				level;
	int				max_size;

	struct ndr_uniq_char_ptr	server_name;
	struct ndr_char_ptr		share_name;

	struct ndr_uniq_ptr		payload_handle;
};

void dcerpc_free(struct cifsd_dcerpc *dce);
struct cifsd_dcerpc *dcerpc_alloc(unsigned int flags, int sz);
struct cifsd_dcerpc *dcerpc_parser_alloc(void *pl, int sz);

struct cifsd_rpc_pipe *rpc_pipe_alloc(unsigned int id);
void rpc_pipe_free(struct cifsd_rpc_pipe *pipe);

struct cifsd_rpc_pipe *rpc_pipe_lookup(unsigned int id);

int rpc_srvsvc_parse_dcerpc_hdr(struct cifsd_dcerpc *dce,
				struct dcerpc_header *hdr);

int rpc_srvsrv_parse_dcerpc_request_hdr(struct cifsd_dcerpc *dce,
					struct dcerpc_request_header *hdr);

int rpc_share_enum_all(struct cifsd_rpc_pipe *pipe);
int rpc_share_get_info(struct cifsd_rpc_pipe *pipe,
		       struct srvsvc_share_info_request *hdr);
struct cifsd_dcerpc *
rpc_srvsvc_share_enum_all(struct cifsd_rpc_pipe *pipe,
			  int level,
			  unsigned int flags,
			  int max_preferred_size);

int rpc_init(void);
void rpc_destroy(void);
#endif /* __CIFSD_RPC_H__ */
