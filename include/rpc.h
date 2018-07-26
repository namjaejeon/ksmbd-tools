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

#define CIFSD_DCERPC_LITTLE_ENDIAN	(1 << 0)
#define CIFSD_DCERPC_ALIGN2		(1 << 1)
#define CIFSD_DCERPC_ALIGN4		(1 << 2)
#define CIFSD_DCERPC_ALIGN8		(1 << 3)
#define CIFSD_DCERPC_ASCII_STRING	(1 << 4)
#define CIFSD_DCERPC_FIXED_PAYLOAD_SZ	(1 << 5)

#define CIFSD_DCERPC_MAX_PREFERRED_SIZE -1

#define CHARSET_UTF16LE			"UTF16LE"
#define CHARSET_UTF16BE			"UTF16BE"
#define CHARSET_UTF8			"UTF8"
#define CHARSET_DEFAULT			CHARSET_UTF8

#define CIFSD_DCERPC_ERROR_MORE_DATA		0x000000EA
#define CIFSD_DCERPC_ERROR_INVALID_LEVEL	0x0000007C

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

void cifsd_dcerpc_free(struct cifsd_dcerpc *dce);
struct cifsd_dcerpc *cifsd_dcerpc_allocate(unsigned int flags,
					   int sz);

struct cifsd_rpc_pipe *cifsd_rpc_pipe_alloc(unsigned int id);
void cifsd_rpc_pipe_free(struct cifsd_rpc_pipe *pipe);

int cifsd_rpc_share_enum_all(struct cifsd_rpc_pipe *pipe);
struct cifsd_dcerpc *
cifsd_rpc_srvsvc_share_enum_all(struct cifsd_rpc_pipe *pipe,
				int level,
				unsigned int flags,
				int max_preferred_size);

int cifsd_rpc_pipe_table_init(void);
void cifsd_rpc_pipe_table_destroy(void);
#endif /* __CIFSD_RPC_H__ */
