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

#define CHARSET_UTF16LE			"UTF16LE"
#define CHARSET_UTF16BE			"UTF16BE"
#define CHARSET_UTF8			"UTF8"
#define CHARSET_DEFAULT			CHARSET_UTF8

struct cifsd_dcerpc {
	unsigned int		flags;
	size_t			offset;
	size_t			payload_sz;
	char			*payload;
};

int cifsd_rpc_share_enum_all(void);

void cifsd_dcerpc_free(struct cifsd_dcerpc *dce);
struct cifsd_dcerpc *cifsd_dcerpc_allocate(unsigned int flags,
					   size_t default_sz);

#endif /* __CIFSD_RPC_H__ */
