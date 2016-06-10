/*
 *   cifssrv-tools/cifsadmin/cifsadmin.h
 *
 *   Copyright (C) 2015 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
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
#ifndef _CIFSMGR_H
#define _CIFSMGR_H

#include "cifssrv.h"

/* process flags */
#define AM_ROOT 0x1
#define F_ADD_USER 0x2
#define F_REMOVE_USER 0x8
#define F_QUERY_USER 0x10

#define COPY_UCS2_CHAR(dest, src) (((unsigned char *)(dest))[0] =\
		((unsigned char *)(src))[0], ((unsigned char *)(dest))[1] =\
		((unsigned char *)(src))[1], (dest))

#define MD4_BLOCK_WORDS	16
#define MD4_HASH_WORDS	4

struct md4_ctx {
	unsigned int hash[MD4_HASH_WORDS];
	unsigned int block[MD4_BLOCK_WORDS];
	unsigned long long byte_count;
};

/* forward declarations */
void md4_init(struct md4_ctx *);
void md4_update(struct md4_ctx *, const unsigned char *, unsigned int);
void md4_final(struct md4_ctx *, unsigned char *);

#endif /* _CIFSMGR_H */
