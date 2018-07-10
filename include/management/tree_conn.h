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

#ifndef __MANAGEMENT_TCONNECTION_H__
#define __MANAGEMENT_TCONNECTION_H__

#include <glib.h>

struct cifsd_user;
struct cifsd_share;

struct cifsd_tree_conn {
	unsigned long long	id;

	struct cifsd_user	*user;
	struct cifsd_share	*share;

	unsigned int		flags;
};

static inline void set_conn_flag(struct cifsd_tree_conn *conn, int bit)
{
	conn->flags |= bit;
}

static inline void clear_conn_flag(struct cifsd_tree_conn *conn, int bit)
{
	conn->flags &= ~bit;
}

static inline int test_conn_flag(struct cifsd_tree_conn *conn, int bit)
{
	conn->flags & bit;
}

struct cifsd_tree_conn *tcm_lookup_conn(unsigned long long id);

struct cifsd_tree_connect_request;
struct cifsd_tree_connect_response;

int tcm_handle_tree_connect(struct cifsd_tree_connect_request *req,
			    struct cifsd_tree_connect_response *resp);

int tcm_handle_tree_disconnect(unsigned long long id);

void tcm_destroy(void);
int tcm_init(void);

#endif /* __MANAGEMENT_TCONNECTION_H__ */
