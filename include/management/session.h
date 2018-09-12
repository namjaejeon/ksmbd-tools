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

struct cifsd_session {
	unsigned long long	id;

	struct cifsd_user	*user;

	GRWLock			update_lock;
	GList			*tree_conns;
	int			ref_counter;
};

struct cifsd_tree_conn;

int sm_check_sessions_capacity(unsigned long long id);

int sm_handle_tree_connect(unsigned long long id,
			   struct cifsd_user *user,
			   struct cifsd_tree_conn *tree_conn);
int sm_handle_tree_disconnect(unsigned long long sess_id,
			      unsigned long long tree_conn_id);

void sm_destroy(void);
int sm_init(void);

#endif /* __MANAGEMENT_TCONNECTION_H__ */
