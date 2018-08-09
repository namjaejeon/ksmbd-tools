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

#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <linux/cifsd_server.h>

#include <management/tree_conn.h>
#include <management/session.h>
#include <management/share.h>
#include <management/user.h>
#include <cifsdtools.h>

static struct cifsd_tree_conn *new_cifsd_tree_conn(void)
{
	struct cifsd_tree_conn *conn = malloc(sizeof(struct cifsd_tree_conn));

	if (!conn)
		return NULL;

	memset(conn, 0x00, sizeof(struct cifsd_tree_conn));
	conn->id = 0;
	return conn;
}

void tcm_tree_conn_free(struct cifsd_tree_conn *conn)
{
	shm_close_connection(conn->share);
	put_cifsd_share(conn->share);
	free(conn);
}

int tcm_handle_tree_connect(struct cifsd_tree_connect_request *req,
			    struct cifsd_tree_connect_response *resp)
{
	struct cifsd_user *user = NULL;
	struct cifsd_share *share = NULL;
	struct cifsd_tree_conn *conn = new_cifsd_tree_conn();
	int ret;

	if (!conn) {
		resp->status = CIFSD_TREE_CONN_STATUS_NOMEM;
		return -ENOMEM;
	}

	if (global_conf.map_to_guest == CIFSD_CONF_MAP_TO_GUEST_NEVER) {
		if (req->account_flags & CIFSD_USER_FLAG_BAD_PASSWORD) {
			resp->status = CIFSD_TREE_CONN_STATUS_INVALID_USER;
			goto out_error;
		}
	}

	share = shm_lookup_share(req->share);
	if (!share) {
		resp->status = CIFSD_TREE_CONN_STATUS_NO_SHARE;
		goto out_error;
	}

	if (test_share_flag(share, CIFSD_SHARE_FLAG_WRITEABLE))
		set_conn_flag(conn, CIFSD_TREE_CONN_FLAG_WRITABLE);
	if (test_share_flag(share, CIFSD_SHARE_FLAG_READONLY))
		set_conn_flag(conn, CIFSD_SHARE_FLAG_READONLY);

	if (shm_open_connection(share)) {
		resp->status = CIFSD_TREE_CONN_STATUS_TOO_MANY_CONNS;
		goto out_error;
	}

	ret = shm_lookup_hosts_map(share,
				   CIFSD_SHARE_HOSTS_ALLOW_MAP,
				   req->peer_addr);
	if (ret == -ENOENT) {
		resp->status = CIFSD_TREE_CONN_STATUS_HOST_DENIED;
		goto out_error;
	}

	if (ret != 0) {
		ret = shm_lookup_hosts_map(share,
					   CIFSD_SHARE_HOSTS_DENY_MAP,
					   req->peer_addr);
		if (ret == 0) {
			resp->status = CIFSD_TREE_CONN_STATUS_HOST_DENIED;
			goto out_error;
		}
	}

	if (test_share_flag(share, CIFSD_SHARE_FLAG_GUEST_OK)) {
		user = usm_lookup_user(share->guest_account);
		if (user) {
			set_conn_flag(conn, CIFSD_TREE_CONN_FLAG_GUEST_ACCOUNT);
			goto bind;
		}

		user = usm_lookup_user(global_conf.guest_account);
		if (user) {
			set_conn_flag(conn, CIFSD_TREE_CONN_FLAG_GUEST_ACCOUNT);
			goto bind;
		}
	}

	user = usm_lookup_user(req->account);
	if (!user) {
		resp->status = CIFSD_TREE_CONN_STATUS_NO_USER;
		goto out_error;
	}

	if (test_user_flag(user, CIFSD_USER_FLAG_GUEST_ACCOUNT))
		set_conn_flag(conn, CIFSD_TREE_CONN_FLAG_GUEST_ACCOUNT);

	ret = shm_lookup_users_map(share,
				   CIFSD_SHARE_ADMIN_USERS_MAP,
				   req->account);
	if (ret == 0) {
		set_conn_flag(conn, CIFSD_TREE_CONN_FLAG_ADMIN_ACCOUNT);
		goto bind;
	}

	ret = shm_lookup_users_map(share,
				   CIFSD_SHARE_INVALID_USERS_MAP,
				   req->account);
	if (ret == 0) {
		resp->status = CIFSD_TREE_CONN_STATUS_INVALID_USER;
		goto out_error;
	}

	ret = shm_lookup_users_map(share,
				   CIFSD_SHARE_READ_LIST_MAP,
				   req->account);
	if (ret == 0) {
		set_conn_flag(conn, CIFSD_TREE_CONN_FLAG_READ_ONLY);
		clear_conn_flag(conn, CIFSD_TREE_CONN_FLAG_WRITABLE);
		goto bind;
	}

	ret = shm_lookup_users_map(share,
				   CIFSD_SHARE_WRITE_LIST_MAP,
				   req->account);
	if (ret == 0) {
		set_conn_flag(conn, CIFSD_TREE_CONN_FLAG_WRITABLE);
		goto bind;
	}

	ret = shm_lookup_users_map(share,
				   CIFSD_SHARE_VALID_USERS_MAP,
				   req->account);
	if (ret == 0)
		goto bind;
	if (ret == -ENOENT) {
		resp->status = CIFSD_TREE_CONN_STATUS_INVALID_USER;
		goto out_error;
	}

bind:
	conn->id = req->connect_id;
	conn->share = share;
	resp->status = CIFSD_TREE_CONN_STATUS_OK;
	resp->connection_flags = conn->flags;

	if (sm_handle_tree_connect(req->session_id, user, conn))
		pr_err("ERROR: we were unable to bind tree connection\n");
	return 0;

out_error:
	tcm_tree_conn_free(conn);
	shm_close_connection(share);
	put_cifsd_share(share);
	put_cifsd_user(user);
	return -EINVAL;
}

int tcm_handle_tree_disconnect(unsigned long long sess_id,
			       unsigned long long tree_conn_id)
{
	sm_handle_tree_disconnect(sess_id, tree_conn_id);
	return 0;
}
