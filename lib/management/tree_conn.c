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

#include <config_parser.h>
#include <management/tree_conn.h>
#include <management/share.h>
#include <management/user.h>
#include <cifsdtools.h>

static GHashTable	*conns_table;
static GRWLock		conns_table_lock;

static GMutex			conn_id_lock;
static unsigned long long	smb2_conn_id = USHRT_MAX;
static unsigned short		smb1_conn_id = 1;

static unsigned short __get_next_smb1_conn_id(void)
{
	unsigned short ret;

	do {
		ret = smb1_conn_id++;
		/* SMB1 id cannot be 0 or 0xFFFE */
	} while (ret == 0 || ret == 0xfffe);

	return ret;
}

static unsigned long long get_next_conn_id(int type)
{
	unsigned long long ret;

	g_mutex_lock(&conn_id_lock);
	if (type & CIFSD_TREE_CONN_FLAG_REQUEST_SMB1)
		ret = __get_next_smb1_conn_id();
	else
		ret = smb2_conn_id++;

	if (smb2_conn_id == 0)
		smb2_conn_id = USHRT_MAX;
	g_mutex_unlock(&conn_id_lock);

	return ret;
}

static void kill_cifsd_tree_conn(struct cifsd_tree_conn *conn)
{
	free(conn);
}

static struct cifsd_tree_conn *new_cifsd_tree_conn(int type)
{
	struct cifsd_tree_conn *conn = malloc(sizeof(struct cifsd_tree_conn));

	if (!conn)
		return NULL;

	memset(conn, 0x00, sizeof(struct cifsd_tree_conn));
	conn->id = get_next_conn_id(type);
	return conn;
}

static void free_hash_entry(gpointer k, gpointer s, gpointer user_data)
{
	kill_cifsd_tree_conn(s);
}

static void tcm_clear_conns(void)
{
	g_rw_lock_writer_lock(&conns_table_lock);
	g_hash_table_foreach(conns_table, free_hash_entry, NULL);
	g_rw_lock_writer_unlock(&conns_table_lock);
}

void tcm_destroy(void)
{
	tcm_clear_conns();
	g_hash_table_destroy(conns_table);
	g_rw_lock_clear(&conns_table_lock);
}

int tcm_init(void)
{
	conns_table = g_hash_table_new(g_int64_hash, g_int64_equal);
	if (!conns_table)
		return -ENOMEM;
	g_rw_lock_init(&conns_table_lock);
	return 0;
}

static int __tcm_remove_conn(struct cifsd_tree_conn *conn)
{
	int ret = -EINVAL;

	g_rw_lock_writer_lock(&conns_table_lock);
	if (g_hash_table_remove(conns_table, &conn->id))
		ret = 0;
	g_rw_lock_writer_unlock(&conns_table_lock);

	if (!ret)
		kill_cifsd_tree_conn(conn);
	return ret;
}

static struct cifsd_tree_conn *__tcm_lookup_conn(unsigned long long id)
{
	return g_hash_table_lookup(conns_table, &id);
}

struct cifsd_tree_conn *tcm_lookup_conn(unsigned long long id)
{
	struct cifsd_tree_conn *conn;

	g_rw_lock_reader_lock(&conns_table_lock);
	conn = __tcm_lookup_conn(id);
	g_rw_lock_reader_unlock(&conns_table_lock);
	return conn;
}

int tcm_handle_tree_connect(struct cifsd_tree_connect_request *req,
			    struct cifsd_tree_connect_response *resp)
{
	struct cifsd_user *user = NULL;
	struct cifsd_share *share = NULL;
	struct cifsd_tree_conn *conn = new_cifsd_tree_conn(req->flags);
	int ret;

	if (!conn) {
		resp->status = CIFSD_TREE_CONN_STATUS_NOMEM;
		return -ENOMEM;
	}

	share = shm_lookup_share(req->share);
	if (!share) {
		resp->status = CIFSD_TREE_CONN_STATUS_NO_SHARE;
		goto out_error;
	}

	ret = shm_lookup_hosts_map(share,
				   CIFSD_SHARE_HOSTS_ALLOW_MAP,
				   req->host);
	if (ret == -ENOENT) {
		resp->status = CIFSD_TREE_CONN_STATUS_HOST_DENIED;
		goto out_error;
	}

	if (ret != 0) {
		ret = shm_lookup_hosts_map(share,
					   CIFSD_SHARE_HOSTS_DENY_MAP,
					   req->host);
		if (ret == 0) {
			resp->status = CIFSD_TREE_CONN_STATUS_HOST_DENIED;
			goto out_error;
		}
	}

	if (get_share_flag(share, CIFSD_SHARE_GUEST_OK)) {
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
		goto bind;
	}

	ret = shm_lookup_users_map(share,
				   CIFSD_SHARE_WRITE_LIST_MAP,
				   req->account);
	if (ret == 0)
		goto bind;

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
	g_rw_lock_writer_lock(&conns_table_lock);
	if (__tcm_lookup_conn(conn->id)) {
		g_rw_lock_writer_unlock(&conns_table_lock);
		pr_info("conn already exists %lld\n", conn->id);
		resp->status = CIFSD_TREE_CONN_STATUS_CONN_EXIST;
		goto out_error;
	}

	if (!g_hash_table_insert(conns_table, &conn->id, conn)) {
		g_rw_lock_writer_unlock(&conns_table_lock);
		resp->status = CIFSD_TREE_CONN_STATUS_ERROR;
		goto out_error;
	}
	g_rw_lock_writer_unlock(&conns_table_lock);

	resp->status = CIFSD_TREE_CONN_STATUS_OK;
	resp->connection_flags = conn->flags;
	resp->connection_id = conn->id;

	conn->share = share;
	conn->user = user;
	usm_bind_connection(user, conn);
	shm_bind_connection(share, conn);
	return 0;

out_error:
	kill_cifsd_tree_conn(conn);
	put_cifsd_share(share);
	put_cifsd_user(user);
	return -EINVAL;
}

int tcm_handle_tree_disconnect(unsigned long long id)
{
	struct cifsd_tree_conn *conn = tcm_lookup_conn(id);

	if (!conn)
		return -ENOENT;

	usm_unbind_connection(conn->user, conn);
	shm_unbind_connection(conn->share, conn);

	put_cifsd_share(conn->share);
	put_cifsd_user(conn->user);

	__tcm_remove_conn(conn);
	return 0;
}
