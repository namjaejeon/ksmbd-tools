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
#include <management/session.h>
#include <management/tree_conn.h>
#include <management/user.h>
#include <cifsdtools.h>

static GHashTable	*sessions_table;
static GRWLock		sessions_table_lock;

static void __free_func(gpointer data, gpointer user_data)
{
	struct cifsd_tree_conn *tree_conn;

	tree_conn = (struct cifsd_tree_conn *)data;
	/* free(data); */
}

static void kill_cifsd_session(struct cifsd_session *sess)
{
	g_list_foreach (sess->tree_conns, __free_func, NULL);
	g_rw_lock_clear(&sess->update_lock);
	put_cifsd_user(sess->user);
	free(sess);
}

static struct cifsd_session *new_cifsd_session(unsigned long long id,
					       struct cifsd_user *user)
{
	struct cifsd_session *sess = malloc(sizeof(struct cifsd_session));

	if (!sess)
		return NULL;

	g_rw_lock_init(&sess->update_lock);
	memset(sess, 0x00, sizeof(struct cifsd_session));
	sess->ref_counter = 1;
	sess->id = id;
	sess->user = user;
	return sess;
}

static void free_hash_entry(gpointer k, gpointer s, gpointer user_data)
{
	kill_cifsd_session(s);
}

static void sm_clear_session(void)
{
	g_rw_lock_writer_lock(&sessions_table_lock);
	g_hash_table_foreach(sessions_table, free_hash_entry, NULL);
	g_rw_lock_writer_unlock(&sessions_table_lock);
}

static int __sm_remove_session(struct cifsd_session *sess)
{
	int ret = -EINVAL;

	g_rw_lock_writer_lock(&sessions_table_lock);
	if (g_hash_table_remove(sessions_table, &sess->id))
		ret = 0;
	g_rw_lock_writer_unlock(&sessions_table_lock);

	if (!ret)
		kill_cifsd_session(sess);
	return ret;
}

static struct cifsd_session *__get_session(struct cifsd_session *sess)
{
	struct cifsd_session *ret = NULL;

	g_rw_lock_writer_lock(&sess->update_lock);
	if (sess->ref_counter != 0) {
		sess->ref_counter++;
		ret = sess;
	} else {
		ret = NULL;
	}
	g_rw_lock_writer_unlock(&sess->update_lock);
	return ret;
}

static void __put_session(struct cifsd_session *sess)
{
	int drop = 0;

	g_rw_lock_writer_lock(&sess->update_lock);
	sess->ref_counter--;
	drop = !sess->ref_counter;
	g_rw_lock_writer_unlock(&sess->update_lock);

	if (drop)
		__sm_remove_session(sess);
}

static struct cifsd_session *__sm_lookup_session(unsigned long long id)
{
	return g_hash_table_lookup(sessions_table, &id);
}

static struct cifsd_session *sm_lookup_session(unsigned long long id)
{
	struct cifsd_session *sess;

	g_rw_lock_reader_lock(&sessions_table_lock);
	sess = __sm_lookup_session(id);
	if (sess)
		sess = __get_session(sess);
	g_rw_lock_reader_unlock(&sessions_table_lock);
	return sess;
}

static int sm_insert_session(struct cifsd_session *sess)
{
	int ret;

	g_rw_lock_writer_lock(&sessions_table_lock);
	ret = g_hash_table_insert(sessions_table, &(sess->id), sess);
	g_rw_lock_writer_lock(&sessions_table_lock);

	return ret;
}

int sm_handle_tree_connect(unsigned long long id,
			   struct cifsd_user *user,
			   struct cifsd_tree_conn *tree_conn)
{
	struct cifsd_session *sess, *lookup;

retry:
	sess = sm_lookup_session(id);
	if (!sess) {
		sess = new_cifsd_session(id, user);
		if (!sess)
			return -EINVAL;

		g_rw_lock_writer_lock(&sessions_table_lock);
		lookup = __sm_lookup_session(id);
		if (lookup)
			lookup = __get_session(lookup);
		if (lookup) {
			kill_cifsd_session(sess);
			sess = lookup;
		}
		if (!g_hash_table_insert(sessions_table, &(sess->id), sess)) {
			kill_cifsd_session(sess);
			sess = NULL;
		}
		g_rw_lock_writer_unlock(&sessions_table_lock);

		if (!sess)
			goto retry;
	}

	g_rw_lock_writer_lock(&sess->update_lock);
	sess->tree_conns = g_list_insert(sess->tree_conns, tree_conn, -1);
	g_rw_lock_writer_unlock(&sess->update_lock);
	return 0;
}

static gint lookup_tree_conn(gconstpointer data, gconstpointer user_data)
{
	struct cifsd_tree_conn *tree_conn = (struct cifsd_tree_conn *)data;
	unsigned long long id = (unsigned long long)user_data;

	if (tree_conn->id == id)
		return 0;
	return 1;
}

int sm_handle_tree_disconnect(unsigned long long sess_id,
			      unsigned long long tree_conn_id)
{
	struct cifsd_session *sess;
	GList *tree_conn;
	int drop;

	sess = sm_lookup_session(sess_id);
	if (!sess)
		return 0;

	g_rw_lock_writer_lock(&sess->update_lock);
	tree_conn = g_list_find_custom(sess->tree_conns,
				       (gconstpointer)tree_conn_id,
				       lookup_tree_conn);
	if (tree_conn) {
		sess->tree_conns = g_list_remove(sess->tree_conns, tree_conn);
		sess->ref_counter--;
		///
		/* free tc */
		///
	}
	g_rw_lock_writer_unlock(&sess->update_lock);

	__put_session(sess);
	return 0;
}

void sm_destroy(void)
{
	sm_clear_session();
	g_hash_table_destroy(sessions_table);
	g_rw_lock_clear(&sessions_table_lock);
}

int sm_init(void)
{
	sessions_table = g_hash_table_new(g_int64_hash, g_int64_equal);
	if (!sessions_table)
		return -ENOMEM;
	g_rw_lock_init(&sessions_table_lock);
	return 0;
}
