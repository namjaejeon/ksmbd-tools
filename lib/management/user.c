/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@sourceforge.net
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

#include <management/user.h>
#include <cifsdtools.h>

static GHashTable	*users_table;
static GRWLock		users_table_lock;

static void kill_cifsd_user(struct cifsd_user *user)
{
	pr_debug("Kill user %s\n", user->name);

	free(user->name);
	free(user->pass_b64);
	free(user->pass);
	g_rw_lock_clear(&user->conns_lock);
	free(user);
}

static int __usm_remove_user(struct cifsd_user *user)
{
	int ret = -EINVAL;

	g_rw_lock_writer_lock(&users_table_lock);
	if (g_hash_table_remove(users_table, user->name))
		ret = 0;
	g_rw_lock_writer_unlock(&users_table_lock);

	if (!ret)
		kill_cifsd_user(user);
	return ret;
}

static struct cifsd_user *get_cifsd_user(struct cifsd_user *user)
{
	if (g_atomic_int_add(&user->ref_count, 1) == 0) {
		g_atomic_int_add(&user->ref_count, -1);
		return NULL;
	}
	return user;
}

void put_cifsd_user(struct cifsd_user *user)
{
	if (!user)
		return;

	if (!g_atomic_int_dec_and_test(&user->ref_count))
		return;

	__usm_remove_user(user);
}

static struct cifsd_user *new_cifsd_user(char *name, char *pwd)
{
	struct cifsd_user *user = malloc(sizeof(struct cifsd_user));
	struct passwd *passwd;
	char *pass = strdup(pwd);

	if (!pass || !user) {
		free(user);
		free(pass);
		return NULL;
	}

	memset(user, 0x00, sizeof(struct cifsd_user));

	g_rw_lock_clear(&user->conns_lock);
	user->name = name;
	user->pass_b64 = pass;
	user->ref_count = 1;
	passwd = getpwnam(name);
	if (passwd) {
		user->uid = passwd->pw_uid;
		user->gid = passwd->pw_gid;
	}

	user->pass = base64_decode(user->pass_b64, &user->pass_sz);
	return user;
}

static void free_hash_entry(gpointer k, gpointer u, gpointer user_data)
{
	kill_cifsd_user(u);
}

static void usm_clear_users(void)
{
	g_rw_lock_writer_lock(&users_table_lock);
	g_hash_table_foreach(users_table, free_hash_entry, NULL);
	g_rw_lock_writer_unlock(&users_table_lock);
}

void usm_final_release(void)
{
	usm_clear_users();
	g_hash_table_destroy(users_table);
	g_rw_lock_clear(&users_table_lock);
}

int usm_init(void)
{
	users_table = g_hash_table_new(g_str_hash, g_str_equal);
	if (!users_table)
		return -ENOMEM;
	g_rw_lock_init(&users_table_lock);
	return 0;
}

static struct cifsd_user *__usm_lookup_user(char *name)
{
	return g_hash_table_lookup(users_table, name);
}

struct cifsd_user *usm_lookup_user(char *name)
{
	struct cifsd_user *user, *ret;

	g_rw_lock_reader_lock(&users_table_lock);
	user = __usm_lookup_user(name);
	if (user) {
		ret = get_cifsd_user(user);
		if (!ret)
			user = NULL;
	}
	g_rw_lock_reader_unlock(&users_table_lock);
	return user;
}

int usm_add_new_user(char *name, char *pwd)
{
	int ret = 0;
	struct cifsd_user *user = new_cifsd_user(name, pwd);

	if (!user)
		return -ENOMEM;

	g_rw_lock_writer_lock(&users_table_lock);
	if (__usm_lookup_user(name)) {
		g_rw_lock_writer_unlock(&users_table_lock);
		pr_info("User exists %s\n", name);
		kill_cifsd_user(user);
		return 0;
	}

	if (!g_hash_table_insert(users_table, user->name, user)) {
		kill_cifsd_user(user);
		ret = -EINVAL;
	}
	g_rw_lock_writer_unlock(&users_table_lock);
	return ret;
}

int usm_new_user_from_pwdentry(char *data)
{
	char *name;
	char *pwd;
	char *pos = strchr(data, ':');
	size_t sz = 0;
	int ret;

	if (!pos) {
		pr_err("Invalid pwd entry %s\n", data);
		return -EINVAL;
	}

	pwd = strdup(pos + 1);
	*pos = 0x00;
	name = strdup(data);

	if (!name || !pwd) {
		free(name);
		free(pwd);
		return -ENOMEM;
	}

	ret = usm_add_new_user(name, pwd);
	if (ret) {
		free(name);
		free(pwd);
	}
	return ret;
}

int usm_bind_connection(struct cifsd_user *user,
			struct cifsd_tree_conn *conn)
{
	g_rw_lock_writer_lock(&user->conns_lock);
	user->conns = g_list_insert(user->conns, conn, -1);
	g_rw_lock_writer_unlock(&user->conns_lock);
	return 0;
}

void usm_unbind_connection(struct cifsd_user *user,
			   struct cifsd_tree_conn *conn)
{
	g_rw_lock_writer_lock(&user->conns_lock);
	user->conns = g_list_remove(user->conns, conn);
	g_rw_lock_writer_unlock(&user->conns_lock);
}

static void hash_walk_cb(gpointer k, gpointer u, gpointer user_data)
{
	walk_users cb = (walk_users)user_data;
	cb(u);
}

void for_each_cifsd_user(walk_users cb)
{
	g_rw_lock_reader_lock(&users_table_lock);
	g_hash_table_foreach(users_table, hash_walk_cb, cb);
	g_rw_lock_reader_unlock(&users_table_lock);
}
