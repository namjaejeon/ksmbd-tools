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
	g_rw_lock_clear(&user->update_lock);
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

struct cifsd_user *get_cifsd_user(struct cifsd_user *user)
{
	g_rw_lock_writer_lock(&user->update_lock);
	if (user->ref_count != 0)
		user->ref_count++;
	else
		user = NULL;
	g_rw_lock_writer_unlock(&user->update_lock);
	return user;
}

void put_cifsd_user(struct cifsd_user *user)
{
	int drop;

	if (!user)
		return;

	g_rw_lock_writer_lock(&user->update_lock);
	user->ref_count--;
	drop = !user->ref_count;
	g_rw_lock_writer_unlock(&user->update_lock);

	if (!drop)
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

	g_rw_lock_clear(&user->update_lock);
	user->name = name;
	user->pass_b64 = pass;
	user->ref_count = 1;
	user->gid = 9999;
	user->uid = 9999;
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

void usm_destroy(void)
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

	if (!name)
		return NULL;

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

	pwd = pos + 1;
	*pos = 0x00;
	name = strdup(data);

	if (!name)
		return -ENOMEM;

	ret = usm_add_new_user(name, pwd);
	if (ret)
		free(name);
	return ret;
}

void for_each_cifsd_user(walk_users cb, gpointer user_data)
{
	g_rw_lock_reader_lock(&users_table_lock);
	g_hash_table_foreach(users_table, cb, user_data);
	g_rw_lock_reader_unlock(&users_table_lock);
}

int usm_update_user_password(struct cifsd_user *user, char *pswd)
{
	size_t pass_sz;
	char *pass_b64 = strdup(pswd);
	char *pass = base64_decode(pass_b64, &pass_sz);

	if (!pass_b64 || !pass) {
		free(pass_b64);
		free(pass);
		return -ENOMEM;
	}

	g_rw_lock_writer_lock(&user->update_lock);
	free(user->pass_b64);
	free(user->pass);
	user->pass_b64 = pass_b64;
	user->pass = pass;
	user->pass_sz = pass_sz;
	g_rw_lock_writer_unlock(&user->update_lock);

	return 0;
}

static int usm_copy_user_passhash(struct cifsd_user *user,
				  char *pass,
				  size_t sz)
{
	int ret = -ENOSPC;

	if (test_user_flag(user, CIFSD_USER_FLAG_GUEST_ACCOUNT))
		return 0;

	g_rw_lock_reader_lock(&user->update_lock);
	if (sz >= user->pass_sz) {
		memcpy(pass, user->pass, user->pass_sz);
		ret = user->pass_sz;
	}
	g_rw_lock_reader_unlock(&user->update_lock);

	return ret;
}

static int usm_copy_user_account(struct cifsd_user *user,
				 char *account,
				 size_t sz)
{
	int account_sz = strlen(user->name);

	if (sz >= account_sz) {
		memcpy(account, user->name, account_sz);
		return 0;
	}
	return -ENOSPC;
}

int usm_handle_login_request(struct cifsd_login_request *req,
			     struct cifsd_login_response *resp)
{
	struct cifsd_user *user = NULL;
	size_t hash_sz;
	int guest_login = 0;

	if (req->account[0] == '\0')
		guest_login = 1;

	if (!guest_login)
		user = usm_lookup_user(req->account);
	if (user) {
		resp->gid = user->gid;
		resp->uid = user->uid;
		resp->status = user->flags;
		resp->status |= CIFSD_USER_FLAG_OK;

		hash_sz = usm_copy_user_passhash(user,
						 resp->hash,
						 sizeof(resp->hash));
		if (hash_sz > 0)
			resp->hash_sz = hash_sz;
		if (hash_sz < 0)
			resp->status = CIFSD_USER_FLAG_INVALID;

		if (usm_copy_user_account(user,
					  resp->account,
					  sizeof(resp->account)))
			resp->status = CIFSD_USER_FLAG_INVALID;

		put_cifsd_user(user);
		return 0;
	}

	resp->status = CIFSD_USER_FLAG_BAD_USER;
	if (!guest_login &&
		global_conf.map_to_guest == CIFSD_CONF_MAP_TO_GUEST_NEVER)
		return -EINVAL;

	if (guest_login || (!guest_login &&
		global_conf.map_to_guest == CIFSD_CONF_MAP_TO_GUEST_BAD_USER))
		user = usm_lookup_user(global_conf.guest_account);

	if (!user)
		return -EINVAL;

	resp->gid = user->gid;
	resp->uid = user->uid;
	resp->status = user->flags;
	resp->status |= CIFSD_USER_FLAG_OK;
	resp->status |= CIFSD_USER_FLAG_ANONYMOUS;

	if (usm_copy_user_account(user, resp->account, sizeof(resp->account)))
		resp->status = CIFSD_USER_FLAG_INVALID;

	put_cifsd_user(user);
	return 0;
}
