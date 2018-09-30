// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <config_parser.h>
#include <linux/cifsd_server.h>

#include <management/share.h>
#include <management/user.h>
#include <cifsdtools.h>

static GHashTable	*shares_table;
static GRWLock		shares_table_lock;

static void list_hosts_callback(gpointer k, gpointer v, gpointer user_data)
{
	free(k);
	free(v);
}

static void free_hosts_map(GHashTable *map)
{
	if (map) {
		g_hash_table_foreach(map, list_hosts_callback, NULL);
		g_hash_table_destroy(map);
	}
}

static void list_user_callback(gpointer k, gpointer u, gpointer user_data)
{
	put_cifsd_user((struct cifsd_user *)u);
}

static void free_user_map(GHashTable *map)
{
	if (map) {
		g_hash_table_foreach(map, list_user_callback, NULL);
		g_hash_table_destroy(map);
	}
}

static void kill_cifsd_share(struct cifsd_share *share)
{
	int i;

	pr_debug("Kill share %s\n", share->name);

	for (i = 0; i < CIFSD_SHARE_USERS_MAX; i++)
		free_user_map(share->maps[i]);

	free_hosts_map(share->hosts_allow_map);
	free_hosts_map(share->hosts_deny_map);

	g_rw_lock_clear(&share->maps_lock);

	free(share->name);
	free(share->path);
	free(share->comment);
	free(share->veto_list);
	free(share->guest_account);
	g_rw_lock_clear(&share->update_lock);
	free(share);
}

static int __shm_remove_share(struct cifsd_share *share)
{
	int ret = -EINVAL;

	g_rw_lock_writer_lock(&shares_table_lock);
	if (g_hash_table_remove(shares_table, share->name))
		ret = 0;
	g_rw_lock_writer_unlock(&shares_table_lock);

	if (!ret)
		kill_cifsd_share(share);
	return ret;
}

struct cifsd_share *get_cifsd_share(struct cifsd_share *share)
{
	g_rw_lock_writer_lock(&share->update_lock);
	if (share->ref_count != 0)
		share->ref_count++;
	else
		share = NULL;
	g_rw_lock_writer_unlock(&share->update_lock);

	return share;
}

void put_cifsd_share(struct cifsd_share *share)
{
	int drop;

	if (!share)
		return;

	g_rw_lock_writer_lock(&share->update_lock);
	share->ref_count--;
	drop = !share->ref_count;
	g_rw_lock_writer_unlock(&share->update_lock);

	if (!drop)
		return;

	__shm_remove_share(share);
}

static struct cifsd_share *new_cifsd_share(void)
{
	struct cifsd_share *share = malloc(sizeof(struct cifsd_share));
	int i;

	if (!share)
		return NULL;

	memset(share, 0x00, sizeof(struct cifsd_share));

	share->ref_count = 1;
	/*
	 * Create maps as needed. NULL maps means that share
	 * does not have a corresponding shmbconf entry.
	 */
	for (i = 0; i < CIFSD_SHARE_USERS_MAX; i++)
		share->maps[i] = NULL;

	share->hosts_allow_map = NULL;
	share->hosts_deny_map = NULL;
	g_rw_lock_init(&share->maps_lock);
	g_rw_lock_init(&share->update_lock);

	return share;
}

static void free_hash_entry(gpointer k, gpointer s, gpointer user_data)
{
	kill_cifsd_share(s);
}

static void shm_clear_shares(void)
{
	g_hash_table_foreach(shares_table, free_hash_entry, NULL);
}

void shm_destroy(void)
{
	shm_clear_shares();
	g_hash_table_destroy(shares_table);
	g_rw_lock_clear(&shares_table_lock);
}

int shm_init(void)
{
	shares_table = g_hash_table_new(g_str_hash, g_str_equal);
	if (!shares_table)
		return -ENOMEM;
	g_rw_lock_init(&shares_table_lock);
	return 0;
}

static struct cifsd_share *__shm_lookup_share(char *name)
{
	return g_hash_table_lookup(shares_table, name);
}

struct cifsd_share *shm_lookup_share(char *name)
{
	struct cifsd_share *share, *ret;

	g_rw_lock_reader_lock(&shares_table_lock);
	share = __shm_lookup_share(name);
	if (share) {
		ret = get_cifsd_share(share);
		if (!ret)
			share = NULL;
	}
	g_rw_lock_reader_unlock(&shares_table_lock);
	return share;
}

static GHashTable *parse_list(GHashTable *map, char **list)
{
	int i;

	if (!list)
		return map;

	if (!map)
		map = g_hash_table_new(g_str_hash, g_str_equal);
	if (!map)
		return map;

	for (i = 0;  list[i] != NULL; i++) {
		struct cifsd_user *user;
		char *p = list[i];

		while (*p && *p == ' ') p++;
		if (*p == 0x00) continue;

		user = usm_lookup_user(p);
		if (!user) {
			pr_info("Drop non-existing user `%s'\n", p);
			continue;
		}

		if (g_hash_table_lookup(map, user->name)) {
			pr_debug("User already exists in a map: %s\n", p);
			continue;
		}

		g_hash_table_insert(map, user->name, user);
	}

	cp_group_kv_list_free(list);
	return map;
}

static void make_veto_list(struct cifsd_share *share)
{
	int i;

	for (i = 0; i < share->veto_list_sz; i++) {
		if (share->veto_list[i] == '/')
			share->veto_list[i] = 0x00;
	}
}

static void process_group_kv(gpointer _k, gpointer _v, gpointer user_data)
{
	struct cifsd_share *share = user_data;
	char *k = _k;
	char *v = _v;

	if (!cp_key_cmp(k, "comment")) {
		share->comment = cp_get_group_kv_string(v);
		if (share->comment == NULL)
			set_share_flag(share, CIFSD_SHARE_FLAG_INVALID);
		return;
	}

	if (!cp_key_cmp(k, "path")) {
		share->path = cp_get_group_kv_string(v);
		if (share->path == NULL)
			set_share_flag(share, CIFSD_SHARE_FLAG_INVALID);
		return;
	}

	if (!cp_key_cmp(k, "guest ok")) {
		if (cp_get_group_kv_bool(v))
			set_share_flag(share, CIFSD_SHARE_FLAG_GUEST_OK);
		return;
	}

	if (!cp_key_cmp(_k, "guest account")) {
		struct cifsd_user *user;

		if (usm_add_new_user(cp_get_group_kv_string(_v),
				     strdup("NULL"))) {
			pr_err("Unable to add guest account\n");
			set_share_flag(share, CIFSD_SHARE_FLAG_INVALID);
			return;
		}

		user = usm_lookup_user(_v);
		if (user) {
			set_user_flag(user, CIFSD_USER_FLAG_GUEST_ACCOUNT);
			put_cifsd_user(user);
		}
		share->guest_account = cp_get_group_kv_string(_v);
		if (!share->guest_account)
			set_share_flag(share, CIFSD_SHARE_FLAG_INVALID);
		return;
	}

	if (!cp_key_cmp(k, "read only")) {
		if (cp_get_group_kv_bool(v)) {
			set_share_flag(share, CIFSD_SHARE_FLAG_READONLY);
			clear_share_flag(share, CIFSD_SHARE_FLAG_WRITEABLE);
		}
		return;
	}

	if (!cp_key_cmp(k, "browseable")) {
		if (cp_get_group_kv_bool(v))
			set_share_flag(share, CIFSD_SHARE_FLAG_BROWSEABLE);
		else
			clear_share_flag(share, CIFSD_SHARE_FLAG_BROWSEABLE);
		return;
	}

	if (!cp_key_cmp(k, "write ok") || !cp_key_cmp(k, "writeable")) {
		if (cp_get_group_kv_bool(v))
			set_share_flag(share, CIFSD_SHARE_FLAG_WRITEABLE);
		else
			clear_share_flag(share, CIFSD_SHARE_FLAG_WRITEABLE);
		return;
	}

	if (!cp_key_cmp(k, "store dos attributes")) {
		if (cp_get_group_kv_bool(v))
			set_share_flag(share, CIFSD_SHARE_FLAG_STORE_DOS_ATTRS);
		else
			clear_share_flag(share, CIFSD_SHARE_FLAG_STORE_DOS_ATTRS);
		return;
	}

	if (!cp_key_cmp(k, "oplocks")) {
		if (cp_get_group_kv_bool(v))
			set_share_flag(share, CIFSD_SHARE_FLAG_OPLOCKS);
		else
			clear_share_flag(share, CIFSD_SHARE_FLAG_OPLOCKS);
		return;
	}

	if (!cp_key_cmp(k, "create mask")) {
		share->create_mask = cp_get_group_kv_long_base(v, 8);
		return;
	}

	if (!cp_key_cmp(k, "directory mask")) {
		share->directory_mask = cp_get_group_kv_long_base(v, 8);
		return;
	}

	if (!cp_key_cmp(k, "valid users")) {
		share->maps[CIFSD_SHARE_VALID_USERS_MAP] =
			parse_list(share->maps[CIFSD_SHARE_VALID_USERS_MAP],
			           cp_get_group_kv_list(v));
		if (share->maps[CIFSD_SHARE_VALID_USERS_MAP] == NULL)
			set_share_flag(share, CIFSD_SHARE_FLAG_INVALID);
		return;
	}

	if (!cp_key_cmp(k, "invalid users")) {
		share->maps[CIFSD_SHARE_INVALID_USERS_MAP] =
			parse_list(share->maps[CIFSD_SHARE_INVALID_USERS_MAP],
			           cp_get_group_kv_list(v));
		if (share->maps[CIFSD_SHARE_INVALID_USERS_MAP] == NULL)
			set_share_flag(share, CIFSD_SHARE_FLAG_INVALID);
		return;
	}

	if (!cp_key_cmp(k, "read list")) {
		share->maps[CIFSD_SHARE_READ_LIST_MAP] =
			parse_list(share->maps[CIFSD_SHARE_READ_LIST_MAP],
				   cp_get_group_kv_list(v));
		if (share->maps[CIFSD_SHARE_READ_LIST_MAP] == NULL)
			set_share_flag(share, CIFSD_SHARE_FLAG_INVALID);
		return;
	}

	if (!cp_key_cmp(k, "write list")) {
		share->maps[CIFSD_SHARE_WRITE_LIST_MAP] =
			parse_list(share->maps[CIFSD_SHARE_WRITE_LIST_MAP],
				   cp_get_group_kv_list(v));
		if (share->maps[CIFSD_SHARE_WRITE_LIST_MAP] == NULL)
			set_share_flag(share, CIFSD_SHARE_FLAG_INVALID);
		return;
	}

	if (!cp_key_cmp(k, "admin users")) {
		share->maps[CIFSD_SHARE_ADMIN_USERS_MAP] =
			parse_list(share->maps[CIFSD_SHARE_ADMIN_USERS_MAP],
				   cp_get_group_kv_list(v));
		if (share->maps[CIFSD_SHARE_ADMIN_USERS_MAP] == NULL)
			set_share_flag(share, CIFSD_SHARE_FLAG_INVALID);
		return;
	}

	if (!cp_key_cmp(k, "hosts allow")) {
		share->hosts_allow_map = parse_list(share->hosts_allow_map,
						    cp_get_group_kv_list(v));
		if (share->hosts_allow_map == NULL)
			set_share_flag(share, CIFSD_SHARE_FLAG_INVALID);
		return;
	}

	if (!cp_key_cmp(k, "hosts deny")) {
		share->hosts_deny_map = parse_list(share->hosts_deny_map,
						   cp_get_group_kv_list(v));
		if (share->hosts_deny_map == NULL)
			set_share_flag(share, CIFSD_SHARE_FLAG_INVALID);
		return;
	}

	if (!cp_key_cmp(k, "max connections")) {
		share->max_connections = cp_get_group_kv_long_base(v, 10);
		return;
	}

	if (!cp_key_cmp(k, "veto files")) {
		share->veto_list = cp_get_group_kv_string(v + 1);
		if (share->veto_list == NULL) {
			set_share_flag(share, CIFSD_SHARE_FLAG_INVALID);
		} else {
			share->veto_list_sz = strlen(share->veto_list);
			make_veto_list(share);
		}
		return;
	}
}

static int init_share_from_group(struct cifsd_share *share,
				 struct smbconf_group *group)
{
	share->name = strdup(group->name);

	set_share_flag(share, CIFSD_SHARE_FLAG_AVAILABLE);
	set_share_flag(share, CIFSD_SHARE_FLAG_BROWSEABLE);
	set_share_flag(share, CIFSD_SHARE_FLAG_OPLOCKS);
	set_share_flag(share, CIFSD_SHARE_FLAG_READONLY);

	if (!cp_key_cmp(share->name, "IPC$"))
		set_share_flag(share, CIFSD_SHARE_FLAG_PIPE);

	g_hash_table_foreach(group->kv, process_group_kv, share);
}

int shm_add_new_share(struct smbconf_group *group)
{
	int ret = 0;
	struct cifsd_share *share = new_cifsd_share();

	if (!share)
		return -ENOMEM;

	init_share_from_group(share, group);
	if (test_share_flag(share, CIFSD_SHARE_FLAG_INVALID)) {
		pr_err("Invalid share %s\n", share->name);
		kill_cifsd_share(share);
		return 0;
	}

	g_rw_lock_writer_lock(&shares_table_lock);
	if (__shm_lookup_share(share->name)) {
		g_rw_lock_writer_unlock(&shares_table_lock);
		pr_info("share exists %s\n", share->name);
		kill_cifsd_share(share);
		return 0;
	}

	if (!g_hash_table_insert(shares_table, share->name, share)) {
		kill_cifsd_share(share);
		ret = -EINVAL;
	}
	g_rw_lock_writer_unlock(&shares_table_lock);
	return ret;
}

int shm_lookup_users_map(struct cifsd_share *share,
			  enum share_users map,
			  char *name)
{
	int ret = -ENOENT;

	if (map >= CIFSD_SHARE_USERS_MAX) {
		pr_err("Invalid users map index: %d\n", map);
		return 0;
	}

	if (!share->maps[map])
		return -EINVAL;

	g_rw_lock_reader_lock(&share->maps_lock);
	if (g_hash_table_lookup(share->maps[map], name))
		ret = 0;
	g_rw_lock_reader_unlock(&share->maps_lock);

	return ret;
}

/*
 * FIXME
 * Do a real hosts lookup. IP masks, etc.
 */
int shm_lookup_hosts_map(struct cifsd_share *share,
			  enum share_hosts map,
			  char *host)
{
	GHashTable *lookup_map;
	int ret = -ENOENT;

	if (map >= CIFSD_SHARE_HOSTS_MAX) {
		pr_err("Invalid hosts map index: %d\n", map);
		return 0;
	}

	if (map == CIFSD_SHARE_HOSTS_ALLOW_MAP)
		lookup_map = share->hosts_allow_map;
	if (map == CIFSD_SHARE_HOSTS_DENY_MAP)
		lookup_map = share->hosts_deny_map;

	if (!lookup_map)
		return -EINVAL;

	g_rw_lock_reader_lock(&share->maps_lock);
	if (g_hash_table_lookup(lookup_map, host))
		ret = 0;
	g_rw_lock_reader_unlock(&share->maps_lock);

	return ret;
}

int shm_open_connection(struct cifsd_share *share)
{
	int ret = 0;

	g_rw_lock_writer_lock(&share->update_lock);
	share->num_connections++;
	if (share->max_connections) {
		if (share->num_connections >= share->max_connections)
			ret = -EINVAL;
	}
	g_rw_lock_writer_unlock(&share->update_lock);
	return ret;
}

int shm_close_connection(struct cifsd_share *share)
{
	if (!share)
		return 0;

	g_rw_lock_writer_lock(&share->update_lock);
	share->num_connections--;
	g_rw_lock_writer_unlock(&share->update_lock);
	return 0;
}

void for_each_cifsd_share(walk_shares cb, gpointer user_data)
{
	g_rw_lock_reader_lock(&shares_table_lock);
	g_hash_table_foreach(shares_table, cb, user_data);
	g_rw_lock_reader_unlock(&shares_table_lock);
}

int shm_share_config_payload_size(struct cifsd_share *share)
{
	int sz = 1;

	if (share && !test_share_flag(share, CIFSD_SHARE_FLAG_PIPE)) {
		sz += strlen(share->path);
		sz += share->veto_list_sz;
	}

	return sz;
}

int shm_handle_share_config_request(struct cifsd_share *share,
				    struct cifsd_share_config_response *resp)
{
	void *config_payload;
	size_t path_sz = 0;

	if (!share)
		return -EINVAL;

	resp->flags = share->flags;
	resp->veto_list_sz = share->veto_list_sz;

	if (test_share_flag(share, CIFSD_SHARE_FLAG_PIPE))
		return 0;

	config_payload = CIFSD_SHARE_CONFIG_VETO_LIST(resp);
	if (resp->veto_list_sz) {
		memcpy(config_payload,
		       share->veto_list,
		       resp->veto_list_sz);
		config_payload += resp->veto_list_sz;
	}
	memcpy(config_payload, share->path, strlen(share->path));
	return 0;
}
