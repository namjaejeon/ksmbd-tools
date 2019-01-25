// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <glib.h>
#include <string.h>
#include <glib/gstdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/cifsd_server.h>

#include <config_parser.h>
#include <cifsdtools.h>
#include <management/user.h>
#include <management/share.h>

struct smbconf_global global_conf;
static struct smbconf_parser parser;

static int is_ascii_spacei_tab(char c)
{
	return c == ' ' || c == '\t';
}

static int is_a_comment(char *line)
{
	return (*line == 0x00 || *line == ';' || *line == '\n' || *line == '#');
}

static int is_a_group(char *line)
{
	char *p = line;

	if (*p != '[')
		return 0;
	p++;
	while (*p && *p != ']')
		p = g_utf8_find_next_char(p, NULL);
	if (*p != ']')
		return 0;
	return 1;
}

static int add_new_group(char *line)
{
	char *begin = line;
	char *end = line;
	char *name = NULL;
	struct smbconf_group *group = NULL;
	struct smbconf_group *lookup;

	while (*end && *end != ']')
		end = g_utf8_find_next_char(end, NULL);

	name = g_ascii_strdown(begin + 1, end - begin - 1);
	if (!name)
		goto out_free;

	lookup = g_hash_table_lookup(parser.groups, name);
	if (lookup) {
		parser.current = lookup;
		pr_info("SMB conf: multiple group definitions `%s'\n",
				name);
		free(name);
		return 0;
	}

	group = malloc(sizeof(struct smbconf_group));
	if (!group)
		goto out_free;

	group->name = name;
	group->kv = g_hash_table_new(g_str_hash, g_str_equal);
	if (!group->kv)
		goto out_free;

	parser.current = group;
	g_hash_table_insert(parser.groups, group->name, group);
	return 0;

out_free:
	free(name);
	if (group && group->kv)
		g_hash_table_destroy(group->kv);
	free(group);
	return -ENOMEM;
}

static int add_group_key_value(char *line)
{
	char *key, *value;
	
	key = strchr(line, '=');
	if (!key)
		return -EINVAL;

	value = key;
	*key = 0x00;
	key--;
	value++;

	while (is_ascii_spacei_tab(*key)) key--;
	while (is_ascii_spacei_tab(*value)) value++;

	if (is_a_comment(value))
		return 0;

	if (g_hash_table_lookup(parser.current->kv, key)) {
		pr_info("SMB conf: multuple key-value [%s] %s\n",
				parser.current->name, key);
		return 0;
	}

	key = strndup(line, key - line + 1);
	value = strdup(value);

	if (!key || !value) {
		free(key);
		free(value);
		return -ENOMEM;
	}

	g_hash_table_insert(parser.current->kv, key, value);
	return 0;
}

static int process_smbconf_entry(char *data)
{
	while (is_ascii_spacei_tab(*data)) data++;

	if (is_a_comment(data))
		return 0;

	if (is_a_group(data))
		return add_new_group(data);

	return add_group_key_value(data);
}

static int __mmap_parse_file(const char *fname, int (*callback)(char *data))
{
	GMappedFile *file;
	GError *err = NULL;
	gchar *contents;
	gsize len;
	char *delim;
	int fd, ret = 0;

	fd = g_open(fname, O_RDONLY, 0);
	if (fd == -1) {
		pr_err("Can't open `%s': %s\n", fname, strerror(errno));
		return -EINVAL;
	}

	file = g_mapped_file_new_from_fd(fd, FALSE, &err);
	if (err) {
		pr_err("%s: `%s'\n", err->message, fname);
		g_error_free(err);
		ret = -EINVAL;
		goto out;
	}

	contents = g_mapped_file_get_contents(file);
	if (!contents)
		goto out;

	len = g_mapped_file_get_length(file);
	while (len) {
		delim = strchr(contents, '\n');
		if (!delim)
			delim = strchr(contents, 0x00);

		if (delim) {
			size_t sz = delim - contents;
			char *data;

			if (delim == contents) {
				contents = delim + 1;
				len--;
				continue;
			}

			if (!sz)
				break;

			data = malloc(sz + 1);
			if (!data) {
				ret = -ENOMEM;
				goto out;
			}

			strncpy(data, contents, sz);
			data[sz] = 0x00;

			ret = callback(data);
			if (ret) {
				free(data);
				goto out;
			}

			free(data);
			contents = delim + 1;
			len -= (sz + 1);
		}
	}

	ret = 0;
out:
	if (file)
		g_mapped_file_unref(file);

	if (fd) {
		g_close(fd, &err);
		if (err) {
			pr_err("%s: %s\n", err->message, fname);
			g_error_free(err);
		}
	}
	return ret;
}

static int init_smbconf_parser(void)
{
	parser.groups = g_hash_table_new(g_str_hash, g_str_equal);
	if (!parser.groups)
		return -ENOMEM;
	return 0;
}

static void release_group_key_value(gpointer k, gpointer v, gpointer user_data)
{
	free(k);
	free(v);
}

static void release_smbconf_group(gpointer k, gpointer v, gpointer user_data)
{
	struct smbconf_group *g = v;

	g_hash_table_foreach(g->kv, release_group_key_value, NULL);
	g_hash_table_destroy(g->kv);
	free(g->name);
	free(g);
}

static void release_smbconf_parser(void)
{
	if (!parser.groups)
		return;

	g_hash_table_foreach(parser.groups, release_smbconf_group, NULL);
	g_hash_table_destroy(parser.groups);
	parser.groups = NULL;
}

int cp_key_cmp(char *k, char *v)
{
	if (!k || !v)
		return -1;
	return g_ascii_strncasecmp(k, v, strlen(v));
}

char *cp_get_group_kv_string(char *v)
{
	return strdup(v);
}

int cp_get_group_kv_bool(char *v)
{
	if (!g_ascii_strncasecmp(v, "yes", 3) ||
		!g_ascii_strncasecmp(v, "1", 1) ||
		!g_ascii_strncasecmp(v, "true", 4) ||
		!g_ascii_strncasecmp(v, "enable", 6))
		return 1;
	return 0;
}

int cp_get_group_kv_config_opt(char *v)
{
	if (!g_ascii_strncasecmp(v, "disabled", 8))
		return CIFSD_CONFIG_OPT_DISABLED;
	if (!g_ascii_strncasecmp(v, "enabled", 7))
		return CIFSD_CONFIG_OPT_ENABLED;
	if (!g_ascii_strncasecmp(v, "auto", 4))
		return CIFSD_CONFIG_OPT_AUTO;
	if (!g_ascii_strncasecmp(v, "mandatory", 9))
		return CIFSD_CONFIG_OPT_MANDATORY;
	return CIFSD_CONFIG_OPT_DISABLED;
}

long cp_get_group_kv_long_base(char *v, int base)
{
	return strtol(v, NULL, base);
}

long cp_get_group_kv_long(char *v)
{
	return cp_get_group_kv_long_base(v, 10);
}

char **cp_get_group_kv_list(char *v)
{
	/*
	 * SMB conf lists are "tabs, spaces, commas" separated.
	 */
	return g_strsplit_set(v, "\t ,", -1);
}

void cp_group_kv_list_free(char **list)
{
	g_strfreev(list);
}

static int cp_add_global_guest_account(gpointer _v)
{
	struct cifsd_user *user;

	if (usm_add_new_user(cp_get_group_kv_string(_v),
			     strdup("NULL"))) {
		pr_err("Unable to add guest account\n");
		return -ENOMEM;
	}

	user = usm_lookup_user(_v);
	if (!user) {
		pr_err("Fatal error: unable to find `%s' account.\n",
			_v);
		return -EINVAL;
	}

	set_user_flag(user, CIFSD_USER_FLAG_GUEST_ACCOUNT);
	put_cifsd_user(user);
	global_conf.guest_account = cp_get_group_kv_string(_v);
	return 0;
}

static void global_group_kv(gpointer _k, gpointer _v, gpointer user_data)
{
	if (!cp_key_cmp(_k, "server string")) {
		global_conf.server_string = cp_get_group_kv_string(_v);
		return;
	}

	if (!cp_key_cmp(_k, "workgroup")) {
		global_conf.work_group = cp_get_group_kv_string(_v);
		return;
	}

	if (!cp_key_cmp(_k, "netbios name")) {
		global_conf.netbios_name = cp_get_group_kv_string(_v);
		return;
	}

	if (!cp_key_cmp(_k, "server min protocol")) {
		global_conf.server_min_protocol = cp_get_group_kv_string(_v);
		return;
	}

	if (!cp_key_cmp(_k, "server signing")) {
		global_conf.server_signing = cp_get_group_kv_config_opt(_v);
		return;
	}

	if (!cp_key_cmp(_k, "server max protocol")) {
		global_conf.server_max_protocol = cp_get_group_kv_string(_v);
		return;
	}

	if (!cp_key_cmp(_k, "guest account")) {
		cp_add_global_guest_account(_v);
		return;
	}

	if (!cp_key_cmp(_k, "max active sessions")) {
		global_conf.sessions_cap = cp_get_group_kv_long(_v);
		return;
	}

	if (!cp_key_cmp(_k, "tcp port")) {
		if (!global_conf.tcp_port)
			global_conf.tcp_port = cp_get_group_kv_long(_v);
		return;
	}

	if (!cp_key_cmp(_k, "ipc timeout")) {
		global_conf.ipc_timeout = cp_get_group_kv_long(_v);
		return;
	}

	if (!cp_key_cmp(_k, "restrict anonymous")) {
		global_conf.restrict_anon = cp_get_group_kv_long(_v);
		if (global_conf.restrict_anon > CIFSD_RESTRICT_ANON_TYPE_2 ||
				global_conf.restrict_anon < 0) {
			global_conf.restrict_anon = 0;
			pr_err("Invalid restrict anonymous value\n");
		}

		return;
	}

	if (!cp_key_cmp(_k, "map to guest")) {
		global_conf.map_to_guest = CIFSD_CONF_MAP_TO_GUEST_NEVER;
		if (!cp_key_cmp(_v, "bad user"))
			global_conf.map_to_guest =
				CIFSD_CONF_MAP_TO_GUEST_BAD_USER;
		if (!cp_key_cmp(_v, "bad password"))
			global_conf.map_to_guest =
				CIFSD_CONF_MAP_TO_GUEST_BAD_PASSWORD;
		if (!cp_key_cmp(_v, "bad uid"))
			global_conf.map_to_guest =
				CIFSD_CONF_MAP_TO_GUEST_BAD_UID;
		return;
	}
}

static void global_group(struct smbconf_group *group)
{
	int ret;

	g_hash_table_foreach(group->kv, global_group_kv, NULL);

	/*
	 * Set default global parameters which were not specified
	 * in smb.conf
	 */
	if (!global_conf.server_string)
		global_conf.server_string =
			cp_get_group_kv_string(CIFSD_CONF_DEFAULT_SERVER_STRING);
	if (!global_conf.netbios_name)
		global_conf.netbios_name =
			cp_get_group_kv_string(CIFSD_CONF_DEFAULT_NETBIOS_NAME);
	if (!global_conf.work_group)
		global_conf.work_group =
			cp_get_group_kv_string(CIFSD_CONF_DEFAULT_WORK_GROUP);
	if (!global_conf.tcp_port)
		global_conf.tcp_port = CIFSD_CONF_DEFAULT_TPC_PORT;

	if (global_conf.sessions_cap <= 0)
		global_conf.sessions_cap = CIFSD_CONF_DEFAULT_SESS_CAP;

	if (global_conf.guest_account)
		return;

	ret = cp_add_global_guest_account(CIFSD_CONF_DEFAULT_GUEST_ACCOUNT);
	if (!ret)
		return;
	ret = cp_add_global_guest_account(CIFSD_CONF_FALLBACK_GUEST_ACCOUNT);
	if (ret)
		pr_err("Fatal error: Cannot set a global guest account %d\n",
			ret);
}

static void groups_callback(gpointer _k, gpointer _v, gpointer user_data)
{
	if (g_ascii_strncasecmp(_k, "global", 6))
		shm_add_new_share((struct smbconf_group *)_v);
	else
		global_group((struct smbconf_group *)_v);
}

static int cp_add_ipc_share(void)
{
	struct cifsd_share *share;
	char *comment = NULL;
	int ret = 0;

	ret = init_smbconf_parser();
	if (ret)
		return ret;

	share = shm_lookup_share("IPC$");
	if (share) {
		put_cifsd_share(share);
		goto out;
	}

	comment = strdup("comment = IPC share");
	ret = add_new_group("[IPC$]");
	ret |= add_group_key_value(comment);
	if (ret) {
		pr_err("Unable to add IPC$ share\n");
		goto out;
	}

	g_hash_table_foreach(parser.groups, groups_callback, NULL);
out:
	free(comment);
	release_smbconf_parser();
	return ret;
}

int cp_parse_smbconf(const char *smbconf)
{
	int ret = init_smbconf_parser();
	if (ret)
		return ret;

	ret = __mmap_parse_file(smbconf, process_smbconf_entry);
	if (!ret)
		g_hash_table_foreach(parser.groups, groups_callback, NULL);
	release_smbconf_parser();

	return cp_add_ipc_share();
}

int cp_parse_pwddb(const char *pwddb)
{
	return __mmap_parse_file(pwddb, usm_add_update_user_from_pwdentry);
}
