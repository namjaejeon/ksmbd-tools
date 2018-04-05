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

#ifndef __CIFSD_CONFIG_H__
#define __CIFSD_CONFIG_H__

#include <glib.h>

struct smbconf_group {
	char			*name;
	GHashTable		*kv;
};

struct smbconf_parser {
	GHashTable		*groups;
	struct smbconf_group	*current;
};

#define CIFSD_CONF_MAP_TO_GUEST_NEVER		(0)
#define CIFSD_CONF_MAP_TO_GUEST_BAD_USER	(1 << 0)
#define CIFSD_CONF_MAP_TO_GUEST_BAD_PASSWORD	(1 << 1)
#define CIFSD_CONF_MAP_TO_GUEST_BAD_UID		(1 << 2)

struct smbconf_global {
	int			map_to_guest;
	char			*guest_account;

	char			*server_string;
	char			*workgroup;
	char			*netbios_name;
	char			*server_signing;
	char			*server_min_protocol;
	char			*server_max_protocol;
};

static struct smbconf_global global_conf;

int cp_parse_pwddb(const char *pwddb);
int cp_parse_smbconf(const char *smbconf);

int cp_key_cmp(char *k, char *v);
char *cp_get_group_kv_string(char *v);
int cp_get_group_kv_bool(char *v);
long cp_get_group_kv_long_base(char *v, int base);
long cp_get_group_kv_long(char *v);
char **cp_get_group_kv_list(char *v);
void cp_group_kv_list_free(char **list);

#endif /* __CIFSD_CONFIG_H__ */
