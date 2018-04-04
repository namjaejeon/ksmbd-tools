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

#ifndef __MANAGEMENT_SHARE_H__
#define __MANAGEMENT_SHARE_H__

#include <glib.h>

#define CIFSD_SHARE_AVAILABLE	(1 << 0)
#define CIFSD_SHARE_GUEST_OK	(1 << 1)
#define CIFSD_SHARE_WRITEABLE	(1 << 2)
#define CIFSD_SHARE_READONLY	(1 << 3)
#define CIFSD_SHARE_BROWSEABLE	(1 << 4)
#define CIFSD_SHARE_GUEST_ONLY	(1 << 5)

#define CIFSD_SHARE_INVALID	(1 << 31)

enum share_users {
	/* Admin users */
	CIFSD_SHARE_ADMIN_USERS_MAP = 0,
	/* Valid users */
	CIFSD_SHARE_VALID_USERS_MAP,
	/* Invalid users */
	CIFSD_SHARE_INVALID_USERS_MAP,
	/* Read-only users */
	CIFSD_SHARE_READ_LIST_MAP,
	/* Read/Write access to a read-only share */
	CIFSD_SHARE_WRITE_LIST_MAP,
	CIFSD_SHARE_USERS_MAX,
};

enum share_hosts {
	CIFSD_SHARE_HOSTS_ALLOW_MAP = 0,
	CIFSD_SHARE_HOSTS_DENY_MAP,
	CIFSD_SHARE_HOSTS_MAX,
};

struct cifsd_share {
	char		*name;
	char		*path;

	int		max_connections;
	int		num_connections;

	GList		*conns;
	GRWLock		conns_lock;

	int		ref_count;

	int		create_mask;
	int		directory_mask;
	int		flags;

	GHashTable	*maps[CIFSD_SHARE_USERS_MAX];
	/*
	 * FIXME
	 * We need to support IP ranges, netmasks, etc.
	 * This is just a silly hostname matching, hence
	 * these two are not in ->maps[].
	 */
	GHashTable	*hosts_allow_map;
	/* Deny access */
	GHashTable	*hosts_deny_map;

	/* One lock to rule them all [as of now] */
	GRWLock		maps_lock;

	char*		comment;
};

static void set_share_flag(struct cifsd_share *share, int flag)
{
	share->flags |= flag;
}

static int get_share_flag(struct cifsd_share *share, int flag)
{
	return share->flags & flag;
}

void put_cifsd_share(struct cifsd_share *share);
struct cifsd_share *shm_lookup_share(char *name);

struct smbconf_group;
int shm_add_new_share(struct smbconf_group *group);

void shm_final_release(void);
int shm_init(void);

int shm_lookup_users_map(struct cifsd_share *share,
			  enum share_users map,
			  char *name);

int shm_lookup_hosts_map(struct cifsd_share *share,
			  enum share_hosts map,
			  char *host);

struct cifsd_tree_conn;
int shm_bind_connection(struct cifsd_share *share,
			struct cifsd_tree_conn *conn);
void shm_unbind_connection(struct cifsd_share *share,
			   struct cifsd_tree_conn *conn);

typedef void (*walk_shares)(struct cifsd_share *share);
void for_each_cifsd_share(walk_shares cb);

#endif /* __MANAGEMENT_SHARE_H__ */
