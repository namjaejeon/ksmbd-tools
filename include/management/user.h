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

#ifndef __MANAGEMENT_USER_H__
#define __MANAGEMENT_USER_H__

#include <sys/types.h>
#include <pwd.h>
#include <glib.h>

#define CIFSD_USER_GUEST_ACCOUNT	(1 << 0)

struct cifsd_user {
	char		*name;
	char		*pass_b64;

	char		*pass;
	size_t		pass_sz;

	uid_t		uid;
	gid_t		gid;

	int		ref_count;
	int 		flags;

	GList		*conns;
	GRWLock		update_lock;
};

static inline void set_user_flag(struct cifsd_user *user, int bit)
{
	user->flags |= bit;
}

static inline int get_user_flag(struct cifsd_user *user, int bit)
{
	return user->flags & bit;
}

static inline size_t get_user_pass_sz(struct cifsd_user *user)
{
	return user->pass_sz;
}

static inline char *get_user_passhash(struct cifsd_user *user)
{
	return user->pass;
}

void put_cifsd_user(struct cifsd_user *user);

struct cifsd_user *usm_lookup_user(char *name);

int usm_add_new_user(char *name, char *pwd);
int usm_new_user_from_pwdentry(char *data);

struct cifsd_tree_conn;
int usm_bind_connection(struct cifsd_user *user,
			struct cifsd_tree_conn *conn);
void usm_unbind_connection(struct cifsd_user *user,
			   struct cifsd_tree_conn *conn);

void usm_final_release(void);
int usm_init(void);

typedef void (*walk_users)(struct cifsd_user *user);
void for_each_cifsd_user(walk_users cb);

int usm_update_user_password(struct cifsd_user *user, char *pass);
#endif /* __MANAGEMENT_USER_H__ */
