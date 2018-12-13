// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#ifndef __CIFSD_USER_ADMIN_H__
#define __CIFSD_USER_ADMIN_H__

int command_add_user(char *pwddb, char *account, char *password);
int command_update_user(char *pwddb, char *account, char *password);
int command_del_user(char *pwddb, char *account);

#endif /* __CIFSD_USER_ADMIN_H__ */
