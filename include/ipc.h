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

#ifndef __CIFSD_IPC_H__
#define __CIFSD_IPC_H__

#define CIFSD_IPC_DESTINATION_KERNEL	0

struct ipc_msg {
	int		type;
	int		destination;

	int		sz;
	unsigned char	____payload[0];
};

#define IPC_MSG_PAYLOAD(m)	\
	((void *)(m) + offsetof(struct ipc_msg, ____payload))

struct ipc_msg *ipc_msg_alloc(size_t sz);
void ipc_msg_free(struct ipc_msg *msg);

int ipc_msg_send(struct ipc_msg *msg);

int ipc_receive_loop(void);
void ipc_final_release(void);
int ipc_init(void);

#endif /* __CIFSD_IPC_H__ */
