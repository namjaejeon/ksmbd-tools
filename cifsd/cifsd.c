/*
 *   cifsd-tools/cifsd/cifsd.c
 *
 *   Copyright (C) 2015 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
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

#include "cifsd.h"
#include "netlink.h"
#include <pwd.h>

struct list_head cifsd_share_list;
int cifsd_num_shares;

char workgroup[MAX_SERVER_WRKGRP_LEN];
char server_string[MAX_SERVER_NAME_LEN];

void usage(void)
{
	fprintf(stderr,
		"Usage: cifsd [-h|--help] [-v|--version] [-d |--debug]\n"
		"       [-c smb.conf|--configure=smb.conf] [-i usrs-db|--import-users=cifspwd.db\n");
	exit(0);
}

/**
 * config_users() - function to configure cifsd with user accounts from
 *		local database file. cifsd should be live in kernel
 *		else this function fails and displays user message
 *		"cifsd is not available"
 *
 * Return:	success: CIFS_SUCCESS; fail: CIFS_FAIL
 */
int config_users(char *db_path)
{
	int eof = 0, usr_fd, db_fd;
	char *entry, *user_account, *dummy, *user_entry = NULL;

	db_fd = open(db_path, O_RDONLY);
	if (db_fd < 0) {
		cifsd_err("[%s] open failed(errno : %d)\n", db_path, errno);
		return CIFS_FAIL;
	}

	usr_fd = open(PATH_CIFSD_USR, O_WRONLY);
	if (usr_fd < 0) {
		cifsd_err("[%s] open failed(errno : %d)\n", PATH_CIFSD_USR,
				errno);
		return CIFS_FAIL;
	}

	while (!eof) {
		int ent_len;

		ent_len = get_entry(db_fd, &entry, &eof);
		if (ent_len < 0) {
			cifsd_err("get_entry failed : %d\n", ent_len);
			goto out2;
		}

		init_2_strings(entry, &user_account, &dummy, ent_len);
		if (user_account) {
			struct passwd *passwd = NULL;
			char *id_buf = NULL;
			int alloc_size;
#define UID_BUF_SIZE 14

			alloc_size = ent_len + UID_BUF_SIZE;

			user_entry = (char *)calloc(1, alloc_size);
			if (!user_entry) {
				cifsd_err("entry allocation failed\n");
				goto out;
			}

			memcpy(user_entry, entry, ent_len);
			passwd = getpwnam(user_account);
			if (passwd) {
				int id_len;

				id_buf = (char *)malloc(UID_BUF_SIZE);
				if (!id_buf)
					goto out;

				if (passwd->pw_uid > 65535 ||
						passwd->pw_gid > 65535) {
					cifsd_err("over limit uid : %d, gid : %d\n",
						passwd->pw_uid, passwd->pw_gid);
					goto out;
				}

				id_len = sprintf(id_buf, ":%u:%u\n",
						passwd->pw_uid, passwd->pw_gid);
				memcpy(user_entry + ent_len, id_buf,
						id_len);
				ent_len += id_len;
				free(id_buf);
			}

			if (write(usr_fd, user_entry, ent_len) != ent_len) {
				cifsd_err("cifsd is not available : %d\n",
					errno);
				goto out;
			}
			free(user_account);
			free(dummy);
			free(user_entry);
		}
		free(entry);
	}

	close(usr_fd);
	close(db_fd);
	return CIFS_SUCCESS;

out:
	free(entry);
	free(user_account);
	free(dummy);
	free(user_entry);
out2:
	close(usr_fd);
	close(db_fd);

	return CIFS_FAIL;
}

/**
 * alloc_new_share() - allocate new share
 *
 * Return:	success: allocated share; fail: NULL
 */
static struct cifsd_share *alloc_new_share(void)
{
	struct cifsd_share *share = NULL;
	share = (struct cifsd_share *) calloc(1,
			sizeof(struct cifsd_share));
	if (!share)
		return NULL;

	share->sharename = (char *) calloc(1, SHARE_MAX_NAME_LEN);
	if (!share->sharename) {
		free(share);
		return NULL;
	}

	share->config.comment = (char *) calloc(1, SHARE_MAX_COMMENT_LEN);
	if (!share->config.comment) {
		free(share);
		free(share->sharename);
		return NULL;
	}

	INIT_LIST_HEAD(&share->list);
	return share;
}

/**
 * add_new_share() - add newly allocated share in global share list
 * @sharename:	share name string
 * @comment:	comment decribing share
 */
static void add_new_share(char *sharename, char *comment)
{
	struct cifsd_share *share;

	share = (struct cifsd_share *)alloc_new_share();
	if (!share)
		return;

	if (sharename)
		memcpy(share->sharename, sharename, strlen(sharename));

	if (share->config.comment)
		memcpy(share->config.comment, comment, strlen(comment));

	list_add(&share->list, &cifsd_share_list);
	cifsd_num_shares++;
}

/**
 * exit_share_config() - destroy share list
 */
static void exit_share_config(void)
{
	struct cifsd_share *share;
	struct list_head *tmp, *t;

	list_for_each_safe(tmp, t, &cifsd_share_list) {
		share = list_entry(tmp, struct cifsd_share, list);
		list_del(&share->list);
		cifsd_num_shares--;
		free(share->config.comment);
		free(share->sharename);
		free(share);
	}
}

/**
 * init_share_config() - initialize global share list head and
 *			add IPC$ share
 */
static void init_share_config(void)
{
	INIT_LIST_HEAD(&cifsd_share_list);
	add_new_share(STR_IPC, "IPC$ share");
	strncpy(workgroup, STR_WRKGRP, strlen(STR_WRKGRP));
	strncpy(server_string, STR_SRV_NAME, strlen(STR_SRV_NAME));
}

/**
 * parse_global_config() - parse global share config
 *
 * @src:	source string to be scanned
 */
static void parse_global_config(char *src)
{
	char *tmp;
	char *dup;
	char *conf;
	char *val;
	char *sstring = NULL;
	char *workgrp = NULL;

	if (!src)
		return;

	tmp = dup = strdup(src);
	conf = strtok(dup, "<");
	if (!conf)
		goto out;

	do {
		if (!strncasecmp("server string =", conf, 15)) {
			val = strchr(conf, '=');
			if (val)
				sstring = val + 2;
		}
		else if (!strncasecmp("workgroup =", conf, 11)) {
			val = strchr(conf, '=');
			if (val)
				workgrp = val + 2;
		}
	}while((conf = strtok(NULL, "<")));

	if (sstring)
		strncpy(server_string, sstring, MAX_SERVER_NAME_LEN - 1);

	if (workgrp)
		strncpy(workgroup, workgrp, MAX_SERVER_WRKGRP_LEN - 1);

out:
	free(tmp);
}

/**
 * parse_share_config() - parse share config entry for sharename and
 *			comment for dcerpc
 *
 * @src:	source string to be scanned
 */
static void parse_share_config(char *src)
{
	char *tmp;
	char *dup;
	char *conf;
	char *val;
	char *sharename = NULL;
	char *comment = NULL;

	if (!src)
		return;

	cifsd_debug("%s\n\n", src);

	if (strcasestr(src, "sharename = global")) {
		parse_global_config(src);
		return;
	}

	tmp = dup = strdup(src);
	conf = strtok(dup, "<");
	if (!conf)
		goto out;

	do {
		if (!strncasecmp("sharename =", conf, 11)) {
			val = strchr(conf, '=');
			if (val)
				sharename = val + 2;
		}
		else if (!strncasecmp("comment =", conf, 9)) {
			val = strchr(conf, '=');
			if (val)
				comment = val + 2;
		}
	}while((conf = strtok(NULL, "<")));

	if (sharename)
		add_new_share(sharename, comment);

out:
	free(tmp);
}

/**
 * prefix_share_name() - add prefix to share name for simple parsing
 * @src:	source string to be scanned
 * @srclen:	lenth of share name
 */
void prefix_share_name(char *src, int *srclen)
{
	char *share_cfg = "sharename = ";
	char share_name[PAGE_SZ];
	int i, j;

	/* remove [ and ] from share name */
	for (i = 0, j = 0; i < *srclen; i++) {
		if (!(src[i] == '[' || src[i] == ']'))
			share_name[j++] = src[i];
	}
	share_name[j] = '\0';

	strncpy(src, share_cfg,  strlen(share_cfg));
	strncat(src, share_name, strlen(share_name));
	*srclen = strlen(src);
}

/**
 * validate_share_path() - check if share path exist or not
 * @path:	share path name string
 * @sname:	share name string
 *
 * Return:	0 on success ortherwise error
 */
int validate_share_path(char *path, char *sname)
{
	struct stat st;

	if (stat(path, &st) == -1) {
		fprintf(stderr, "Failed to add SMB %s \t", sname);
		fprintf(stderr, "%s: %s\n", path, strerror(errno));
		return -errno;
	}

	return 0;
}

/**
 * get_share_path() - get share path for a share
 *
 * @dst:	destination buffer for share path
 * @src:	source string to be scanned
 * @sharename:	share name string
 * Return:	lenth of share path on success otherwise zero or error
 */
int get_share_path(char *dst, char *src, char *sharename)
{
	char *pname;
	char *tmp, *dup;
	int len;
	int ret;

	if (!src || !dst)
		return 0;

	/* global config does not have share path */
	if (strcasestr(sharename, "sharename = global"))
		return 0;

	tmp = dup = strdup(src);
	if (strcasestr(dup, "path = "))
	{
		pname = strtok(dup, "= ");
		pname = strtok(NULL, "= ");
		if (pname)
		{
			len = strlen(pname);
			strncpy(dst, pname, len);
			dst[len] = '\0';
			free(tmp);
			ret = validate_share_path(dst, sharename);
			if (ret < 0)
				return ret;
			else
				return len;
		}
	}

	free(tmp);
	return 0;
}

/**
 * getfchar() - helper function to locate valid starting character
 *              and copies characters till i/p LINE length.
 *              Here valid data means:
 *              i) not commented line (starting with ';' or '#')
 *              ii) ascii values between- a-z || A-Z || 0-9
 * @sz: current LINE length
 * @c:          first valid character
 * @dst:        initialize destination string with LINE data starting from 'c'
 * @ssz:        total length of copied destination data
 */
void getfchar(char *LINE, int sz, char *c, char *dst, int *ssz)
{
	int cnt = 0;
	int i = 0;
	int len = 0;

	while ((cnt < sz) && ((LINE[cnt] != ';') &&
	       (LINE[cnt] != '#') && (LINE[cnt] != '[') &&
	       !(LINE[cnt] >= 'A' && LINE[cnt] <= 'Z') &&
	       !(LINE[cnt] >= 'a' && LINE[cnt] <= 'z') &&
	       !(LINE[cnt] >= '0' && LINE[cnt] <= '9')))
		cnt++;

	cnt == sz ? (*c = ' ') : (*c = LINE[cnt]);

	if ((LINE[cnt] != ';') && (LINE[cnt] != '#')) {
		while ((cnt < sz) && (LINE[cnt] != ';') &&
			(LINE[cnt] != '#')) {
			dst[i++] = LINE[cnt++];
			len++;
		}
	}

	*ssz = len;
}

/**
 * config_shares() - function to initialize cifsd with share settings.
 *		     This function parses local configuration file and
 *		     initializes cifsd with [share] settings
 *
 * Return:	success: CIFS_SUCCESS; fail: CIFS_FAIL
 */
int config_shares(char *conf_path)
{
	char lshare[PAGE_SZ] = "", sharepath[PAGE_SZ] = "", tbuf[PAGE_SZ];
	int sharepath_len = 0, cnt = 0, lssz = 0, limit = 0, eof = 0, sz;
	int fd_conf;
	FILE *fd_share;

	fd_share = fopen(conf_path, "r");
	if (fd_share == NULL) {
		cifsd_err("[%s] is not existing, err %d\n", conf_path, errno);
		return CIFS_FAIL;
	}

	fd_conf = open(PATH_CIFSD_CONFIG, O_WRONLY);
	if (fd_conf < 0) {
		cifsd_err("[%s] open failed, err %d\n", PATH_CIFSD_CONFIG,
			errno);
		fclose(fd_share);
		return CIFS_FAIL;
	}

	memset(tbuf, 0, PAGE_SZ);

	while (!eof) {
		char ch;
		char stro[PAGE_SZ] = "";
		char str[PAGE_SZ] = "";
		char cont_str[PAGE_SZ] = "";
		int contsz = 0, ssz = 0;
		char *line;

		cnt = readline(fd_share, &line, &eof, 1);
		if (cnt < 0)
			goto out;
		else if (!cnt) {
			free(line);
			continue;
		}

		if (line[cnt - 1] == '\\') {
			do {
				strncat(cont_str, line, cnt - 1);
				free(line);
				cnt = readline(fd_share, &line, &eof, 1);
			} while ((cnt > 0) && (line[cnt - 1] == '\\'));

			if (cnt > 0)
				strncat(cont_str, line, cnt);
			free(line);

			contsz = strlen(cont_str);
			line = (char *)malloc(contsz + 1);
			memset(line, 0, contsz + 1);
			strncpy(line, cont_str, contsz);
			cnt = contsz;
		}

		getfchar(line, cnt, &ch, stro, &ssz);
		free(line);
		tlws(stro, str, &ssz);

		if ((ch == '[') || (ch >= 'A' && ch <= 'Z') ||
		    (ch >= 'a' && ch <= 'z')) {
			/* writeout previous export entry */
			if (ch == '[' && limit > 0) {
				if (sharepath_len >= 0) {
					tbuf[limit] = '\0';
					limit += 1;
					lseek(fd_conf, 0, SEEK_SET);
					sz = write(fd_conf, tbuf,
							limit);
					if (sz != limit)
						perror("config error");
					else
						parse_share_config(tbuf);
				}

				memset(tbuf, 0, PAGE_SZ);
				limit = 0;
				sharepath_len = 0;
			}

			if (ch == '[') {
				prefix_share_name(str, &ssz);
				memset(lshare, 0, PAGE_SZ);
				strncpy(lshare, str, ssz);
				lssz = ssz;
			}

			if (!sharepath_len)
				sharepath_len =
					get_share_path(sharepath, str, lshare);
again:
			if ((limit + ssz + 1) < PAGE_SZ) {
				strncat(tbuf+limit, "<", 1);
				strncat(tbuf+limit + 1, str, ssz);
				limit += ssz + 1;
			} else {
				if (sharepath_len >= 0) {
					tbuf[limit] = '\0';
					limit += 1;
					lseek(fd_conf, 0, SEEK_SET);
					sz = write(fd_conf, tbuf,
							limit);
					if (sz != limit)
						perror("config error");
				}

				memset(tbuf, 0, PAGE_SZ);

				if (ch != '[') {
					strncat(tbuf, "<", 1);
					strncat(tbuf + 1, lshare, lssz);
					limit = lssz + 1;
				} else {
					sharepath_len = 0;
					limit = 0;
				}

				goto again;
			}
		}
	}

out:
	if (sharepath_len >= 0 && limit > 0) {
		tbuf[limit] = '\0';
		limit += 1;

		lseek(fd_conf, 0, SEEK_SET);
		sz = write(fd_conf, tbuf, limit);
		if (sz != limit) {
			/* retry once again */
			sleep(1);
			lseek(fd_conf, 0, SEEK_SET);
			sz = write(fd_conf, tbuf, limit);
			if (sz != limit) {
				perror("write error");
				cifsd_err(": <write=%d> <req=%d>\n", sz, limit);
			}
		}
		else
			parse_share_config(tbuf);

		sharepath_len = 0;
	}

	fclose(fd_share);
	close(fd_conf);

	return CIFS_SUCCESS;
}

int main(int argc, char**argv)
{
	char *cifspwd = PATH_PWDDB;
	char *cifsconf = PATH_SHARECONF;
	int c;
	int ret;

	/* Parse the command line options and arguments. */
	opterr = 0;
	while ((c = getopt(argc, argv, "c:i:vh")) != EOF)
		switch (c) {
		case 'c':
			cifsconf = strdup(optarg);
			break;
		case 'i':
			cifspwd = strdup(optarg);
			break;
		case 'v':
			if (argc <= 2) {
				printf("[option] needed with verbose\n");
				usage();
			}
			vflags |= F_VERBOSE;
			break;
		case '?':
		case 'h':
		default:
			usage();
	}

	init_share_config();

	/* import user account */
	ret = config_users(cifspwd);
	if (ret != CIFS_SUCCESS)
		goto out;

	/* import shares info */
	ret = config_shares(cifsconf);
	if (ret != CIFS_SUCCESS)
		goto out;

	//cifsd_debug("cifsd version : %d\n", cifsd_version);

	/* netlink communication loop */
	cifsd_netlink_setup();

	exit_share_config();

out:
	cifsd_debug("cifsd terminated\n");
	
	exit(1);
}
