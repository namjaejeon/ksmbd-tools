// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>

#include <config_parser.h>
#include <cifsdtools.h>

#include <management/user.h>
#include <management/share.h>

#include <md4_hash.h>

static char *account = NULL;
static int conf_fd = -1;

#define MAX_NT_PWD_LEN 129

enum {
	COMMAND_ADD_USER = 1,
	COMMAND_DEL_USER,
	COMMAND_UPDATE_USER,
};

static void usage(void)
{
	fprintf(stderr, "cifsd-tools version : %s, date : %s\n",
			CIFSD_TOOLS_VERSION,
			CIFSD_TOOLS_DATE);
	fprintf(stderr, "Usage: cifsd_admin\n");

	fprintf(stderr, "\t-a | --add-user=login\n");
	fprintf(stderr, "\t-d | --del-user=login\n");
	fprintf(stderr, "\t-u | --update-user=login\n");

	fprintf(stderr, "\t-c smb.conf | --config=smb.conf\n");
	fprintf(stderr, "\t-i cifspwd.db | --import-users=cifspwd.db\n");
	fprintf(stderr, "\t-v | --verbose\n");

	exit(EXIT_FAILURE);
}

static int test_access(char *conf)
{
	int fd = open(conf, O_RDWR | O_CREAT, S_IRWXU | S_IRGRP);

	if (fd != -1) {
		close(fd);
		return 0;
	}

	pr_err("%s %s\n", conf, strerror(errno));
	return -EINVAL;
}

static int parse_configs(char *pwddb, char *smbconf)
{
	int ret;

	ret = test_access(pwddb);
	if (ret)
		return ret;

	ret = cp_parse_pwddb(pwddb);
	if (ret)
		return ret;

	ret = test_access(smbconf);
	if (ret)
		return ret;

	ret = cp_parse_smbconf(smbconf);
	if (ret)
		return ret;
	return 0;
}

static void term_toggle_echo(int on_off)
{
	struct termios term;

	tcgetattr(STDIN_FILENO, &term);

	if (on_off)
		term.c_lflag |= ECHO;
	else
		term.c_lflag &= ~ECHO;

	tcsetattr(STDIN_FILENO, TCSAFLUSH, &term);
}

static char *prompt_password(size_t *sz)
{
	char *pswd1 = malloc(MAX_NT_PWD_LEN + 1);
	char *pswd2 = malloc(MAX_NT_PWD_LEN + 1);
	size_t len = 0;
	int i;

	if (!pswd1 || !pswd2) {
		free(pswd1);
		free(pswd2);
		pr_err("Out of memory\n");
		return NULL;
	}

again:
	memset(pswd1, 0x00, MAX_NT_PWD_LEN + 1);
	memset(pswd2, 0x00, MAX_NT_PWD_LEN + 1);

	printf("New password:\n");
	term_toggle_echo(0);
	if (fgets(pswd1, MAX_NT_PWD_LEN, stdin) == NULL) {
		term_toggle_echo(1);
		pr_err("Fatal error: %s\n", strerror(errno));
		return NULL;
	}

	printf("Retype new password:\n");
	if (fgets(pswd2, MAX_NT_PWD_LEN, stdin) == NULL) {
		term_toggle_echo(1);
		pr_err("Fatal error: %s\n", strerror(errno));
		return NULL;
	}
	term_toggle_echo(1);

	len = strlen(pswd1);
	for (i = 0; i < len; i++)
		if (pswd1[i] == '\n')
			pswd1[i] = 0x00;

	len = strlen(pswd2);
	for (i = 0; i < len; i++)
		if (pswd2[i] == '\n')
			pswd2[i] = 0x00;

	if (memcmp(pswd1, pswd2, MAX_NT_PWD_LEN + 1)) {
		pr_err("Passwords don't match\n");
		goto again;
	}

	len = strlen(pswd1);
	if (len <= 1) {
		pr_err("No password was provided\n");
		goto again;
	}

	*sz = len;
	free(pswd2);
	return pswd1;
}

static char *get_utf8_password(long *len)
{
	size_t raw_sz;
	char *pswd_raw, *pswd_converted;
	gsize bytes_read = 0;
	gsize bytes_written = 0;
	GError *err = NULL;

	pswd_raw = prompt_password(&raw_sz);
	if (!pswd_raw)
		return NULL;

	pswd_converted = g_convert(pswd_raw,
				   raw_sz,
				   CIFSD_CHARSET_UTF16LE,
				   CIFSD_CHARSET_DEFAULT,
				   &bytes_read,
				   &bytes_written,
				   &err);
	if (err) {
		pr_err("Can't convert string: %s\n", err->message);
		free(pswd_raw);
		g_error_free(err);
		return NULL;
	}

	*len = bytes_written;
	free(pswd_raw);
	return pswd_converted;
}

static void __sanity_check(char *pswd_hash, char *pswd_b64)
{
	size_t pass_sz;
	char *pass = base64_decode(pswd_b64, &pass_sz);

	if (!pass) {
		pr_err("Unable to decode NT hash\n");
		exit(1);
	}

	if (memcmp(pass, pswd_hash, pass_sz)) {
		pr_err("NT hash encoding error\n");
		exit(1);
	}
	free(pass);
}

static char *get_hashed_b64_password(void)
{
	struct md4_ctx mctx;
	long len;
	char *pswd_plain, *pswd_hash, *pswd_b64;

	pswd_plain = get_utf8_password(&len);
	if (!pswd_plain)
		return NULL;

	pswd_hash = malloc(sizeof(mctx.hash) + 1);
	if (!pswd_hash) {
		free(pswd_plain);
		pr_err("Out of memory\n");
		return NULL;
	}

	memset(pswd_hash, 0x00, sizeof(mctx.hash) + 1);

	md4_init(&mctx);
	md4_update(&mctx, pswd_plain, len);
	md4_final(&mctx, pswd_hash);

	pswd_b64 = base64_encode(pswd_hash,
				 MD4_HASH_WORDS * sizeof(unsigned int));

	__sanity_check(pswd_hash, pswd_b64);
	free(pswd_plain);
	free(pswd_hash);
	return pswd_b64;
}

static void write_user(struct cifsd_user *user)
{
	size_t sz = strlen(user->name) + strlen(user->pass_b64) + 4;
	char *data;
	int ret, nr = 0;
	size_t wsz;

	data = malloc(sz);
	if (!data) {
		pr_err("Out of memory allocating %d bytes for user %s\n",
				sz, user->name);
		exit(1);
	}

	memset(data, 0x00, sz);
	wsz = snprintf(data, sz, "%s:%s\n", user->name, user->pass_b64);

	while (wsz && (ret = write(conf_fd, data + nr, wsz)) != 0) {
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			pr_err("%s\n", strerror(errno));
			exit(1);
		}

		nr += ret;
		wsz -= ret;
	}

	free(data);
}

static void write_user_cb(gpointer key, gpointer value, gpointer user_data)
{
	struct cifsd_user *user = (struct cifsd_user *)value;
	write_user(user);
}

static void write_remove_user_cb(gpointer key,
				 gpointer value,
				 gpointer user_data)
{
	struct cifsd_user *user = (struct cifsd_user *)value;

	if (!g_ascii_strncasecmp(user->name, account, strlen(account)))
		return;

	write_user_cb(key, value, user_data);
}

static int command_add_user(char *pwddb)
{
	struct cifsd_user *user = usm_lookup_user(account);
	char *pswd;

	if (user) {
		put_cifsd_user(user);
		pr_err("Account `%s' already exists\n", account);
		return -EEXIST;
	}

	pswd = get_hashed_b64_password();
	if (!pswd) {
		pr_err("Out of memory\n");
		return -EINVAL;
	}

	/* pswd is already strdup-ed */
	if (usm_add_new_user(account, pswd)) {
		pr_err("Could not add new account\n");
		return -EINVAL;
	}

	conf_fd = open(pwddb, O_WRONLY);
	if (conf_fd == -1) {
		pr_err("%s %s\n", strerror(errno), pwddb);
		return -EINVAL;
	}

	if (ftruncate(conf_fd, 0)) {
		pr_err("%s %s\n", strerror(errno), pwddb);
		close(conf_fd);
		return -EINVAL;
	}

	for_each_cifsd_user(write_user_cb, NULL);
	close(conf_fd);
	return 0;
}

static void lookup_can_del_user(gpointer key,
				gpointer value,
				gpointer user_data)
{
	struct cifsd_share *share = (struct cifsd_share *)value;
	int ret = 0;
	int *abort_del_user = (int *)user_data;

	if (*abort_del_user)
		return;

	ret = shm_lookup_users_map(share,
				   CIFSD_SHARE_ADMIN_USERS_MAP,
				   account);
	if (ret == 0)
		goto conflict;

	ret = shm_lookup_users_map(share,
				   CIFSD_SHARE_WRITE_LIST_MAP,
				   account);
	if (ret == 0)
		goto conflict;

	ret = shm_lookup_users_map(share,
				   CIFSD_SHARE_VALID_USERS_MAP,
				   account);
	if (ret == 0)
		goto conflict;

	*abort_del_user = 0;
	return;

conflict:
	pr_err("Share %s requires user %s to exist\n", share->name, account);
	*abort_del_user = 1;
}

static int command_del_user(char *pwddb)
{
	int abort_del_user = 0;

	if (!cp_key_cmp(global_conf.guest_account, account)) {
		pr_err("User %s is a global guest account. Abort deletion.\n",
				account);
		return -EINVAL;
	}

	for_each_cifsd_share(lookup_can_del_user, &abort_del_user);

	if (abort_del_user) {
		pr_err("Aborting user deletion\n");
		return -EINVAL;
	}

	conf_fd = open(pwddb, O_WRONLY);

	if (conf_fd == -1) {
		pr_err("%s %s\n", strerror(errno), pwddb);
		return -EINVAL;
	}

	if (ftruncate(conf_fd, 0)) {
		pr_err("%s %s\n", strerror(errno), pwddb);
		close(conf_fd);
		return -EINVAL;
	}

	for_each_cifsd_user(write_remove_user_cb, NULL);
	close(conf_fd);
	return 0;
}

static int command_update_user(char *pwddb)
{
	struct cifsd_user *user = usm_lookup_user(account);
	char *pswd;

	if (!user) {
		pr_err("Unknown account\n");
		return -EINVAL;
	}

	pswd = get_hashed_b64_password();
	if (!pswd) {
		pr_err("Out of memory\n");
		put_cifsd_user(user);
		return -EINVAL;
	}

	if (usm_update_user_password(user, pswd)) {
		pr_err("Out of memory\n");
		put_cifsd_user(user);
		return -ENOMEM;
	}

	put_cifsd_user(user);
	free(pswd);

	conf_fd = open(pwddb, O_WRONLY);
	if (conf_fd == -1) {
		pr_err("%s %s\n", strerror(errno), pwddb);
		return -EINVAL;
	}

	if (ftruncate(conf_fd, 0)) {
		pr_err("%s %s\n", strerror(errno), pwddb);
		close(conf_fd);
		return -EINVAL;
	}

	for_each_cifsd_user(write_user_cb, NULL);
	close(conf_fd);
	return 0;
}

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	char *pwddb = PATH_PWDDB;
	char *smbconf = PATH_SMBCONF;
	int c, cmd = 0;

	set_logger_app_name("cifsd_admin");

	opterr = 0;
	while ((c = getopt(argc, argv, "c:i:a:d:u:vh")) != EOF)
		switch (c) {
		case 'a':
			account = strdup(optarg);
			cmd = COMMAND_ADD_USER;
			break;
		case 'd':
			account = strdup(optarg);
			cmd = COMMAND_DEL_USER;
			break;
		case 'u':
			account = strdup(optarg);
			cmd = COMMAND_UPDATE_USER;
			break;
		case 'c':
			smbconf = strdup(optarg);
			break;
		case 'i':
			pwddb = strdup(optarg);
			break;
		case 'v':
			break;
		case '?':
		case 'h':
		default:
			usage();
	}

	if (!smbconf || !pwddb) {
		pr_err("Out of memory\n");
		goto out;
	}

	ret = usm_init();
	if (ret) {
		pr_err("Failed to init user management\n");
		goto out;
	}

	ret = shm_init();
	if (ret) {
		pr_err("Failed to init net share management\n");
		goto out;
	}

	ret = parse_configs(pwddb, smbconf);
	if (ret) {
		pr_err("Unable to parse configuration files\n");
		goto out;
	}

	if (cmd == COMMAND_ADD_USER)
		ret = command_add_user(pwddb);
	if (cmd == COMMAND_DEL_USER)
		ret = command_del_user(pwddb);
	if (cmd == COMMAND_UPDATE_USER)
		ret = command_update_user(pwddb);
out:
	shm_destroy();
	usm_destroy();
	return ret;
}
