/*
 *   cifsd-tools/cifsadmin/cifsadmin.c
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

#include "cifsadmin.h"

/* global variables */
static char *dup_optarg;

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

/**
 * handle_sigint() - registered signal handler for SIGINT
 * @signum:	occured signal number
 * @siginfo:	information associated with signum
 * @message:	additonal text data for signum
 */
static void handle_sigint(int signum, siginfo_t *siginfo, void *message)
{
	if (signum == SIGINT) {
		cifsd_debug("Received [Signo:%d] [SigCode:%d]\n",
			siginfo->si_signo, siginfo->si_code);

		/* code added to suppress warning*/
		if (!(int *)message)
			cifsd_debug("Message field empty\n");

		term_toggle_echo(1);

		cifsd_debug("Terminating program\n");
		exit(0);
	}
}

/**
 * strlen_w() - helper function to calculate unicode string length
 * @src:	source unicode string to find length
 *
 * Return:	length of unicode string
 */
size_t strlen_w(const unsigned short *src)
{
	size_t len;
	unsigned short c;

	for (len = 0; *(COPY_UCS2_CHAR(&c, src)); src++, len++);

	return len;
}

/**
 * convert_nthash() - function to convert password to NTHash
 * @dst:	destination pointer to save NTHash
 * @pwd:	source password string
 *
 * Return:	success: 0; fail: -1
 */
int convert_nthash(unsigned char *dst, char *pwd)
{
	unsigned short uni[MAX_NT_PWD_LEN];
	char *pOut = (char *)uni;
	size_t srclen = MAX_NT_PWD_LEN;
	size_t dstlen = MAX_NT_PWD_LEN;
	iconv_t conv;
	size_t len;
	struct md4_ctx mctx;

	memset(pOut, 0, MAX_NT_PWD_LEN * sizeof(unsigned short));

	conv = iconv_open("UTF16LE", "UTF-8");
	if (conv == (iconv_t)-1) {
		if (errno == EINVAL) {
			conv = iconv_open("UCS-2LE", "UTF-8");
			if (conv == (iconv_t)-1) {
				cifsd_err("failed to open conversion"
					" for UCS-2LE to UTF-8\n");
				perror("iconv_open");
				return -1;
			}
		} else {
			cifsd_err("failed to open conversion for"
					" UTF16LE to UTF-8\n");
			return -1;
		}
	}

	iconv(conv, &pwd, &srclen, &pOut, &dstlen);
	len = strlen_w(uni) * sizeof(unsigned short);
	md4_init(&mctx);
	md4_update(&mctx, (unsigned char *)uni, len);
	md4_final(&mctx, dst);

	iconv_close(conv);
	return 0;
}

/**
 * get_pwd_prompt() - helper function to read user password string from stdin
 * @message:	information to be displayed to user
 *
 * Return:	success: "user provided pwd string"; fail: "NULL"
 */
char *get_pwd_prompt(char *message)
{
	int len;
	char *password;

	password = malloc(MAX_NT_PWD_LEN + 1);
	if (!password)
		return NULL;

	term_toggle_echo(0);

retry:
	fprintf(stdout, "%s", message);
	if (fgets(password, MAX_NT_PWD_LEN, stdin) == NULL) {
		free(password);
		password = NULL;
		goto out;
	}

	len = strlen(password);
	if (len < 0 && len > MAX_NT_PWD_LEN) {
		cifsd_err("Password length(%d) invalid!"
				" allowed length 1 ~ %d\n",
				len, MAX_NT_PWD_LEN - 1);
		goto retry;
	}

	if (password[len - 1] == '\n')
		password[len - 1] = 0;

out:
	term_toggle_echo(1);
	return password;
}

/**
 * get_enc_pwd() - function to read and encrypted user password
 *
 * Return:	pointer for user supplied pwd. otherwise NULL.
 */
unsigned char *get_enc_pwd()
{
	char *new_pwd = NULL;
	char *re_pwd = NULL;
	unsigned char *encrypt = NULL;
	int err = -1;

	new_pwd = get_pwd_prompt("New Password:\n");
	if (!new_pwd) {
		cifsd_err("Error while setting password.\n");
		goto out;
	}

	re_pwd = get_pwd_prompt("Retype Password:\n");
	if (!re_pwd) {
		cifsd_err("Error while setting password.\n");
		goto out;
	}

	if (strcmp(new_pwd, re_pwd)) {
		cifsd_err("Passwords mismatch.\n");
		goto out;
	}

	encrypt = (unsigned char *)malloc(CIFS_NTHASH_SIZE + 1);
	if (!encrypt)
		goto out;
	memset(encrypt, 0, CIFS_NTHASH_SIZE + 1);

	if (convert_nthash(encrypt, new_pwd))
		goto out;

	err = 0;
out:
	if (new_pwd)
		free(new_pwd);
	if (re_pwd)
		free(re_pwd);
	if (err < 0 && encrypt) {
		free(encrypt);
		encrypt = NULL;
	}

	return encrypt;
}

/**
 * getusrpwd() - helper function to extract username and pwd from i/p string
 * @line:	input string containing username and pwd
 * @fusrname:	initialize with username or NULL
 * @pwd1:	initialize with password or NULL
 * @len:	length of input line string
 *
 * Return:	success: 1; fail: 0
 */
int getusrpwd(char *line, char **fusrname, char **pwd1, int len)
{
	char *name = NULL;
	char *pwd = NULL;

	init_2_strings(line, &name, &pwd, len);

	if (name && pwd) {
		*fusrname = name;
		*pwd1 = pwd;
	} else {
		*fusrname = NULL;
		*pwd1 = NULL;
		return 0;
	}

	return 1;
}

/**
 * updatedb() - helper function to replace existing user entry
 *		with new details in database file
 * @nstr:	source string to be updated in database file
 * @nsz:	source length to be updated in database file
 * @lno:	line number to be updated in database file
 *
 * Return:	success: 1; fail: 0
 */
int updatedb(int fd, char *nstr, size_t nsz, int lno)
{
	char *line;
	int eof = 0;
	int cnt = 1;

	if (lseek(fd, 0, SEEK_SET) == -1)
		return 0;

	while (cnt++ < lno) {
		if (get_entry(fd, &line, &eof) != -1)
			free(line);
	}

	if (write(fd, nstr, nsz) != nsz)
		return 0;

	if (write(fd, "\n", 1) != 1)
		return 0;

	return 1;
}

int update_current_user_entry(int fd, char *username, unsigned char *password,
		int line_num, int is_root)
{
	unsigned char *new_pwd;
	int ret = CIFS_SUCCESS;

	if (!is_root) {
		char *old_pwd;
		unsigned char enc_pwd[CIFS_NTHASH_SIZE + 1];

		old_pwd = get_pwd_prompt("Old Password:\n");
		if (!old_pwd) {
			cifsd_err("Error while setting password.\n");
			ret = CIFS_FAIL;
			goto out;
		}

		if (convert_nthash(enc_pwd, old_pwd)) {
			free(old_pwd);
			ret = CIFS_FAIL;
			goto out;
		}

		if (strcmp((const char *)password,
				(const char *)enc_pwd)) {
			cifsd_err(
				"Password authentication failed\n");
			goto out;
		}

		free(old_pwd);
	}

	new_pwd = get_enc_pwd();
	if (new_pwd) {
		char *newline;
		size_t sz;
		int ulen = strlen(username);

		sz = ulen + CIFS_NTHASH_SIZE + 2;

		newline = (char *)malloc(sz);
		if (!newline) {
			free(new_pwd);
			ret = CIFS_FAIL;
			goto out;
		}

		memset(newline, 0, sz);
		memcpy(newline, username, ulen);
		memcpy(newline + ulen, ":", 1);
		memcpy(newline + ulen + 1, new_pwd, CIFS_NTHASH_SIZE);

		updatedb(fd, newline, sz - 1, line_num);

		free(new_pwd);
		free(newline);
	}

out:
	return ret;
}

int add_new_user_entry(int fd, char *username)
{
	unsigned char *newpwd;

	newpwd = get_enc_pwd();
	if (newpwd) {
		size_t sz, val = strlen(username);
		char *construct;

		if (lseek(fd, 0, SEEK_END) == -1) {
			free(newpwd);
			return CIFS_FAIL;
		}

		sz = val + CIFS_NTHASH_SIZE + 3;

		construct = (char *)malloc(sz);
		if (!construct) {
			free(newpwd);
			return CIFS_FAIL;
		}

		memset(construct, 0, sz);
		memcpy(construct, username, val);
		memcpy(construct + val, ":", 1);
		memcpy(construct + val + 1, newpwd, 16);
		memcpy(construct + val + 1 + 16, "\n", 1);

		if (write(fd, construct, sz - 1) != sz - 1) {
			cifsd_err("%d: file operation failed, errno : %d\n",
					__LINE__, errno);
			free(construct);
			return CIFS_FAIL;
		}

		free(construct);
		free(newpwd);
	}

	return CIFS_SUCCESS;
}

/**
 * add_user_account() - function to add/modify user account to local DB file
 * @username:	user entry to be added/modified
 * @flag:	flag indicating caller context as Root/Non-Root
 *		  - Root can add/modify any user account
 *		  - Non-Root can only add/modify it's own account
 *
 * Return:	success: CIFS_SUCCESS; fail: CIFS_FAIL
 */
int add_user_account(int fd, char *username, int flag)
{
	char *fusrname, *line;
	unsigned char *passwd = NULL;
	int iseof = 0, lno = 0, len;
	int ret = CIFS_FAIL;

	if (lseek(fd, 0, SEEK_SET) == -1)
		return CIFS_FAIL;

	do {
		len = get_entry(fd, &line, &iseof);
		if (len == -ENOMEM)
			goto out;

		if (len < 0) {
			free(line);
			continue;
		}

		if (iseof) {
			free(line);
			break;
		}

		lno++;
		if (!getusrpwd(line, &fusrname, (char **)&passwd, len)) {
			free(line);
			goto out;
		}

		if (!strcmp((const char *)fusrname,
					(const char *)username)) {
			ret = update_current_user_entry(fd, username, passwd,
				lno, flag & AM_ROOT);
				goto out;
		}

		free(line);
		free(fusrname);
	} while (!iseof);

	ret = add_new_user_entry(fd, username);
out:

	return ret;
}

/**
 * remove_user_entry() - function to delete user account from local database
 *		file and running cifsd if available
 * @usrname:	user name to be removed
 * @lno:	line number of user entry in local database file
 *
 * Return:	success: 1; fail: 0
 */
int remove_user_entry(int fd, char *usrname, int lno)
{
	long pos1, pos2, pos3;
	char *data;
	size_t rem;
	char *line = NULL;
	char *construct;
	int fd_usr;
	int eof = 0;
	int len;
	int cnt = 1;

	if (lseek(fd, 0, SEEK_SET) == -1) {
		cifsd_debug("%d: file operation failed\n", __LINE__);
		return 0;
	}

	while (cnt++ < lno) {
		if (get_entry(fd, &line, &eof) != -1)
			free(line);
	}

	pos1 = lseek(fd, 0, SEEK_CUR);
	if (pos1 == -1) {
		cifsd_debug("%d: file operation failed\n", __LINE__);
		return 0;
	}

	len = get_entry(fd, &line, &eof);
	if (len >= 0)
		free(line);

	len += 1; /* add '\n' to length */
	pos2 = pos1 + len;
	if (lseek(fd, 0, SEEK_END) == -1) {
		cifsd_debug("%d: file operation failed\n", __LINE__);
		return 0;
	}

	pos3 = lseek(fd, 0, SEEK_CUR);
	if (pos3 == -1) {
		cifsd_debug("%d: file operation failed\n", __LINE__);
		return 0;
	}

	rem = pos3 - pos2;
	data = (char *)malloc(rem);
	if (!data) {
		cifsd_debug("%d: memory allocation failed\n", __LINE__);
		return 0;
	}

	if (lseek(fd, pos2, SEEK_SET) == -1) {
		cifsd_debug("%d: file operation failed\n", __LINE__);
		free(data);
		return 0;
	}

	if (read(fd, data, rem) != rem) {
		cifsd_debug("%d: file operation failed\n", __LINE__);
		free(data);
		return 0;
	}

	if (lseek(fd, pos1, SEEK_SET) == -1) {
		cifsd_debug("%d: file operation failed\n", __LINE__);
		free(data);
		return 0;
	}

	if (write(fd, data, rem) != rem) {
		cifsd_debug("%d: file operation failed\n", __LINE__);
		free(data);
		return 0;
	}

	if (ftruncate(fd, pos3 - len) == -1) {
		cifsd_debug("%d: file operation failed\n", __LINE__);
		free(data);
		return 0;
	}

	free(data);

	fd_usr = open(PATH_CIFSD_USR, O_WRONLY);
	if (fd_usr) {
		len = strlen(usrname) + 2;
		construct = (char *)malloc(len);
		if (!construct) {
			close(fd_usr);
			return 0;
		}

		memset(construct, 0, len);
		snprintf(construct, len, "%s:", usrname);
		if (write(fd_usr, construct, len-1) != len-1) {
			cifsd_err("%s write failed, errno : %d\n",
				PATH_CIFSD_USR, errno);
			free(construct);
			close(fd_usr);
			return 0;
		}
		free(construct);
		close(fd_usr);
	}

	return 1;
}

/**
 * remove_user_account() - function to remove user account
 * @username:	account for username to be removed
 *
 * Return:	success: CIFS_SUCCESS; fail: CIFS_FAIL
 */
int remove_user_account(int fd, char *username)
{
	char *line, *name;
	int iseof = 0, lcnt = 0, removed = 0, len;

	if (lseek(fd, 0, SEEK_SET) == -1) {
		cifsd_debug("%d: file operation failed\n", __LINE__);
		return CIFS_FAIL;
	}

	do {
		len = get_entry(fd, &line, &iseof);
		if (len == -ENOMEM)
			break;

		if (len < 0) {
			free(line);
			continue;
		}

		lcnt++;
		name = strtok(line, ":");
		if (name && !strcmp(name, username)) {
			if (remove_user_entry(fd, username, lcnt)) {
				cifsd_debug("[%s] remove success\n",
					username);
				removed = 1;
			}
		}
		free(line);

	} while (!iseof && !removed);


	return removed ? CIFS_SUCCESS : CIFS_FAIL;
}

/**
 * query_user_account() - function to check user account status in cifsd
 * @usrname:	user name for the account under query
 *
 * Return:	success: CIFS_SUCCESS (user configured with cifsd)
 *		fail: CIFS_NONE_USR (user not configured with cifsd)
 *		fail: CIFS_FAIL (cifsd not available)
 */
int query_user_account(char *username)
{
	char *q_usrname;
	int eof = 0, len, ret;
	FILE *fp;

	fp = fopen(PATH_CIFSD_USR, "r");
	if (!fp) {
		cifsd_err("%s open failed, error : %d\n", PATH_CIFSD_USR, errno);
		return -errno;
	}

retry:
	len = readline(fp, &q_usrname, &eof, 0);
	if (len > 0) {
		if (*q_usrname == '\0') /* skip NULL in read from sysfs */
			ret = strncmp(q_usrname+1, username, strlen(username));
		else
			ret = strncmp(q_usrname, username, strlen(username));

		if (!ret) {
			cifsd_err("[%s] is configured with cifsd\n",
				username);
		} else {
			free(q_usrname);
			goto retry;
		}
	} else
		cifsd_err("[%s] is not configured with cifsd\n",
				username);

	fclose(fp);
	free(q_usrname);

	return ((len > 0) ? CIFS_SUCCESS : CIFS_NONE_USR);
}

/**
 * usage() - utility function to show usage details
 */
void usage(void)
{
	fprintf(stdout, "cifsd-tools version : %s, date : %s\n"
			"Usage: cifsadmin [option]\n"
			"option:\n"
			"	-h help\n"
			"	-v verbose\n"
			"	-a <username> add/update user account\n"
			"	-d <username> delete user account\n"
			"	-q <username> query user exists in cifsd\n",
			CIFSD_TOOLS_VERSION, CIFSD_TOOLS_DATE);

	exit(0);
}

/**
 * parse_options() - utility function to parse commandline arguments
 * @argc:	commandline argument count
 * @argv:	commandline argument list
 *
 * Return:	user selected option flag value
 */
int parse_options(int argc, char **argv)
{
	int ch;
	int s_flags = 0;

	while ((ch = getopt(argc, argv, "a:d:q:hv")) != EOF) {
		if (ch == 'a' || ch == 'd' || ch == 'q') {
			if (!optarg) {
				cifsd_debug("option [value] missing\n");
				usage();
			}
			if (dup_optarg)
				free(dup_optarg);
			dup_optarg = strdup(optarg);
		}

		if (ch == 'a' || ch == 'd' || ch == 'q') {
			if (s_flags && s_flags != F_VERBOSE) {
				cifsd_err("Try with single flag at a time\n");
				usage();
			}
		}

		switch (ch) {
		case 'a':
			s_flags |= F_ADD_USER;
		break;
		case 'd':
			s_flags |= F_REMOVE_USER;
		break;
		case 'q':
			s_flags |= F_QUERY_USER;
		break;
		case 'v':
			if (argc <= 2) {
				cifsd_debug(
					"[option] needed with verbose\n");
				usage();
			}
			s_flags |= F_VERBOSE;
		break;
		case '?':
		case 'h':
		default:
			usage();
		}
	}

	return s_flags;
}

/**
 * sigcatcher_setup() - utility function to setup SIGINT handler
 */
void sigcatcher_setup(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_sigaction = handle_sigint;
	sa.sa_flags = SA_SIGINFO;

	sigaction(SIGINT, &sa, 0);
}

/**
 * main() - entry point of application
 * @argc:	commandline argument count
 * @argv:	commandline argument list
 *
 * Return: success/fail: 0
 */
int main(int argc, char *argv[])
{
	int options = 0, ret = 0;
	int fd_db;

	if (argc < 2)
		usage();

	sigcatcher_setup();
	dup_optarg = NULL;

	options = parse_options(argc, argv);

	fd_db = open(PATH_PWDDB, O_RDWR);
	if (fd_db < 0) {
		/* file not existing, create it now */
		fd_db = open(PATH_PWDDB, O_CREAT | O_RDWR, 0666);
		if (fd_db < 0) {
			cifsd_err("[%s] open failed\n", PATH_PWDDB);
			return 0;
		}
	}

	if (getuid() == 0)
		options |= AM_ROOT;

	if ((options & F_QUERY_USER) && dup_optarg)
		ret = query_user_account(dup_optarg);
	else if (((options & F_ADD_USER) || (options & F_REMOVE_USER)) && dup_optarg) {
		struct passwd *p = getpwuid(getuid());
		if ((options & AM_ROOT) || !strcmp(p->pw_name, dup_optarg)) {
			if (options & F_ADD_USER)
				ret = add_user_account(fd_db, dup_optarg, options);
			else if (options & F_REMOVE_USER)
				ret = remove_user_account(fd_db, dup_optarg);
		}
	}

	close(fd_db);
	if (dup_optarg)
		free(dup_optarg);

	return ret;
}
