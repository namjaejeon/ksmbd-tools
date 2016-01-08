/*
 *   cifssrv-tools/cifsmgr.c
 *
 *   Copyright (C) 2015 Samsung Electronics Co., Ltd.
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

#include "cifsmgr.h"

/* global variables */
static FILE *fp_dbpath;
static struct termios old_attr;
static int isterm;
static char *LINE;
static char *dup_optarg;
static const char FMTerr[] = "Format Err, expected single space around '='";
static char def_conf[] =
";**************************************************************************\n"
"; File to define cifssrv [share] configuration parameters.\n"
";\n"
"; Currently supported parameters list:\n"
";\t- allow hosts\n"
";\t- available\n"
";\t- browsable\n"
";\t- comment\n"
";\t- deny hosts\n"
";\t- guest ok\n"
";\t- guest only\n"
";\t- invalid users\n"
";\t- max connections\n"
";\t- oplocks\n"
";\t- path\n"
";\t- read list\n"
";\t- valid users\n"
";\t- writeable\n"
"; Parameters not set would be initialized to default, refer below link:\n"
";\thttps://www.samba.org/samba/docs/man/manpages-3/smb.conf.5.html\n"
";\n"
"; Rules to update this file:\n"
";\t- Every [share] definition should start on new line\n"
";\t- Every share's parameter should be indented with single tab\n"
";\t- There should be single spaces around equal (eg: \" = \")\n"
";\t- Multiple parameters should be separated with comma\n"
"\t\teg: \"invalid users = usr1,usr2,usr3\"\n"
";\n"
"; Make sure to configure the server after making changes to this file.\n"
";**************************************************************************\n"
"\n"
"[homes]\n"
"\tcomment = target file server share\n"
"\tpath = /tmp\n";

/**
 * handle_sigint() - registered signal handler for SIGINT
 * @signum:	occured signal number
 * @siginfo:	information associated with signum
 * @message:	additonal text data for signum
 */
static void handle_sigint(int signum, siginfo_t *siginfo, void *message)
{
	if (signum == SIGINT) {
		fprintf(stdout, "Received [Signo:%d] [SigCode:%d]\n",
			siginfo->si_signo, siginfo->si_code);

		/* code added to suppress warning*/
		if (!(int *)message)
			fprintf(stdout, "Message field empty\n");

		if (isterm)
			if (isatty(STDIN_FILENO))
				tcsetattr(STDIN_FILENO, TCSANOW, &old_attr);

		fprintf(stdout, "Terminating program\n");
		exit(0);
	}
}

/**
 * cifs_chk_err() - function to check error type
 * @flags:	error flag to check for print
 */
static void cifs_chk_err(int flags)
{
	if (!(flags & VERBOSE))
		return;

	switch (flags) {
		case CIFS_NONE_USR:
			fprintf(stderr, "Invalid user\n");
			break;
		case CIFS_CONF_FAIL:
			fprintf(stderr, "Configuration failed\n");
			break;
		case CIFS_AUTH_FAIL:
			fprintf(stderr, "Authentication failed\n");
			break;
		default:
			break;
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

	for (len = 0; *(COPY_UCS2_CHAR(&c, src)); src++, len++)
		;

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

	memset(pOut, 0, MAX_NT_PWD_LEN*sizeof(unsigned short));

	conv = iconv_open("UTF16LE", "UTF-8");
	if (conv == (iconv_t)-1) {
		if (errno == EINVAL) {
			conv = iconv_open("UCS-2LE", "UTF-8");
			if (conv == (iconv_t)-1) {
				fprintf(stderr,"failed(%d) to open conversion"
					" for UCS-2LE to UTF-8\n", errno);
				return -1;
			}
		} else {
			fprintf(stderr, "failed to open conversion for"
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
 * prompt_pwd() - helper function to read user password string from stdin
 * @message:	information to be displayed to user
 *
 * Return:	success: "user provided pwd string"; fail: "NULL"
 */
char *prompt_pwd(char *message)
{
	struct termios attr;
	char password[MAX_NT_PWD_LEN];
	int fd = -1;
	size_t len;

	memset(password, 0, MAX_NT_PWD_LEN);

	if (isatty(STDIN_FILENO)) {
		memset((void *)&attr, 0, sizeof(attr));
		memset((void *)&old_attr, 0, sizeof(old_attr));

		if (tcgetattr(STDIN_FILENO, &attr) < 0) {
			perror("tcgetattr");
			return NULL;
		}

		memcpy(&old_attr, &attr, sizeof(attr));
		fd = fcntl(0, F_GETFL, 0);
		if (fd < 0) {
			perror("fcntl");
			return NULL;
		}

		attr.c_lflag &= ~(ECHO);

		isterm = 1;

		if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &attr) < 0) {
			perror("tcsetattr");
			return NULL;
		}
	}

retry:
	fprintf(stdout, "%s", message);
	if (fgets(password, sizeof(password), stdin) == NULL) {
		if (isatty(STDIN_FILENO)) {
			tcsetattr(STDIN_FILENO, TCSANOW, &old_attr);
			isterm = 0;
		}
		return NULL;
	}

	len = strlen(password);
	if (!len) {
		fprintf(stdout, "Password length(%d) invalid!"
				" allowed length 1 ~ %d\n",
				len, MAX_NT_PWD_LEN-1);
		goto retry;
	}

	if (password[len-1] == '\n')
		password[len - 1] = 0;

	if (isatty(STDIN_FILENO)) {
		tcsetattr(STDIN_FILENO, TCSANOW, &old_attr);
		isterm = 0;
	}

	return strdup(password);
}

/**
 * readline() - reads single line of characters from file
 * @fp:	source file pointer
 * @buf:	allocate and initialize destination pointer
 * @isEOF:	end of file indicator
 * @check:	flag to check line input for formatting
 *
 * Return:	line size in number of characters
 */
int readline(FILE *fp, char **buf, int *isEOF, int check)
{
	ssize_t cnt = 0;
	size_t sz = 0;
	char *lbuf = NULL;
	static int lcnt;
	int i;

	cnt = getline(&lbuf, &sz, fp);
	if (cnt == -1)
		*isEOF = 1;
	else {
		cnt -= 1; /* discard '\0' */
		*isEOF = 0;
		if (check)
			lcnt++;
	}

	if (cnt && check) {
		if (strpbrk(lbuf, "=") != NULL) {
			i = strcspn(lbuf, "=");

			if ((lbuf[i-1] != ' ') ||
					(lbuf[cnt-1] != '=' &&
					 lbuf[i+1] != ' ')) {
				fprintf(stdout, "[Line:%d] %s\n", lcnt, FMTerr);
				exit(0);
			}
		}
	}

	*buf = lbuf;

	return cnt;
}

/**
 * get_entry() - this is special case where getline() can't be used
 *		because NTHash value could also contain 0x0A
 * @fd:	source file descriptor
 * @buf:	allocate and initialize destination pointer
 * @isEOF:	end of file marker
 *
 * Return:	success: "value > 0"; fail: "value <= 0"
 */
int get_entry(FILE *fd, char **buf, int *isEOF)
{
	char c;
	int cnt = 0;
	int val;
	char *lbuf = (char *)malloc(LINESZ+1);

	if (!lbuf) {
		fprintf(stdout, "%d: memory allocation failed\n", __LINE__);
		return -1;
	}

	memset(lbuf, 0, LINESZ+1);
	*buf = lbuf;

	while ((val = fread(&c, 1, 1, fd)) > 0) {
		lbuf[cnt++] = c;

		if (c == ':') {
			if (fread(&lbuf[cnt], 1, CIFS_NTHASH_SIZE + 1, fd) !=
				CIFS_NTHASH_SIZE + 1) {
				fprintf(stdout, "%d: file operation failed\n",
					__LINE__);
				return 0;
			}
			lbuf[cnt + CIFS_NTHASH_SIZE] = 0; /* skip '\n' */
			cnt += CIFS_NTHASH_SIZE;
			break;
		}
	}

	if (!val)
		*isEOF = 1;

	return cnt;
}

/**
 * rdpwd() - function to read and encrypted user password
 * @pwd:	allocate and initialize destination
 *		pointer for user supplied pwd
 *
 * Return:	success: 1; fail: 0
 */
int rdpwd(unsigned char **pwd)
{
	char *new_pwd = NULL;
	char *re_pwd = NULL;
	unsigned char *encrypt = NULL;

	*pwd = NULL;

	encrypt = (unsigned char *)malloc(CIFS_NTHASH_SIZE+1);
	if (!encrypt)
		return 0;

	memset(encrypt, 0, CIFS_NTHASH_SIZE+1);

	new_pwd = prompt_pwd("New Password:\n");
	if (!new_pwd) {
		fprintf(stdout, "Error while setting password.\n");
		free(encrypt);
		return 0;
	}

	re_pwd = prompt_pwd("Retype Password:\n");
	if (!re_pwd) {
		fprintf(stdout, "Error while setting password.\n");
		free(encrypt);
		free(new_pwd);
		return 0;
	}

	if (strcmp(new_pwd, re_pwd)) {
		fprintf(stdout, "Passwords mismatch.\n");
		free(encrypt);
		free(new_pwd);
		free(re_pwd);
		return 0;
	}

	if (convert_nthash(encrypt, new_pwd)) {
		free(encrypt);
		free(new_pwd);
		free(re_pwd);
		return 0;
	}

	*pwd = encrypt;

	free(new_pwd);
	free(re_pwd);

	return 1;
}

/**
 * init_2_strings() - allocate and initialize two strings from src string
 * @src:	src string contains two stings delimated by ":"
 * @str1:	allocated and intialized by string prior to ":" in src
 * @str2:	allocated and intialized by string after ":" in src
 * @len:	length of src string
 *
 * Return:      0 on success, -ENOMEM on error
 */
int init_2_strings(const char *src, char **str1, char **str2, int len)
{
	int idx;
	int idx2;
	char *pos;

	if (src[len - 1] == '\n')
		len--;

	pos = strchr(src, ':');

	if (pos == NULL)
		return 0;

	idx = (int)(pos - src);
	if (idx <= 0)
		return 0;

	idx2 = len - idx - 1;

	*str1 = malloc(idx + 1);
	if (*str1 == NULL)
		return 0;

	*str2 = malloc(idx2 + 1);
	if (*str2 == NULL) {
		free(*str1);
		return 0;
	}

	memcpy(*str1, src, idx);
	*(*str1 + idx) = '\0';

	src += (idx + 1);

	memcpy(*str2, src, idx2);
	*(*str2 + idx2) = '\0';

	return 1;
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
 * updatetxt() - helper function to replace existing user entry
 *		with new details in database file
 * @nstr:	source string to be updated in database file
 * @nsz:	source length to be updated in database file
 * @lno:	line number to be updated in database file
 *
 * Return:	success: 1; fail: 0
 */
int updatetxt(char *nstr, size_t nsz, int lno)
{
	char *line;
	int eof = 0;
	int cnt = 1;

	if (fseek(fp_dbpath, 0, SEEK_SET) == -1)
		return 0;

	while (cnt++ < lno) {
		if (get_entry(fp_dbpath, &line, &eof) != -1)
			free(line);
	}

	if (fwrite(nstr, 1, nsz, fp_dbpath) != nsz)
		return 0;

	if (fwrite("\n", 1, 1, fp_dbpath) != 1)
		return 0;

	return 1;
}

/**
 * add_usr() - function to add/modify user account to local database file
 * @usrname:	user entry to be added/modified
 * @flag:	flag indicating caller context as Root/Non-Root
 *		- Root can add/modify any user account
 *		- Non-Root can only add/modify it's own account
 *
 * Return:	success: CIFS_SUCCESS; fail: CIFS_FAIL
 */
int add_usr(char *usrname, int flag)
{
	char *fusrname = NULL;
	unsigned char *pwd1 = NULL;
	int iseof = 0;
	int new = 1;
	int lno = 0;
	int len;

	if (fseek(fp_dbpath, 0, SEEK_SET) == -1)
		return CIFS_FAIL;

	while (!iseof) {
		char *line = NULL;

		len = get_entry(fp_dbpath, &line, &iseof);
		if (len > 0) {
			lno++;
			if (!getusrpwd(line, &fusrname, (char **)&pwd1, len)) {
				free(line);
				return CIFS_FAIL;
			}

			if (!strcmp((const char *)fusrname,
						(const char *)usrname)) {
				char *pwd2 = NULL;
				unsigned char encrypt[CIFS_NTHASH_SIZE + 1];

				memset(encrypt, 0, CIFS_NTHASH_SIZE + 1);

				if (flag & AM_ROOT)
					goto BYPASS;

				pwd2 = prompt_pwd("Old Password:\n");
				if (!pwd2) {
					fprintf(stdout,
						"Error while setting pwd.\n");
					free(line);
					free(fusrname);
					free(pwd1);
					return CIFS_FAIL;
				}

				if (convert_nthash(encrypt, pwd2)) {
					free(line);
					free(fusrname);
					free(pwd1);
					free(pwd2);
					return CIFS_FAIL;
				}

				if (!strcmp((const char *)pwd1,
						(const char *)encrypt)) {
					unsigned char *newpwd;
BYPASS:
					rdpwd(&newpwd);
					if (newpwd) {
						char *newline = NULL;
						size_t sz = 0;
						int tmp = strlen(usrname);

						sz = tmp + CIFS_NTHASH_SIZE + 2;

						newline = (char *)malloc(sz);
						if (!newline) {
							free(line);
							free(fusrname);
							free(pwd1);
							if (pwd2)
								free(pwd2);
							free(newpwd);
							return CIFS_FAIL;
						}

						memset(newline, 0, sz);
						memcpy(newline, usrname, tmp);
						memcpy(newline+tmp, ":", 1);
						memcpy(newline + tmp + 1,
							newpwd,
							CIFS_NTHASH_SIZE);

						updatetxt(newline, sz - 1, lno);

						free(newpwd);
						free(newline);
					}

					if (flag & AM_ROOT) {
						new = 0;
						free(fusrname);
						free(pwd1);
						free(line);
						if (pwd2)
							free(pwd2);
						break;
					}
				} else
					fprintf(stdout,
						"Pwd authentication failed\n");

				new = 0;
				free(fusrname);
				free(pwd2);
				free(pwd1);
				free(line);
				break;
			}
			free(fusrname);
			free(pwd1);
		}
		if (len >= 0)
			free(line);
	}

	if (iseof && new) {
		unsigned char *newpwd;

		rdpwd(&newpwd);
		if (newpwd) {
			size_t sz, val = strlen(usrname);
			char *construct;

			if (fseek(fp_dbpath, 0, SEEK_END) == -1) {
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
			memcpy(construct, usrname, val);
			memcpy(construct+val, ":", 1);
			memcpy(construct+val + 1, newpwd, 16);
			memcpy(construct+val + 1 + 16, "\n", 1);

			if (fwrite(construct, 1, sz - 1, fp_dbpath) != sz - 1) {
				fprintf(stdout, "%d: file operation failed\n",
					__LINE__);
				free(newpwd);
				free(construct);

				return CIFS_FAIL;
			}

			free(construct);
			free(newpwd);
		}
	}

	return CIFS_SUCCESS;
}

/**
 * delete_usr() - function to delete user account from local database file
 *		and running cifssrv if available
 * @usrname:	user name to be removed
 * @lno:	line number of user entry in local database file
 *
 * Return:	success: 1; fail: 0
 */
int delete_usr(char *usrname, int lno)
{
	long pos1, pos2, pos3;
	char *data;
	size_t rem;
	char *line = NULL;
	char *construct;
	FILE *fd_cifssrv_usr;
	int eof = 0;
	int len;
	int cnt = 1;

	if (fseek(fp_dbpath, 0, SEEK_SET) == -1) {
		fprintf(stdout, "%d: file operation failed\n", __LINE__);
		return 0;
	}

	while (cnt++ < lno) {
		if (get_entry(fp_dbpath, &line, &eof) != -1)
			free(line);
	}

	pos1 = ftell(fp_dbpath);
	if (pos1 == -1) {
		fprintf(stdout, "%d: file operation failed\n", __LINE__);
		return 0;
	}
	len = get_entry(fp_dbpath, &line, &eof);
	if (len >= 0)
		free(line);
	len += 1; /* add '\n' to length */
	pos2 = pos1 + len;
	if (fseek(fp_dbpath, 0, SEEK_END) == -1) {
		fprintf(stdout, "%d: file operation failed\n", __LINE__);
		return 0;
	}
	pos3 = ftell(fp_dbpath);
	if (pos3 == -1) {
		fprintf(stdout, "%d: file operation failed\n", __LINE__);
		return 0;
	}

	rem = pos3 - pos2;
	data = (char *)malloc(rem);
	if (!data) {
		fprintf(stdout, "%d: memory allocation failed\n", __LINE__);
		return 0;
	}

	if (fseek(fp_dbpath, pos2, SEEK_SET) == -1) {
		fprintf(stdout, "%d: file operation failed\n", __LINE__);
		free(data);
		return 0;
	}

	if (fread(data, 1, rem, fp_dbpath) != rem) {
		fprintf(stdout, "%d: file operation failed\n", __LINE__);
		free(data);
		return 0;
	}

	if (fseek(fp_dbpath, pos1, SEEK_SET) == -1) {
		fprintf(stdout, "%d: file operation failed\n", __LINE__);
		free(data);
		return 0;
	}

	if (fwrite(data, 1, rem, fp_dbpath) != rem) {
		fprintf(stdout, "%d: file operation failed\n", __LINE__);
		free(data);
		return 0;
	}

	if (ftruncate(fileno(fp_dbpath), pos3 - len) == -1) {
		fprintf(stdout, "%d: file operation failed\n", __LINE__);
		free(data);
		return 0;
	}

	free(data);

	fd_cifssrv_usr = fopen(PATH_CIFSSRV_USR, "w");
	if (fd_cifssrv_usr) {
		len = strlen(usrname) + 2;
		construct = (char *)malloc(len);
		if (!construct) {
			fclose(fd_cifssrv_usr);
			return 0;
		}

		memset(construct, 0, len);
		snprintf(construct, len, "%s:", usrname);
		if (fwrite(construct, 1, len-1, fd_cifssrv_usr) != len-1) {
			fprintf(stdout, "cifssrv not available\n");
			free(construct);
			fclose(fd_cifssrv_usr);
			return 0;
		}
		free(construct);
		fclose(fd_cifssrv_usr);
	}

	return 1;
}

/**
 * rm_usr() - function to remove user account
 * @usrname:	account for user name to be removed
 *
 * Return:	success: CIFS_SUCCESS; fail: CIFS_FAIL
 */
int rm_usr(char *usrname)
{
	int iseof = 0;
	char *line;
	int lcnt = 0;
	char *name;
	int removed = 0;
	int len;

	if (fseek(fp_dbpath, 0, SEEK_SET) == -1) {
		fprintf(stdout, "%d: file operation failed\n", __LINE__);
		return CIFS_FAIL;
	}

	while (!iseof) {
		len = get_entry(fp_dbpath, &line, &iseof);
		if (len > 0) {
			lcnt++;
			name = strtok(line, ":");
			if (name && !strcmp(name, usrname)) {
				if (delete_usr(usrname, lcnt)) {
					fprintf(stdout, "[%s] remove success\n",
						usrname);
					removed = 1;
				}

				free(line);
				break;
			}
		}

		if (len >= 0)
			free(line);
	}

	if (!removed)
		fprintf(stdout, "[%s] remove failed\n", usrname);

	return removed ? CIFS_SUCCESS : CIFS_FAIL;
}

/**
 * config_users() - function to configure cifssrv with user accounts from
 *			local database file. cifssrv should be live in kernel
 *			else this function fails and displays user message
 *			"cifssrv not available"
 *
 * Return:	success: CIFS_SUCCESS; fail: CIFS_CONF_FAIL
 */
int config_users(void)
{
	int eof = 0;
	char *lstr;
	char *usr;
	char *pwd;
	char *construct = NULL;
	int len;
	FILE *fd_cifssrv_usr;

	fd_cifssrv_usr = fopen(PATH_CIFSSRV_USR, "w");
	if (!fd_cifssrv_usr) {
		fprintf(stderr, "cifssrv not available\n");
		return CIFS_CONF_FAIL;
	}

	if (fseek(fp_dbpath, 0, SEEK_SET) == -1) {
		fclose(fd_cifssrv_usr);
		return CIFS_CONF_FAIL;
	}

	while (!eof) {
		size_t i;

		len = get_entry(fp_dbpath, &lstr, &eof);
		if (len > 0) {
			usr = NULL;
			pwd = NULL;

			init_2_strings(lstr, &usr, &pwd, len);

			if (usr && pwd) {
				len = strlen(usr);
				i = len+CIFS_NTHASH_SIZE+2;

				construct = (char *)malloc(i);
				if (!construct) {
					free(lstr);
					free(usr);
					free(pwd);
					fclose(fd_cifssrv_usr);
					return CIFS_CONF_FAIL;
				}

				memset(construct, 0, i);

				memcpy(construct, usr, len);
				memcpy(construct+len, ":", 1);
				memcpy(construct+len+1, pwd, 16);

				if (fwrite(construct, 1, i-1, fd_cifssrv_usr) !=
						i-1) {
					fprintf(stderr,
						"cifssrv not available\n");
					free(lstr);
					free(usr);
					free(pwd);
					free(construct);
					fclose(fd_cifssrv_usr);
					return CIFS_CONF_FAIL;
				}
				fflush(fd_cifssrv_usr);
				free(usr);
				free(pwd);
				free(construct);
			}
		}

		if (len >= 0)
			free(lstr);
	}

	fclose(fd_cifssrv_usr);
	return CIFS_SUCCESS;
}

/**
 * gval() - utility function to convert hex value to decimal
 * @ch:		input hex value in ascii representation
 *
 * Return:	converted to decimal value from ch
 */
int gval(unsigned char *ch)
{
	int val = 0;

	if (*ch >= '0' && *ch <= '9')
		return *ch - '0';

	switch (*ch) {
	case 'A':
	case 'a':
		val = 10;
	break;
	case 'B':
	case 'b':
		val = 11;
	break;
	case 'C':
	case 'c':
		val = 12;
	break;
	case 'D':
	case 'd':
		val = 13;
	break;
	case 'E':
	case 'e':
		val = 14;
	break;
	case 'F':
	case 'f':
		val = 15;
	break;
	}

	return val;
}

/**
 * comp_list() - helper function to construct list of users
 *		existing in local database file.
 *		This would be used to protect overwriting of existing user
 *		account details when inporting from SAMBA databse file
 * @list:	constructed list of user names
 *
 * Return:	success: 1; fail: 0
 */
int comp_list(char *list)
{
	int eof = 0;
	char *lstr;
	char sep[] = ":";
	char *token;
	int len;

	if (fseek(fp_dbpath, 0, SEEK_SET) == -1)
		return 0;

	while (!eof) {
		len = get_entry(fp_dbpath, &lstr, &eof);
		if (len > 0) {
			token = strtok((char *)lstr, sep);
			if (token) {
				strncat(list, token, strlen(token));
				strncat(list, ":", 1);
			}
		}

		if (len >= 0)
			free(lstr);
	}

	return 1;
}

/**
 * chk_list() - helper function to check user account status
 *		in populated user list through comp_list()
 * @list:	source list of existing user accounts
 * @usr:	user name for the query
 *
 * Return:	success: 1 (user exists); fail: 0 (user not existing)
 */
int chk_list(char *list, char *usr)
{
	char sep[] = ":";
	char *token;
	char *dup = strdup(list);

	token = strtok(dup, sep);
	while (token) {
		if (!strcmp(usr, token)) {
			free(dup);
			return 1;
		}

		token = strtok(NULL, sep);
	}

	free(dup);
	return 0;
}

/**
 * import() - function to import user acccounts from SAMBA database file
 * @fname:	SAMBA database file as source to be used for importing
 *
 * Return:	success: CIFS_SUCCESS; fail: CIFS_FAIL
 */
int import(char *fname)
{
	char sep[] = ":\n";
	char *usr_buf;
	unsigned char construct[LINESZ];
	unsigned char *token1, *token2, *token3;
	FILE *fd;
	int i, j, k;
	int eof = 0;
	size_t len;
	char list[PAGE_SZ];

	fd = fopen(fname, "r");
	if (!fd) {
		fprintf(stderr, "[%s] open failed\n", fname);
		perror("Error");
		return CIFS_FAIL;
	}

	memset(list, 0, PAGE_SZ);
	if (!comp_list(list)) {
		fclose(fd);
		return CIFS_FAIL;
	}

	while (!eof) {
		memset(construct, 0, LINESZ);

		/* atleast HASH size should be read */
		if (readline(fd, &usr_buf, &eof, 0) < 32) {
			free(usr_buf);
			goto EXIT;
		}

		token1 = (unsigned char *)strtok(usr_buf, sep);
		token2 = (unsigned char *)strtok(NULL, sep);
		token2 = (unsigned char *)strtok(NULL, sep);
		token2 = (unsigned char *)strtok(NULL, sep);
		token3 = (unsigned char *)strtok(NULL, sep);
		token3 = (unsigned char *)strtok(NULL, sep);
		if (token1 && token2 && token3) {
			if (chk_list(list, (char *)token1)) {
				fprintf(stdout,
					"%s already exists, import skipped\n",
					token1);
				continue;
			}

			k = snprintf((char *)construct, LINESZ, "%s:", token1);

			for (i = 0, j = 0; i < 32; i += 2, j++)
				construct[j+k] = ((gval(&token2[i])*16) +
							gval(&token2[i+1]));
			construct[j+k] = '\n';
		} else {
			fprintf(stderr,
				"Import error, [%s] not in smbpasswd format\n",
				fname);
			free(usr_buf);
			fclose(fd);
			return CIFS_FAIL;
		}

		len = strlen((char *)construct);
		if (fwrite(construct, 1, len, fp_dbpath) != len) {
			fprintf(stderr, "%d: file operation failed\n",
				__LINE__);
			free(usr_buf);
			fclose(fd);
			return CIFS_FAIL;
		}

		fprintf(stderr, "Importing %s success\n", token1);
		free(usr_buf);
	}

EXIT:
	fclose(fd);
	return CIFS_SUCCESS;
}

/**
 * query_usr() - function to check user account status in cifssrv
 * @usrname:	user name for the account under query
 *
 * Return:	success: CIFS_SUCCESS (user configured with cifssrv)
 *		fail: CIFS_NONE_USR (user not configured with cifssrv)
 *		fail: CIFS_FAIL (cifssrv not available)
 */
int query_usr(char *usrname)
{
	FILE *fd;
	char *q_usrname;
	int eof = 0;
	int len;
	int ret;

	fd = fopen(PATH_CIFSSRV_USR, "r");
	if (!fd) {
		fprintf(stdout, "cifssrv not available\n");
		return CIFS_FAIL;
	}

retry:
	len = readline(fd, &q_usrname, &eof, 0);
	if (len > 0) {
		if (*q_usrname == '\0') /* skip NULL in read from sysfs */
			ret = strncmp(q_usrname+1, usrname, strlen(usrname));
		else
			ret = strncmp(q_usrname, usrname, strlen(usrname));

		if (!ret) {
			fprintf(stdout, "%s configured with cifssrv\n",
				usrname);
			goto found;
		} else {
			free(q_usrname);
			goto retry;
		}
	}

	fprintf(stdout, "%s not configured with cifssrv\n", usrname);

found:
	fclose(fd);
	free(q_usrname);
	return ((len > 0) ? CIFS_SUCCESS : CIFS_NONE_USR);
}

/**
 * getfchar() - helper function to locate valid starting character
 *		and copies characters till i/p LINE length.
 *		Here valid data means:
 *		i) not commented line (starting with ';' or '#')
 *		ii) ascii values between- a-z || A-Z || 0-9
 * @sz:	current LINE length
 * @c:		first valid character
 * @dst:	initialize destination string with LINE data starting from 'c'
 * @ssz:	total length of copied destination data
 */
void getfchar(int sz, char *c, char *dst, int *ssz)
{
	int cnt = 0;
	int i = 0;
	int len = 0;

	while ((cnt < sz) &&
			((LINE[cnt] != ';') &&
			 (LINE[cnt] != '#') &&
			 (LINE[cnt] != '[') &&
			 !(LINE[cnt] >= 'A' && LINE[cnt] <= 'Z') &&
			 !(LINE[cnt] >= 'a' && LINE[cnt] <= 'z') &&
			 !(LINE[cnt] >= '0' && LINE[cnt] <= '9')))
		cnt++;

	if (cnt == sz)
		*c = ' ';
	else
		*c = LINE[cnt];

	if ((LINE[cnt] != ';') && (LINE[cnt] != '#')) {
		while ((cnt < sz) &&
				(LINE[cnt] != ';') &&
				(LINE[cnt] != '#')) {
			dst[i++] = LINE[cnt++];
			len++;
		}
	}

	*ssz = len;
}

/**
 * tlws() - utility function truncates ending blank spaces
 * @src:	source string to be scanned
 * @dst:	destination string after truncating
 * @sz:	length of populated destination string
 */
void tlws(char *src, char *dst, int *sz)
{
	int dcnt = 0;
	int i = *sz;

	while ((--i >= 0) &&
			(src[i] != ']' &&
			 !(src[i] >= 'A' && src[i] <= 'Z') &&
			 !(src[i] >= 'a' && src[i] <= 'z') &&
			 !(src[i] >= '0' && src[i] <= '9')))
		;

	for (; i >= 0; i--) {
		dst[i] = src[i];
		dcnt++;
	}

	*sz = dcnt;
}

/**
 * config_shares() - function to initialize cifssrv with share settings.
 *			This function parses local configuration file and
 *			initializes cifssrv with [share] settings
 *
 * Return:	success: CIFS_SUCCESS; fail: CIFS_CONF_FAIL
 */
int config_shares(void)
{
	char lshare[PAGE_SZ] = "";
	char tbuf[PAGE_SZ];
	int cnt = 0;
	int lssz = 0;
	int limit = 0;
	int eof = 0;
	int sz;
	FILE *fd_cifssrv_config;
	FILE *fd_share_dir;

start:

	fd_share_dir = fopen(PATH_SHARECONF, "r");
	if (!fd_share_dir) {
		size_t len;

		fprintf(stdout, "[%s] not existing, installing\n",
			PATH_SHARECONF);
		fd_share_dir = fopen(PATH_SHARECONF, "w");
		if (!fd_share_dir) {
			fprintf(stdout, "[%s] Installation failed\n",
				PATH_SHARECONF);
			perror("Error");
			return CIFS_CONF_FAIL;
		}

		len = strlen(def_conf);
		if (fwrite(def_conf, 1, len, fd_share_dir) != len) {
			fprintf(stdout, "%d: file operation failed\n",
				__LINE__);
			fclose(fd_share_dir);
			return CIFS_CONF_FAIL;
		}

		fclose(fd_share_dir);
		goto start;
	}

	fd_cifssrv_config = fopen(PATH_CIFSSRV_CONFIG, "w");
	if (!fd_cifssrv_config) {
		fprintf(stdout, "cifssrv not available\n");
		fclose(fd_share_dir);
		return CIFS_CONF_FAIL;
	}

	memset(tbuf, 0, PAGE_SZ);

	while (!eof) {
		char ch;
		char stro[PAGE_SZ] = "";
		char str[PAGE_SZ] = "";
		char cont_str[PAGE_SZ] = "";
		int contsz = 0;
		int ssz = 0;

		cnt = readline(fd_share_dir, &LINE, &eof, 1);
		if (cnt > 0) {
			if (LINE[cnt-1] == '\\') {
				do {
					strncat(cont_str, LINE, cnt-1);
					free(LINE);
					cnt = readline(fd_share_dir,
							&LINE, &eof, 1);
				} while ((cnt > 0) && (LINE[cnt-1] == '\\'));

				if (cnt > 0)
					strncat(cont_str, LINE, cnt);
				free(LINE);

				contsz = strlen(cont_str);
				LINE = (char *)malloc(contsz+1);
				memset(LINE, 0, contsz+1);
				strncpy(LINE, cont_str, contsz);
				cnt = contsz;
			}

			getfchar(cnt, &ch, stro, &ssz);
			tlws(stro, str, &ssz);

			if ((ch == '[') ||
					(ch >= 'A' && ch <= 'Z') ||
					(ch >= 'a' && ch <= 'z')) {
				if (ch == '[') {
					memset(lshare, 0, PAGE_SZ);
					strncpy(lshare, str, ssz);
					lssz = ssz;
				}

again:
				if ((limit + ssz + 2) < PAGE_SZ) {
					strncat(tbuf+limit, "<", 1);
					strncat(tbuf+limit+1, str, ssz);
					strncat(tbuf+limit+1+ssz, ">", 1);
					limit += ssz+2;
				} else {
					strncat(tbuf+limit, "#", 1);
					limit += 1;
					sz = fwrite(tbuf, 1, limit,
							fd_cifssrv_config);
					if (sz != limit) {
						/* retry once again */
						sleep(1);
						sz = fwrite(tbuf, 1, limit,
							fd_cifssrv_config);
						if (sz != limit) {
							fprintf(stdout,
								"%d:",
								__LINE__);
							perror("write error");
						}
					}

					memset(tbuf, 0, PAGE_SZ);

					if (ch != '[') {
						strncat(tbuf, "<", 1);
						strncat(tbuf+1, lshare, lssz);
						strncat(tbuf+1+lssz, ">", 1);
						limit = lssz+2;
					} else
						limit = 0;

					goto again;
				}
			}
		}

		free(LINE);
	}

	strncat(tbuf+limit, "#", 1);
	limit += 1;

	sz = fwrite(tbuf, 1, limit, fd_cifssrv_config);
	if (sz != limit) {
		/* retry once again */
		sleep(1);
		sz = fwrite(tbuf, 1, limit, fd_cifssrv_config);
		if (sz != limit) {
			perror("write error");
			fprintf(stdout, "%d: <write=%d> <req=%d>\n",
				__LINE__, sz, limit);
		}
	}

	fclose(fd_share_dir);
	fclose(fd_cifssrv_config);

	return CIFS_SUCCESS;
}

/**
 * getsh() - helper function to extract share details from source buffer
 * @buf:	source buffer containing share details
 * @share:	share name to be scanned in source buffer
 * @sz:	total length of source buffer
 * @osz:	copied size in characters of extracted buffer
 *
 * Return:	success: "extracted buffer pointer"; fail: "NULL"
 */
char *getsh(char *buf, char *share, int sz, int *osz)
{
	char *base = buf;
	char *dbuf = (char *)malloc(PAGE_SZ);
	char *dup = (char *)malloc(SMALLSZ);
	int cnt;

	if (!dbuf || !dup) {
		fprintf(stdout, "%d: memory allocation failed\n", __LINE__);
		if (dbuf)
			free(dbuf);
		if (dup)
			free(dup);
		return NULL;
	}
	memset(dbuf, 0, PAGE_SZ);

	while (buf < base+sz) {
		while ((buf < base+sz) && (*(buf++) != '['))
			;
		memset(dup, 0, SMALLSZ);
		cnt = 0;
		while ((buf < base+sz) && (*buf != ']'))
			dup[cnt++] = *(buf++);

		buf++; /* skip ']' */

		if (!strcmp(dup, share)) {
			cnt = 0;
			while ((buf < base+sz) && (*buf != '['))
				dbuf[cnt++] = *(buf++);

			*osz = cnt;
			free(dup);
			return dbuf;
		}
	}

	free(dbuf);
	free(dup);
	return NULL;
}

/**
 * sshare() - function to display requested share settings
 * @shname:	share name under query
 *
 * Return:	success: CIFS_SUCCESS; fail: CIFS_FAIL
 */
int sshare(char *shname)
{
	FILE *fp;
	char buf[PAGE_SZ];
	char *sbuf;
	int found = 0;
	int cnt;
	int ocnt;
	int i;

	fp = fopen(PATH_CIFSSRV_CONFIG, "r");
	if (!fp) {
		fprintf(stdout, "cifssrv not available\n");
		return CIFS_FAIL;
	}

	while ((cnt = fread(buf, 1, PAGE_SZ, fp)) > 0) {
		sbuf = getsh(buf, shname, cnt, &ocnt);
		if (sbuf) {
			fprintf(stdout, "[%s]", shname);
			for (i = 0; i < ocnt; i++)
				fprintf(stdout, "%c", sbuf[i]);
			found = 1;
			free(sbuf);
			break;
		}
	}

	if (!found)
		fprintf(stdout, "[%s] do not exist\n", shname);

	fclose(fp);
	return CIFS_SUCCESS;
}

/**
 * lshares() - function to show all configured share[s] with cifssrv
 *
 * Return:	success: CIFS_SUCCESS
 *		fail: CIFS_FAIL (displays message "cifssrv not available")
 */
int lshares(void)
{
	FILE *fp;
	char buf[PAGE_SZ];
	int cnt;
	int i;

	fp = fopen(PATH_CIFSSRV_SHARE, "r");
	if (!fp) {
		fprintf(stdout, "cifssrv not available\n");
		return CIFS_FAIL;
	}

	while ((cnt = fread(buf, 1, PAGE_SZ, fp)) > 0) {
		for (i = 0; i < cnt; i++)
			fprintf(stdout, "%c", buf[i]);
	}
	fclose(fp);
	return CIFS_SUCCESS;
}

/**
 * usage() - utility function to show usage details
 */
void usage(void)
{
	fprintf(stdout, "Usage: cifsadmin [option]\n"
			"option:\n"
			"	-h help\n"
			"	-v verbose\n"
			"	-a <usrname> add/update user\n"
			"	-r <usrname> remove user\n"
			"	-q <usrname> query user exists in cifssrv\n"
			"	-i <path> import SAMBA userlist from smbpasswd file\n"
			"	-c configure cifssrv with user(s) and share(s) details\n"
			"	-l list all shares\n"
			"	-s <share> show share settings\n");

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

	while ((ch = getopt(argc, argv, "a:r:q:i:s:hvcl")) != EOF) {
		if (ch == 'a' ||
				ch == 'r' ||
				ch == 'q' ||
				ch == 'i' ||
				ch == 's') {
			if (!optarg) {
				fprintf(stdout, "option [value] missing\n");
				usage();
			}
			if (dup_optarg)
				free(dup_optarg);
			dup_optarg = strdup(optarg);
		}

		if (ch == 'a' ||
				ch == 'r' ||
				ch == 'q' ||
				ch == 'i' ||
				ch == 's' ||
				ch == 'c' ||
				ch == 'l') {
			if (s_flags > VERBOSE) {
				fprintf(stdout,
					"Try with single flag at a time\n");
				usage();
			}
		}

		switch (ch) {
		case 'a':
			s_flags |= ADD_USR;
		break;
		case 'r':
			s_flags |= RM_USR;
		break;
		case 'q':
			s_flags |= QRY_USR;
		break;
		case 'i':
			s_flags |= IMPORT_USR_DB;
		break;
		case 'c':
			s_flags |= CONFIG_CIFSSRV;
		break;
		case 'l':
			s_flags |= LIST_SHARES;
		break;
		case 's':
			s_flags |= SHOW_SHARE;
		break;
		case 'v':
			if (argc <= 2) {
				fprintf(stdout,
					"[option] needed with verbose\n");
				usage();
			}
			s_flags |= VERBOSE;
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

	if (argc < 2) {
		usage();
		return 0;
	} else if (argc > 4) {
		fprintf(stdout, "Try with single flag at a time\n");
		return 0;
	}

	sigcatcher_setup();
	isterm = 0;
	dup_optarg = NULL;

	options = parse_options(argc, argv);

	fp_dbpath = fopen(PATH_PWDDB, "r+");
	if (!fp_dbpath) { /* file not existing, create it now */
		fp_dbpath = fopen(PATH_PWDDB, "w+");
		if (!fp_dbpath) {
			fprintf(stdout, "[%s] open failed\n", PATH_PWDDB);
			perror("Error");
			return 0;
		}
	}
	if (getuid() == 0)
		options |= AM_ROOT;

	if (options & LIST_SHARES)
		ret = lshares();
	else if ((options & SHOW_SHARE) && dup_optarg)
		ret = sshare(dup_optarg);
	else if ((options & QRY_USR) && dup_optarg)
		ret = query_usr(dup_optarg);
	else if ((options & IMPORT_USR_DB) && dup_optarg)
		ret = import(dup_optarg);
	else if (((options & ADD_USR) || (options & RM_USR)) && dup_optarg) {
		struct passwd *p = getpwuid(getuid());
		ret = CIFS_AUTH_FAIL;
		if ((options & AM_ROOT) || !strcmp(p->pw_name, dup_optarg)) {
			if (options & ADD_USR)
				ret = add_usr(dup_optarg, options);
			else if (options & RM_USR)
				ret = rm_usr(dup_optarg);
		}
	} else if (options & CONFIG_CIFSSRV) {
		ret = config_users();
		if (ret == CIFS_SUCCESS)
			ret = config_shares();
	}

	cifs_chk_err(ret);
	fclose(fp_dbpath);
	if (dup_optarg)
		free(dup_optarg);

	return 0;
}
