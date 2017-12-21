/*
 *   cifsd-tools/lib/libcifsd.c
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cifsd.h"

static const char FMTerr[] = "Format Err, expected single space around '='";

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

	*str1 = *str2 = NULL;

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
		cnt -= 1; /* discard newline */
		*isEOF = 0;
		if (check)
			lcnt++;
	}

	if (cnt > 0 && check) {
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
 * @fd:		source file descriptor
 * @buf:	allocate and initialize destination pointer
 * @isEOF:	end of file marker
 *
 * Return:	success: "value > 0"; fail: "value <= 0"
 */
int get_entry(int fd, char **dst, int *isEOF)
{
	char c;
	int cnt = 0;
	int val;
	char *buf;
	int i = 0;

	buf = (char *)malloc(LINESZ + 1);
	if (!buf) {
		cifsd_err("memory allocation failed\n");
		return -ENOMEM;
	}

	memset(buf, 0, LINESZ + 1);
	*dst = buf;

	while ((val = read(fd, &c, 1)) > 0 && ++i <= LINESZ) {
		buf[cnt++] = c;

		if (c == ':') {
			if (read(fd, &buf[cnt], CIFS_NTHASH_SIZE + 1) !=
				CIFS_NTHASH_SIZE + 1) {
				cifsd_err("file operation is failed"
					", errno(%d)\n", errno);
				return -1;
			}

			buf[cnt + CIFS_NTHASH_SIZE] = 0; /* skip '\n' */
			cnt += CIFS_NTHASH_SIZE;
			break;
		}
	}

	if (!val)
		*isEOF = 1;

	return cnt;
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
