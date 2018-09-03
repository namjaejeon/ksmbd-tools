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

#include <syslog.h>
#include <glib.h>
#include <glib/gi18n.h>

#include <stdio.h>
#include <cifsdtools.h>

static const char *app_name = "unknown";
static int log_open;

typedef void (*logger)(int level, const char *fmt, va_list list);

static int syslog_level(int level)
{
	if (level == PR_ERROR)
		return LOG_ERR;
	if (level == PR_INFO)
		return LOG_INFO;
	if (level == PR_DEBUG)
		return LOG_DEBUG;

	return LOG_ERR;
}

static void __pr_log_stdio(int level, const char *fmt, va_list list)
{
	char buf[1024];

	vsnprintf(buf, sizeof(buf), fmt, list);
	printf("%s", buf);
}

static void __pr_log_syslog(int level, const char *fmt, va_list list)
{
	vsyslog(syslog_level(level), fmt, list);
}

static logger __logger = __pr_log_stdio;

void set_logger_app_name(const char *an)
{
	app_name = an;
}

const char *get_logger_app_name(void)
{
	return app_name;
}

void __pr_log(int level, const char *fmt,...)
{
	va_list list;

	va_start(list, fmt);
	__logger(level, fmt, list);
	va_end(list);
}

void pr_logger_init(int flag)
{
	if (flag == PR_LOGGER_SYSLOG) {
		if (log_open) {
			closelog();
			log_open = 0;
		}
		openlog("cifsd", LOG_NDELAY, LOG_LOCAL5);
		__logger = __pr_log_syslog;
		log_open = 1;
	}
}

void pr_hex_dump(const void *mem, size_t sz)
{
	const int WIDTH = 160;
	int xi = 0, si = 0, mi = 0;
	char xline[WIDTH];
	char sline[WIDTH];

	while (mi < sz) {
		char c = *((char *)mem + mi);

		mi++;
		xi += sprintf(xline + xi, "%02X ", 0xff & c);
		if (c > ' ' && c < '~')
			si += sprintf(sline + si, "%c", c);
		else
			si += sprintf(sline + si, ".");
		if (xi >= WIDTH / 2) {
			pr_err("%s         %s\n", xline, sline);
			xi = 0;
			si = 0;
		}
	}

	if (xi) {
		int sz = WIDTH / 2 - xi + 1;
		if (sz > 0) {
			memset(xline + xi, ' ', sz);
			xline[WIDTH / 2 + 1] = 0x00;
		}
		pr_err("%s         %s\n", xline, sline);
	}
}

char *base64_encode(unsigned char *src, unsigned long srclen)
{
	return g_base64_encode(src, srclen);
}

unsigned char *base64_decode(char const *src, unsigned long *dstlen)
{
	unsigned char *ret = g_base64_decode(src, dstlen);
	if (ret)
		ret[*dstlen] = 0x00;
	return ret;
}
