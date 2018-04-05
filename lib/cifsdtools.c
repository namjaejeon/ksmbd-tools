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

#include <glib.h>
#include <glib/gi18n.h>

#include <stdio.h>
#include <cifsdtools.h>

static const char *app_name = "unknown";

void set_logger_app_name(const char *an)
{
	app_name = an;
}

const char *get_logger_app_name(void)
{
	return app_name;
}

void __pr_log(const char *fmt,...)
{
	char buf[1024];
	va_list args;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	printf("%s", buf);
}

char *base64_encode(unsigned char *src, size_t srclen)
{
	return g_base64_encode(src, srclen);
}

unsigned char *base64_decode(char const *src, size_t *dstlen)
{
	unsigned char *ret = g_base64_decode(src, dstlen);
	if (ret)
		ret[*dstlen] = 0x00;
	return ret;
}
