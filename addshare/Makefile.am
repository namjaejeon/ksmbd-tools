AM_CFLAGS = -Wall -Werror -Wunused-parameter \
            -Wno-address-of-packed-member \
	    -I$(top_srcdir)/include $(GLIB_CFLAGS) $(LIBNL_CFLAGS) -fno-common
LIBS = $(GLIB_LIBS)
ksmbd_addshare_LDADD = $(top_builddir)/lib/libksmbdtools.la

sbin_PROGRAMS = ksmbd.addshare

ksmbd_addshare_SOURCES = share_admin.c addshare.c
