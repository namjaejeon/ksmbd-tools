AM_CFLAGS = -DSYSCONFDIR='"${sysconfdir}"' -DRUNSTATEDIR='"${runstatedir}"' \
            -I$(top_srcdir)/include $(GLIB_CFLAGS) $(LIBNL_CFLAGS) -fno-common
LIBS = $(GLIB_LIBS)
ksmbd_addshare_LDADD = $(top_builddir)/lib/libksmbdtools.a

sbin_PROGRAMS = ksmbd.addshare

ksmbd_addshare_SOURCES = share_admin.c addshare.c share_admin.h

EXTRA_DIST = ksmbd.addshare.8.in

man_MANS = ksmbd.addshare.8
$(man_MANS): %: %.in; @$(in_script) $< >$@

CLEANFILES = $(man_MANS)
