AM_CFLAGS = -DSYSCONFDIR='"${sysconfdir}"' -DRUNSTATEDIR='"${runstatedir}"' \
            -I$(top_srcdir)/include $(GLIB_CFLAGS) $(LIBNL_CFLAGS) -fno-common
LIBS = $(GLIB_LIBS)
ksmbd_control_LDADD = $(top_builddir)/lib/libksmbdtools.a

sbin_PROGRAMS = ksmbd.control

ksmbd_control_SOURCES = control.c

EXTRA_DIST = ksmbd.control.1.in

man_MANS = ksmbd.control.1
$(man_MANS): %: %.in; @$(in_script) $< >$@

CLEANFILES = $(man_MANS)
