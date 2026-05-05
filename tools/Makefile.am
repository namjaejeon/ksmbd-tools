AM_CFLAGS = -DSYSCONFDIR='"${sysconfdir}"' -DRUNSTATEDIR='"${runstatedir}"' \
            -I$(top_srcdir)/include $(GLIB_CFLAGS) $(LIBKRB5_CFLAGS) -fno-common \
            $(ASAN_CFLAGS) $(MSAN_CFLAGS)
AM_LDFLAGS = $(ASAN_LDFLAGS) $(MSAN_LDFLAGS)
LIBS = $(GLIB_LIBS) $(LIBNL_LIBS) $(LIBKRB5_LIBS) $(PTHREAD_LIBS)

EXTRA_DIST = meson.build

libexec_PROGRAMS = ksmbd.tools
ksmbd_tools_SOURCES =     management/tree_conn.c \
                          management/user.c \
                          management/share.c \
                          management/session.c \
                          config_parser.c \
                          tools.c
if HAVE_LIBKRB5
ksmbd_tools_SOURCES +=     management/spnego.c \
                           asn1.c \
                           management/spnego_krb5.c \
                           management/spnego_mech.h
endif
ksmbd_tools_LDADD = $(top_builddir)/addshare/libaddshare.a \
                    $(top_builddir)/adduser/libadduser.a \
                    $(top_builddir)/control/libcontrol.a \
                    $(top_builddir)/mountd/libmountd.a
