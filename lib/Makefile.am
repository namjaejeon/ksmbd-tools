AM_CFLAGS = -I$(top_srcdir)/include $(GLIB_CFLAGS) -fno-common
LIBS = $(GLIB_LIBS)

lib_LTLIBRARIES = libcifsdtools.la
libcifsdtools_la_LIBADD = -lresolv
libcifsdtools_la_SOURCES = management/tree_conn.c \
			   management/user.c \
			   management/share.c \
			   management/session.c \
			   config_parser.c \
			   cifsdtools.c
