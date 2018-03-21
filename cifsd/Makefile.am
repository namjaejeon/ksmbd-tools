AM_CFLAGS = -I$(top_srcdir)/include $(GLIB_CFLAGS) $(LIBNL_CFLAGS)
LIBS = $(GLIB_LIBS) $(LIBNL_LIBS)
cifsd_LDADD = $(top_builddir)/lib/libcifsdtools.la

sbin_PROGRAMS = cifsd

cifsd_SOURCES = management/tree_conn.c management/user.c management/share.c \
		config_parser.c worker_pool.c ipc.c cifsd.c
