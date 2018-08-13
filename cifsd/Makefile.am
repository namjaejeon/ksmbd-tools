AM_CFLAGS = -I$(top_srcdir)/include $(GLIB_CFLAGS) $(LIBNL_CFLAGS) -fno-common
LIBS = $(GLIB_LIBS) $(LIBNL_LIBS)
cifsd_LDADD = $(top_builddir)/lib/libcifsdtools.la

sbin_PROGRAMS = cifsd

cifsd_SOURCES = worker.c ipc.c rpc.c rpc_srvsvc.c cifsd.c
