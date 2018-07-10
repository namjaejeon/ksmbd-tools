AM_CFLAGS = -I$(top_srcdir)/include $(GLIB_CFLAGS) $(LIBNL_CFLAGS) -fno-common
LIBS = $(GLIB_LIBS) $(LIBNL_LIBS)
cifsd_admin_LDADD = $(top_builddir)/lib/libcifsdtools.la

sbin_PROGRAMS = cifsd_admin

cifsd_admin_SOURCES = md4_hash.c cifsd_admin.c
