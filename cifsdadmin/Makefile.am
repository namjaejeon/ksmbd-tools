AM_CFLAGS = -I$(top_srcdir)/include $(GLIB_CFLAGS) $(LIBNL_CFLAGS) -fno-common
LIBS = $(GLIB_LIBS) $(LIBNL_LIBS)
cifsdadmin_LDADD = $(top_builddir)/lib/libcifsdtools.la

sbin_PROGRAMS = cifsdadmin

cifsdadmin_SOURCES = md4_hash.c cifsdadmin.c
