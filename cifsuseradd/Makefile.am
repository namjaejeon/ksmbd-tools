AM_CFLAGS = -I$(top_srcdir)/include $(GLIB_CFLAGS) $(LIBNL_CFLAGS) -fno-common
LIBS = $(GLIB_LIBS) $(LIBNL_LIBS)
cifsuseradd_LDADD = $(top_builddir)/lib/libcifsdtools.la

sbin_PROGRAMS = cifsuseradd

cifsuseradd_SOURCES = md4_hash.c user_admin.c cifsuseradd.c
