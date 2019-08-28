AM_CFLAGS = -I$(top_srcdir)/include $(GLIB_CFLAGS) $(LIBNL_CFLAGS) -fno-common
LIBS = $(GLIB_LIBS) $(LIBNL_LIBS)
cifsshareadd_LDADD = $(top_builddir)/lib/libcifsdtools.la

sbin_PROGRAMS = cifsshareadd

cifsshareadd_SOURCES = share_admin.c cifsshareadd.c
