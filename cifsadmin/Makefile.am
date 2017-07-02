## Makefile.am

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -Wall
sbin_PROGRAMS = cifsadmin
cifsadmin_SOURCES = cifsadmin.c  cifsadmin.h hash.c $(top_srcdir)/include/cifsd.h
cifsadmin_LDADD = $(top_builddir)/lib/libcifsd.la
