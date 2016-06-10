## Makefile.am

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -Wall
sbin_PROGRAMS = cifssrvd
cifssrvd_SOURCES = conv.c dcerpc.c pipecb.c netlink.c winreg.c cifssrvd.c netlink.h winreg.h $(top_srcdir)/include/cifssrv.h
cifssrvd_LDADD = $(top_builddir)/lib/libcifssrv.la
