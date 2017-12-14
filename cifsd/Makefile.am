## Makefile.am
threads_LIB = -lpthread
threads_CFLAGS = -pthread
AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -Wall $(threads_CFLAGS)
sbin_PROGRAMS = cifsd
cifsd_SOURCES = conv.c dcerpc.c pipecb.c winreg.c cifsd.c winreg.h $(top_srcdir)/include/cifsd.h
cifsd_LDADD = $(top_builddir)/lib/libcifsd.la $(threads_LIB)
