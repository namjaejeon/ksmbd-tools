AM_CFLAGS = -I$(top_srcdir)/include $(GLIB_CFLAGS)
check_PROGRAMS = quota-test rpc-test
TESTS = $(check_PROGRAMS)
TEST_EXTENSIONS = .py
quota_test_SOURCES = quota.c ../mountd/quota.c
quota_test_LDADD = $(GLIB_LIBS)
quota_test_LDFLAGS = -Wl,--wrap=open,--wrap=open64,--wrap=close,--wrap=fstat,--wrap=fstat64,--wrap=__fxstat,--wrap=__fxstat64,--wrap=fstatfs,--wrap=fstatfs64,--wrap=syscall,--wrap=ioctl
rpc_test_SOURCES = rpc.c
rpc_test_LDADD = $(top_builddir)/mountd/libmountd.a $(GLIB_LIBS)
if HAVE_IMPACKET
TESTS += rpc-interop.py
PY_LOG_COMPILER = $(PYTHON)
AM_TESTS_ENVIRONMENT = KSMBD_RPC_TEST='$(abs_builddir)/rpc-test'; export KSMBD_RPC_TEST;
if HAVE_NDR64
AM_TESTS_ENVIRONMENT += KSMBD_RPC_NDR64=1; export KSMBD_RPC_NDR64;
endif
endif
EXTRA_DIST = meson.build rpc-interop.py
