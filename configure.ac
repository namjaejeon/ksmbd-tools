AC_PREREQ([2.68])

AC_INIT([CIFSD tools], [cifsd_tools_version],
	[linux-cifsd-devel@lists.sourceforge.net])

# Get version from file VERSION
m4_define([cifsd_tools_version], m4_esyscmd([sed -n '1p' VERSION | tr -d '\n']))
m4_define([cifsd_tools_date], m4_esyscmd([sed -n '2p' VERSION | tr -d '\n']))
m4_define([cifsd_tools_gitdate],
                m4_esyscmd([git log -1 --pretty=format:%ci 2> /dev/null]))

AC_DEFINE([CIFSD_TOOLS_VERSION], "cifsd_tools_version", [cifsd-tools version])
AC_DEFINE([CIFSD_MAJOR_VERSION], m4_bpatsubst(cifsd_tools_version,
				 [\([0-9]*\)\(\w\|\W\)*], [\1]),
				 [Major version for cifsd-tools])
AC_DEFINE([CIFSD_MINOR_VERSION], m4_bpatsubst(cifsd_tools_version,
				 [\([0-9]*\).\([0-9]*\)\(\w\|\W\)*], [\2]),
				 [Minor version for cifsd-tools])
AC_CHECK_FILE(.git,
        AC_DEFINE([CIFSD_TOOLS_DATE],
                "m4_bpatsubst(cifsd_tools_gitdate,
                [\([0-9-]*\)\(\w\|\W\)*], [\1])",
                [cifsd-tools date based on Git commits]),
        AC_DEFINE([CIFSD_TOOLS_DATE],
                "cifsd_tools_date",
                [cifsd-tools date based on Source releases]))

AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign tar-pax dist-xz subdir-objects])

AC_LANG([C])
AC_PROG_CC
AC_PROG_CC_STDC
AM_SILENT_RULES([yes])
AC_PROG_LIBTOOL

# Checks for header files.
AC_CHECK_HEADERS([linux/netlink.h fcntl.h stdlib.h string.h \
		  unistd.h sys/socket.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS_ONCE([
	memset
	memcpy
	getpwnam
	sendmsg
	recvmsg
])

PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.40], [has_glib2=1], [has_glib2=0])
AS_IF([test "$has_glib2" -eq 0],
      AC_MSG_ERROR([No glib2 was found])
])

has_libnl_ver=0
dnl libnl-genl-3.0.pc pkg-config file just for libnl-3.0 case.
PKG_CHECK_MODULES([LIBNL], [libnl-3.0 >= 3.0 libnl-genl-3.0 >= 3.0], [has_libnl_ver=3], [has_libnl_ver=0])
AS_IF([test "$has_libnl_ver" -eq 0], [
	AC_MSG_ERROR([libnl and libnl-genl are required but were not found])
])
AS_IF([test "$has_libnl_ver" -gt 1], [
	AC_DEFINE([HAVE_LIBNL20], [1], [Define if you have libnl-2.0 or higher])
])

AC_CONFIG_FILES([
	Makefile
	lib/Makefile
	cifsd/Makefile
	cifsd_admin/Makefile
])

AC_OUTPUT
