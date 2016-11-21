#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])

# Get version from file VERSION
m4_define([cifssrv_tools_version], m4_esyscmd([sed -n '1p' VERSION | tr -d '\n']))
m4_define([cifssrv_tools_date], m4_esyscmd([sed -n '2p' VERSION | tr -d '\n']))
m4_define([cifssrv_tools_gitdate],
                m4_esyscmd([git log -1 --pretty=format:%ci 2> /dev/null]))

AC_INIT([CIFSSRV tools], [cifssrv_tools_version],
                        [namjae.jeon@protocolfreedom.org])

AC_DEFINE([CIFSSRV_TOOLS_VERSION], "cifssrv_tools_version", [cifssrv-tools version])
AC_DEFINE([CIFSSRV_MAJOR_VERSION], m4_bpatsubst(cifssrv_tools_version,
                                [\([0-9]*\)\(\w\|\W\)*], [\1]),
                                [Major version for cifssrv-tools])
AC_DEFINE([CIFSSRV_MINOR_VERSION], m4_bpatsubst(cifssrv_tools_version,
                                [\([0-9]*\).\([0-9]*\)\(\w\|\W\)*], [\2]),
                                [Minor version for cifssrv-tools])

AC_CHECK_FILE(.git,
        AC_DEFINE([CIFSSRV_TOOLS_DATE],
                "m4_bpatsubst(cifssrv_tools_gitdate,
                [\([0-9-]*\)\(\w\|\W\)*], [\1])",
                [cifssrv-tools date based on Git commits]),
        AC_DEFINE([CIFSSRV_TOOLS_DATE],
                "cifssrv_tools_date",
                [cifssrv-tools date based on Source releases]))

AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign tar-pax dist-xz])

AC_CHECK_HEADERS_ONCE([
	fcntl.h
	stdlib.h
	string.h
	unistd.h
	sys/ioctl.h
])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PATH_PROG([LDCONFIG], [ldconfig],
       [AC_MSG_ERROR([ldconfig not found])],
       [$PATH:/sbin])

# Checks for header files.
AC_CHECK_HEADERS([linux/fs.h fcntl.h stdlib.h string.h \
		sys/ioctl.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_GETMNTENT
AC_CHECK_FUNCS_ONCE([
	memset
])

AS_IF([test "$ac_cv_header_byteswap_h" = "yes"],
      [AC_CHECK_DECLS([bswap_64],,,[#include <byteswap.h>])])

# Install directories
#AC_PREFIX_DEFAULT([/usr])
#AC_SUBST([sbindir], [/sbin])
#AC_SUBST([sysconfdir], [/etc])
#AC_SUBST([localstatedir], [/var])
AC_CONFIG_FILES([
	Makefile
	lib/Makefile
	cifssrvd/Makefile
	cifsadmin/Makefile
	cifsstat/Makefile
])

AC_OUTPUT
