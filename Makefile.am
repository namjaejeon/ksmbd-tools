ACLOCAL_AMFLAGS = -I m4

SUBDIRS = lib mountd adduser addshare control

EXTRA_DIST = include \
             README.md \
             ksmbd-tools.spec \
             smb.conf.5ksmbd.in \
             ksmbdpwd.db.5.in \
             ksmbd.service.in

pkgsysconfdir = $(sysconfdir)/ksmbd
dist_pkgsysconf_DATA = smb.conf.example

man_MANS = smb.conf.5ksmbd ksmbdpwd.db.5
systemdsystemunit_DATA = ksmbd.service
$(man_MANS) $(systemdsystemunit_DATA): %: %.in; @$(in_script) $< >$@

CLEANFILES = $(man_MANS) $(systemdsystemunit_DATA)

AM_DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$${dc_install_base}/$(systemdsystemunitdir)
