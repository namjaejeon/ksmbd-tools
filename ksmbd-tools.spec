#
# spec file for package ksmbd-tools
#
# Copyright (c) 2021 SUSE LLC
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.
#
# Please submit bugfixes or comments via https://bugs.opensuse.org/
#

Name:           ksmbd-tools
Version:        3.4.2
Release:        0
Summary:        cifsd/ksmbd kernel server userspace utilities
License:        GPL-2.0-or-later
Group:          System/Filesystems
Url:            https://github.com/cifsd-team/ksmbd-tools
Source:         %{name}-%{version}.tar.bz2

# ksmbd kernel module was only added in kernel 5.15
BuildRequires:  kernel-default >= 5.15
BuildRequires:  glib2-devel
BuildRequires:  libnl3-devel
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:	libtool

Requires(pre):	kernel-default >= 5.15

%description
Set of utilities for creating and managing SMB3 shares for the ksmbd kernel
module.

%prep
%setup -q

%build
./autogen.sh
%configure
make %{?_smp_mflags}

%install
mkdir -p %{buildroot}/%{_sysconfdir}/ksmbd

%make_install
install -m 644 -p smb.conf.example %{buildroot}%{_sysconfdir}/ksmbd

%files
%{_sbindir}/ksmbd.addshare
%{_sbindir}/ksmbd.adduser
%{_sbindir}/ksmbd.control
%{_sbindir}/ksmbd.mountd
%dir %{_sysconfdir}/ksmbd
%config %{_sysconfdir}/ksmbd/smb.conf.example

%changelog
