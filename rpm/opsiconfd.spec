#
# spec file for package opsiconfd
#
# Copyright (c) 2008-2019 uib GmbH.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#

Name:           opsiconfd
BuildRequires:  systemd
%if 0%{?suse_version}
BuildRequires:  logrotate
BuildRequires:  systemd-rpm-macros
BuildRequires:  zypper
%endif
BuildArch:      noarch
Requires:       opsiconfd-common
Requires:       opsigateway
Requires:       opsiwebservice
Requires:       logrotate
%{?systemd_requires}
Url:            http://www.opsi.org
License:        AGPL-3.0+
Group:          Productivity/Networking/Opsi
AutoReqProv:    on
Version:        4.2.0.1
Release:        1
Summary:        This is the opsi configuration service
Source:         opsiconfd_4.2.0.1-1.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%define tarname opsiconfd
%define fileadmingroup %(grep "fileadmingroup" /etc/opsi/opsi.conf | cut -d "=" -f 2 | sed 's/\s*//g')
%define toplevel_dir %{name}-%{version}

# ===[ description ]================================
%description
This package contains the opsi configuration service.

# ===[ prep ]=======================================
%prep

# ===[ setup ]======================================
%setup -n %{tarname}-%{version}

# ===[ build ]======================================
%build

# ===[ pre ]========================================
%pre
%if 0%{?suse_version}
%service_add_pre opsiconfd.service
%endif

# ===[ install ]====================================
%install

mkdir -p $RPM_BUILD_ROOT/var/log/opsi/opsiconfd

# Adjusting to the correct service names
sed --in-place "s/=smbd.service/=smb.service/" "debian/opsiconfd.service" || true
sed --in-place "s/=isc-dhcp-server.service/=dhcpd.service/" "debian/opsiconfd.service" || true

install -D -m 644 debian/opsiconfd.service %{buildroot}%{_unitdir}/opsiconfd.service

# ===[ clean ]======================================
%clean
rm -rf $RPM_BUILD_ROOT

# ===[ post ]=======================================
%post
arg0=$1

fileadmingroup=$(grep "fileadmingroup" /etc/opsi/opsi.conf | cut -d "=" -f 2 | sed 's/\s*//g')
if [ -z "$fileadmingroup" ]; then
	fileadmingroup=pcpatch
fi

chmod 750 /var/log/opsi/opsiconfd
chown -R opsiconfd:$fileadmingroup /var/log/opsi/opsiconfd

%if 0%{?rhel_version} || 0%{?centos_version}
%systemd_post opsiconfd.service
%else
%service_add_post opsiconfd.service
%endif

systemctl=`which systemctl`
$systemctl enable opsiconfd.service && echo "Enabled opsiconfd.service" || echo "Enabling opsiconfd.service failed!"

if [ "$arg0" -eq 1 ]; then
	# Install
	$systemctl start opsiconfd.service || true
else
	# Upgrade
	$systemctl restart opsiconfd.service || true
fi

# ===[ preun ]======================================
%preun
%if 0%{?rhel_version} || 0%{?centos_version}
%systemd_preun opsiconfd.service
%else
%service_del_preun opsiconfd.service
%endif

# ===[ postun ]=====================================
%postun
%if 0%{?rhel_version} || 0%{?centos_version}
%systemd_postun opsiconfd.service
%else
%service_del_postun opsiconfd.service
%endif

# ===[ files ]======================================
%files
# default attributes
%defattr(-,root,root)

%{_unitdir}/opsiconfd.service

# configfiles
%config /etc/logrotate.d/opsiconfd

## directories
%dir /var/log/opsi
%attr(0750,opsiconfd,root) %dir /var/log/opsi/opsiconfd

# ===[ changelog ]==================================
%changelog
