#
# spec file for package opsiconfd
#
# Copyright (c) 2008-2017 uib GmbH.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#

Name:           opsiconfd
BuildRequires:  python-devel python-setuptools openssl procps systemd
Requires:       python-opsi >= 4.1.1.1
%if 0%{?suse_version} >= 1210
BuildRequires: systemd-rpm-macros
%endif
BuildArch:      noarch
Requires:       openssl
Requires:       python-twisted
Requires:       psmisc
Requires:       procps
Requires:       logrotate
%{?systemd_requires}
Url:            http://www.opsi.org
License:        AGPL-3.0+
Group:          Productivity/Networking/Opsi
AutoReqProv:    on
Version:        4.1.1.4
Release:        2
Summary:        This is the opsi configuration service
Source:         opsiconfd_4.1.1.4-1.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
%if 0%{?suse_version} == 1110 || 0%{?suse_version} == 1315
# SLES
Requires:       pkg-config
BuildRequires:  python-opsi >= 4.1.1.1 zypper logrotate
BuildRequires:  pkg-config
Suggests:       python-rrdtool
%{py_requires}
%else
%if 0%{?suse_version}
Suggests: logrotate
Requires:       pkg-config
BuildRequires:  pkg-config
BuildRequires:  python-rrdtool zypper logrotate
%{py_requires}
%else
Requires:       pkgconfig
%endif
%endif

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
%if 0%{?rhel_version} >= 700 || 0%{?centos_version} >= 700
# Fix for https://bugzilla.redhat.com/show_bug.cgi?id=1117878
export PATH="/usr/bin:$PATH"
%endif
export CFLAGS="$RPM_OPT_FLAGS"
python setup.py build

%pre
%if 0%{?suse_version}
%service_add_pre opsiconfd.service
%endif

# ===[ install ]====================================
%install

%if 0%{?suse_version}
python setup.py install --prefix=%{_prefix} --root=$RPM_BUILD_ROOT --record-rpm=INSTALLED_FILES
%else
python setup.py install --prefix=%{_prefix} --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES
%endif

mkdir -p $RPM_BUILD_ROOT/var/log/opsi/opsiconfd

sed -i 's#/etc/logrotate.d$##' INSTALLED_FILES

%if 0%{?rhel_version} || 0%{?centos_version} || 0%{?fedora_version}
	echo "Detected RHEL / CentOS / Fedora"
	%if 0%{?rhel_version} == 600 || 0%{?centos_version} == 600
		echo "Fixing logrotate configuration"
		LOGROTATE_TEMP=$RPM_BUILD_ROOT/opsi-logrotate_config.temp
		LOGROTATE_CONFIG=$RPM_BUILD_ROOT/etc/logrotate.d/opsiconfd
		grep -v "su opsiconfd opsiadmin" $LOGROTATE_CONFIG > $LOGROTATE_TEMP
		mv $LOGROTATE_TEMP $LOGROTATE_CONFIG
	%endif
%endif

# Patching systemd service file
%if 0%{?suse_version} >= 1315 || 0%{?centos_version} >= 700 || 0%{?rhel_version} >= 700
	# Adjusting to the correct service names
	sed --in-place "s/=smbd.service/=smb.service/" "debian/opsiconfd.service" || true
	sed --in-place "s/=isc-dhcp-server.service/=dhcpd.service/" "debian/opsiconfd.service" || true
%endif

%if 0%{?suse_version} || 0%{?centos_version} || 0%{?rhel_version}
	MKDIR_PATH=$(which mkdir)
	CHOWN_PATH=$(which chown)
	sed --in-place "s!=-/bin/mkdir!=-$MKDIR_PATH!" "debian/opsiconfd.service" || True
	sed --in-place "s!=-/bin/chown!=-$CHOWN_PATH!" "debian/opsiconfd.service" || True
%endif

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

if [ $arg0 -eq 1 ]; then
	# Install
	if [ $fileadmingroup != pcpatch -a -z "$(getent group $fileadmingroup)" ]; then
		groupmod -n $fileadmingroup pcpatch
	else
		if [ -z "$(getent group $fileadmingroup)" ]; then
			groupadd $fileadmingroup
		fi
	fi

	if [ -z "`getent passwd opsiconfd`" ]; then
		useradd --system -g $fileadmingroup -d /var/lib/opsi -s /bin/bash opsiconfd
	fi

	if [ -z "`getent group opsiadmin`" ]; then
		groupadd opsiadmin
	fi

	%if 0%{?rhel_version} || 0%{?centos_version} || 0%{?fedora_version} || 0%{?suse_version} >= 1230
		getent group shadow > /dev/null || groupadd -r shadow
		chgrp shadow /etc/shadow
		chmod g+r /etc/shadow
		usermod -a -G shadow opsiconfd 1>/dev/null 2>/dev/null || true
		usermod -a -G opsiadmin opsiconfd 1>/dev/null 2>/dev/null || true
	%else
		groupmod -A opsiconfd shadow 1>/dev/null 2>/dev/null || true
		groupmod -A opsiconfd uucp 1>/dev/null 2>/dev/null || true
		groupmod -A opsiconfd opsiadmin 1>/dev/null 2>/dev/null || true
	%endif
fi

if [ ! -e "/etc/opsi/opsiconfd.pem" ]; then
	umask 077

	cert_country="DE"
	cert_state="RP"
	cert_locality="Mainz"
	cert_organization="uib GmbH"
	cert_commonname=`hostname -f`
	cert_email="root@$cert_commonname"

	echo "RANDFILE = /tmp/opsiconfd.rand" 	>  /tmp/opsiconfd.cnf
	echo "" 				>> /tmp/opsiconfd.cnf
	echo "[ req ]" 				>> /tmp/opsiconfd.cnf
	echo "default_bits = 1024" 		>> /tmp/opsiconfd.cnf
	echo "encrypt_key = yes" 		>> /tmp/opsiconfd.cnf
	echo "distinguished_name = req_dn" 	>> /tmp/opsiconfd.cnf
	echo "x509_extensions = cert_type" 	>> /tmp/opsiconfd.cnf
	echo "prompt = no" 			>> /tmp/opsiconfd.cnf
	echo "" 				>> /tmp/opsiconfd.cnf
	echo "[ req_dn ]" 			>> /tmp/opsiconfd.cnf
	echo "C=$cert_country"			>> /tmp/opsiconfd.cnf
	echo "ST=$cert_state" 			>> /tmp/opsiconfd.cnf
	echo "L=$cert_locality" 		>> /tmp/opsiconfd.cnf
	echo "O=$cert_organization" 		>> /tmp/opsiconfd.cnf
	#echo "OU=$cert_unit" 			>> /tmp/opsiconfd.cnf
	echo "CN=$cert_commonname" 		>> /tmp/opsiconfd.cnf
	echo "emailAddress=$cert_email"		>> /tmp/opsiconfd.cnf
	echo "" 				>> /tmp/opsiconfd.cnf
	echo "[ cert_type ]" 			>> /tmp/opsiconfd.cnf
	echo "nsCertType = server" 		>> /tmp/opsiconfd.cnf

	dd if=/dev/urandom of=/tmp/opsiconfd.rand count=1 2>/dev/null
	openssl req -new -x509 -days 1000 -nodes \
		-config /tmp/opsiconfd.cnf -out /etc/opsi/opsiconfd.pem -keyout /etc/opsi/opsiconfd.pem
	openssl gendh -rand /tmp/opsiconfd.rand 512 >>/etc/opsi/opsiconfd.pem
	openssl x509 -subject -dates -fingerprint -noout -in /etc/opsi/opsiconfd.pem
	rm -f /tmp/opsiconfd.rand /tmp/opsiconfd.cnf
fi

chmod 600 /etc/opsi/opsiconfd.pem
chown opsiconfd:opsiadmin /etc/opsi/opsiconfd.pem || true
chmod 750 /var/log/opsi/opsiconfd
chown -R opsiconfd:$fileadmingroup /var/log/opsi/opsiconfd

%if 0%{?rhel_version} || 0%{?centos_version}
%systemd_post opsiconfd.service
%else
%service_add_post opsiconfd.service
%endif

systemctl=`which systemctl 2>/dev/null` || true
if [ ! -z "$systemctl" -a -x "$systemctl" ]; then
	$systemctl enable opsiconfd.service && echo "Enabled opsiconfd.service" || echo "Enabling opsiconfd.service failed!"

	if [ $arg0 -eq 1 ]; then
		# Install
		$systemctl start opsiconfd.service || true
	else
		# Upgrade
		$systemctl restart opsiconfd.service || true
	fi
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

if [ $1 -eq 0 ]; then
	%if 0%{?suse_version}
		groupmod -R opsiconfd shadow 1>/dev/null 2>/dev/null || true
		groupmod -R opsiconfd uucp 1>/dev/null 2>/dev/null || true
	%endif
	[ -z "`getent passwd opsiconfd`" ] || userdel opsiconfd
	rm -f /etc/opsi/opsiconfd.pem  1>/dev/null 2>/dev/null || true
fi

# ===[ files ]======================================
%files -f INSTALLED_FILES
# default attributes
%defattr(-,root,root)

%{_unitdir}/opsiconfd.service

# configfiles
%config(noreplace) /etc/opsi/opsiconfd.conf
%config /etc/logrotate.d/opsiconfd

## directories
%dir /var/log/opsi

%attr(0750,opsiconfd,root) %dir /var/log/opsi/opsiconfd

%if 0%{?rhel_version} || 0%{?centos_version} || 0%{?fedora_version}
%define python_sitearch %(%{__python} -c 'from distutils import sysconfig; print sysconfig.get_python_lib()')
%{python_sitearch}/opsiconfd/*
%endif

# ===[ changelog ]==================================
%changelog
