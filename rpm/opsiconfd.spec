#
# spec file for package opsiconfd
#
# Copyright (c) 2008 uib GmbH.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#

Name:           opsiconfd
BuildRequires:  python-devel python-setuptools openssl dbus-1-python python-opsi >= 3.99 procps
Requires:       python-opsi >= 3.99 openssl python-twisted dbus-1-python psmisc procps
Url:            http://www.opsi.org
License:        GPL v2 or later
Group:          Productivity/Networking/Opsi
AutoReqProv:    on
Version:        3.99.0.1
Release:        1
Summary:        opsi configuration service
%define tarname opsiconfd
Source:         opsiconfd_3.99.0.1-1.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
%if 0%{?sles_version}
Requires:       python-rrdtool
BuildRequires:  python-rrdtool
PreReq:         %insserv_prereq
%else
%if 0%{?suse_version}
Requires:       python-avahi python-rrdtool
BuildRequires:  python-rrdtool
PreReq:         %insserv_prereq
%{py_requires}
%endif
%endif
%if 0%{?centos_version} || 0%{?redhat_version} || 0%{?fedora_version}
BuildArch:      noarch
%endif

%define toplevel_dir %{name}-%{version}

# ===[ description ]================================
%description
This package contains the opsi configuration service.

# ===[ debug_package ]==============================
%debug_package

# ===[ prep ]=======================================
%prep

# ===[ setup ]======================================
%setup -n %{tarname}-%{version}

# ===[ build ]======================================
%build
export CFLAGS="$RPM_OPT_FLAGS"
python setup.py build

# ===[ install ]====================================
%install
%if 0%{?suse_version}
python setup.py install --prefix=%{_prefix} --root=$RPM_BUILD_ROOT --record-rpm=INSTALLED_FILES
%else
python setup.py install --prefix=%{_prefix} --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES
%endif

mkdir -p $RPM_BUILD_ROOT/var/log/opsi/opsiconfd

#mkdir -p $RPM_BUILD_ROOT/usr/share/opsiconfd/static
#mkdir -p $RPM_BUILD_ROOT/etc/opsi
#mkdir -p $RPM_BUILD_ROOT/etc/init.d
#mkdir -p $RPM_BUILD_ROOT/etc/logrotate.d
#
#install -m 0755 opsiconfd $RPM_BUILD_ROOT/usr/sbin/
#install -m 0755 opsiconfd-guard $RPM_BUILD_ROOT/usr/sbin/
#install -m 0644 files/opsiconfd.conf $RPM_BUILD_ROOT/etc/opsi/
#install -m 0644 debian/opsiconfd.logrotate $RPM_BUILD_ROOT/etc/logrotate.d/opsiconfd
#install -m 0755 debian/opsiconfd.init $RPM_BUILD_ROOT/etc/init.d/opsiconfd
#install -m 0644 files/index.html $RPM_BUILD_ROOT/usr/share/opsiconfd/static/index.html
#install -m 0644 files/opsi_logo.png $RPM_BUILD_ROOT/usr/share/opsiconfd/static/opsi_logo.png
#install -m 0644 files/favicon.ico $RPM_BUILD_ROOT/usr/share/opsiconfd/static/favicon.ico

mkdir -p $RPM_BUILD_ROOT/usr/sbin
ln -sf /etc/init.d/opsiconfd $RPM_BUILD_ROOT/usr/sbin/rcopsiconfd

sed -i 's#/etc/init.d$##;s#/etc/logrotate.d$##' INSTALLED_FILES


# ===[ clean ]======================================
%clean
rm -rf $RPM_BUILD_ROOT

# ===[ post ]=======================================
%post
arg0=$1
if [ $arg0 -eq 1 ]; then
	# Install
	#%{fillup_and_insserv opsiconfd}
	%if 0%{?centos_version} || 0%{?redhat_version} || 0%{?fedora_version}
		chkconfig --add opsiconfd
	%else
		insserv opsiconfd || true
	%endif
	
	if [ -z "`getent group pcpatch`" ]; then
		groupadd -g 992 pcpatch
	fi
	
	if [ -z "`getent passwd opsiconfd`" ]; then
		useradd -r -u 993 -g 992 -d /var/lib/opsi -s /bin/bash opsiconfd
	fi
	
	if [ -z "`getent group opsiadmin`" ]; then
		groupadd opsiadmin
	fi
	
	%if 0%{?rhel_version} || 0%{?centos_version}
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
chown -R opsiconfd:pcpatch /var/log/opsi/opsiconfd

if [ $arg0 -eq 1 ]; then
	# Install
	/etc/init.d/opsiconfd start || true
else
	# Upgrade
	if [ -e /var/run/opsiconfd.pid -o -e /var/run/opsiconfd/opsiconfd.pid ]; then
		rm /var/run/opsiconfd.pid 2>/dev/null || true
		/etc/init.d/opsiconfd restart || true
	fi
fi

# ===[ preun ]======================================
%preun
%stop_on_removal opsiconfd

# ===[ postun ]=====================================
%postun
%restart_on_update opsiconfd
if [ $1 -eq 0 ]; then
	%if 0%{?centos_version} || 0%{?redhat_version} || 0%{?fedora_version}
		chkconfig --del opsiconfd
	%else
		%insserv_cleanup
	%endif
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

# documentation
#%doc LICENSE README RELNOTES doc

# configfiles
%config(noreplace) /etc/opsi/opsiconfd.conf
%attr(0755,root,root) %config /etc/init.d/opsiconfd
%config /etc/logrotate.d/opsiconfd

## other files
#%attr(0755,root,root) /usr/sbin/opsiconfd
#%attr(0755,root,root) /usr/sbin/opsiconfd-guard
%attr(0755,root,root) /usr/sbin/rcopsiconfd
#/usr/share/opsiconfd/static/index.html
#/usr/share/opsiconfd/static/opsi_logo.png
#/usr/share/opsiconfd/static/favicon.ico
#
## directories
#%attr(0755,pcpatch,root) %dir /etc/opsi
#%attr(0755,root,root) %dir /usr/share/opsiconfd
#%attr(0755,root,root) %dir /usr/share/opsiconfd/static
%dir /var/log/opsi
%attr(0750,opsiconfd,pcpatch) %dir /var/log/opsi/opsiconfd

%if 0%{?rhel_version} || 0%{?centos_version}
%define python_sitearch %(%{__python} -c 'from distutils import sysconfig; print sysconfig.get_python_lib()')
%{python_sitearch}/opsiconfd/*
%endif

# ===[ changelog ]==================================
%changelog
