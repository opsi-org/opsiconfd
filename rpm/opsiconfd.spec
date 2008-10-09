#
# spec file for package opsiconfd
#
# Copyright (c) 2008 uib GmbH.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#

Name:           opsiconfd
Requires:       python-opsi openssl python-twisted python-twisted-web2 python-xml
PreReq:         %insserv_prereq
Url:            http://www.opsi.org
License:        GPL v2 or later
Group:          Productivity/Networking/Opsi
AutoReqProv:    on
Version:        2.0.0.10
Release:        1
Summary:        OPSI configuration service
%define tarname opsiconfd
Source:         %{tarname}-%{version}.tar.bz2
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildArch:      noarch
%{py_requires}

# ===[ description ]================================
%description
This package contains the OPSI configuration service.

# ===[ debug_package ]==============================
%debug_package

# ===[ prep ]=======================================
%prep

# ===[ setup ]======================================
%setup -n %{tarname}-%{version}

# ===[ build ]======================================
%build

# ===[ install ]====================================
%install
mkdir -p $RPM_BUILD_ROOT/usr/sbin
mkdir -p $RPM_BUILD_ROOT/usr/share/opsiconfd/static
mkdir -p $RPM_BUILD_ROOT/etc/opsi
mkdir -p $RPM_BUILD_ROOT/etc/init.d
mkdir -p $RPM_BUILD_ROOT/etc/logrotate.d
mkdir -p $RPM_BUILD_ROOT/var/log/opsi/opsiconfd
install -m 0755 opsiconfd $RPM_BUILD_ROOT/usr/sbin/
install -m 0755 opsiconfd-guard $RPM_BUILD_ROOT/usr/sbin/
install -m 0644 files/opsiconfd.conf $RPM_BUILD_ROOT/etc/opsi/
install -m 0644 debian/opsiconfd.logrotate $RPM_BUILD_ROOT/etc/logrotate.d/opsiconfd
install -m 0755 debian/opsiconfd.init $RPM_BUILD_ROOT/etc/init.d/opsiconfd
install -m 0644 files/index.html $RPM_BUILD_ROOT/usr/share/opsiconfd/static/index.html
install -m 0644 files/opsi_logo.png $RPM_BUILD_ROOT/usr/share/opsiconfd/static/opsi_logo.png
install -m 0644 files/favicon.ico $RPM_BUILD_ROOT/usr/share/opsiconfd/static/favicon.ico
ln -sf ../../etc/init.d/opsiconfd $RPM_BUILD_ROOT/usr/sbin/rcopsiconfd


# ===[ clean ]======================================
%clean
rm -rf $RPM_BUILD_ROOT

# ===[ post ]=======================================
%post
#%{fillup_and_insserv opsiconfd}
insserv opsiconfd

if [ -z "`getent group pcpatch`" ]; then
	groupadd -g 992 pcpatch
fi

if [ -z "`getent passwd opsiconfd`" ]; then
	useradd -u 993 -g 992 -d /var/lib/opsi -s /bin/bash opsiconfd
fi

if [ -z "`getent group opsiadmin`" ]; then
	groupadd opsiadmin
fi

groupmod -A opsiconfd shadow 1>/dev/null 2>/dev/null || true
groupmod -A opsiconfd uucp 1>/dev/null 2>/dev/null || true

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
	echo "emailAddress=$cert_email"	>> /tmp/opsiconfd.cnf
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

# update?
if [ ${FIRST_ARG:-0} -gt 1 ]; then
	if [ -e /var/run/opsiconfd.pid ]; then
		/etc/init.d/opsiconfd restart || true
	fi
else
	/etc/init.d/opsiconfd start || true
fi

# ===[ preun ]======================================
%preun
%stop_on_removal opsiconfd

# ===[ postun ]=====================================
%postun
%restart_on_update opsiconfd
%insserv_cleanup
groupmod -R opsiconfd shadow 1>/dev/null 2>/dev/null || true
groupmod -R opsiconfd uucp 1>/dev/null 2>/dev/null || true
[ -z "`getent passwd opsiconfd`" ] || userdel opsiconfd
rm -f /etc/opsi/opsiconfd.pem  1>/dev/null 2>/dev/null || true

# ===[ files ]======================================
%files
# default attributes
%defattr(-,root,root)

# documentation
#%doc LICENSE README RELNOTES doc

# configfiles
%config(noreplace) /etc/opsi/opsiconfd.conf
%attr(0755,root,root) %config /etc/init.d/opsiconfd
%config /etc/logrotate.d/opsiconfd

# other files
%attr(0755,root,root) /usr/sbin/opsiconfd
%attr(0755,root,root) /usr/sbin/opsiconfd-guard
%attr(0755,root,root) /usr/sbin/rcopsiconfd
/usr/share/opsiconfd/static/index.html
/usr/share/opsiconfd/static/opsi_logo.png
/usr/share/opsiconfd/static/favicon.ico

# directories
%attr(0755,pcpatch,root) %dir /etc/opsi
%attr(0755,root,root) %dir /usr/share/opsiconfd
%attr(0755,root,root) %dir /usr/share/opsiconfd/static
%attr(0750,opsiconfd,pcpatch) %dir /var/log/opsi/opsiconfd

# ===[ changelog ]==================================
%changelog
* Wed Sep 17 2008 - j.schneider@uib.de
- created new package









