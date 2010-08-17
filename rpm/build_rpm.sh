#!/bin/bash

topdir=/usr/src/packages
builddir=${topdir}/BUILD
rpmdir=${topdir}/RPMS
sourcedir=${topdir}/SOURCES
specdir=${topdir}/SPECS
srcrpmdir=${topdir}/SRPMS
packagename=$(basename rpm/*.spec .spec)
version=$(grep -i ^Version  rpm/${packagename}.spec | awk '{ print $2 }')
tmpdir=/tmp/${packagename}-${version}
cwd=$(pwd)
dir=$(dirname ${cwd}/$(dirname $0))

test -e $specdir || mkdir -p $specdir
test -e $sourcedir || mkdir -p $sourcedir
test -e $buildroot && rm -rf $buildroot

cd $dir
bash rpm/create_source.sh
mv /tmp/${packagename}-${version}.tar.bz2 ${sourcedir}/
cp rpm/${packagename}.spec $specdir/
rpmbuild -ba $specdir/${packagename}.spec
cd $cwd

