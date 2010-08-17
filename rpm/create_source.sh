#!/bin/bash

packagename=$(basename rpm/*.spec .spec)
version=$(head -n1 debian/changelog | cut -d'(' -f2 | cut -d')' -f1 | cut -d'-' -f1)
release=$(head -n1 debian/changelog | cut -d'(' -f2 | cut -d')' -f1 | cut -d'-' -f2)
cwd=$(pwd)
dir=$(dirname ${cwd}/$(dirname $0))
tmpdir=/tmp/${packagename}-${version}

cd $dir

cp rpm/${packagename}.spec /tmp/
cat /tmp/${packagename}.spec \
	| sed "s/^Version:.*/Version:        ${version}/" \
	| sed "s/^Release:.*/Release:        ${release}/" \
	| sed -ne '1,/%changelog/p' \
	> rpm/${packagename}.spec

#cat debian/changelog | sed "s/^${packagename}/* ${packagename}/" >> rpm/${packagename}.spec
rm /tmp/${packagename}.spec

test -e $tmpdir && rm -rf $tmpdir
mkdir $tmpdir
cp -r setup.py opsiconfd data scripts ${tmpdir}/
find ${tmpdir} -iname "*.pyc"   -exec rm "{}" \;
find ${tmpdir} -iname "*.marks" -exec rm "{}" \;
find ${tmpdir} -iname "*~"      -exec rm "{}" \;
find ${tmpdir} -iname "*.svn"   -exec rm -rf "{}" \; 2>/dev/null

cd ${tmpdir}/..
tar cjf /tmp/${packagename}-${version}.tar.bz2 ${packagename}-${version}
rm -rf $tmpdir
echo "Source archive: /tmp/${packagename}-${version}.tar.bz2"
cd $cwd

