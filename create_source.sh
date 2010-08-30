#!/bin/bash

destdir=$1
cwd=$(pwd)
dir=$(dirname ${cwd}/$(dirname $0))
[ "$destdir" = "" ] && destdir=$cwd

packagename=$(basename rpm/*.spec .spec)
version=$(head -n1 debian/changelog | cut -d'(' -f2 | cut -d')' -f1 | cut -d'-' -f1)
release=$(head -n1 debian/changelog | cut -d'(' -f2 | cut -d')' -f1 | cut -d'-' -f2)
tmpdir=/tmp/${packagename}-${version}


cd $dir
rm destdir/${packagename}*.tar.gz  2>/dev/null || true
rm destdir/${packagename}*.dsc     2>/dev/null || true
rm destdir/${packagename}*.spec    2>/dev/null || true

cp rpm/${packagename}.spec /tmp/
cat /tmp/${packagename}.spec \
	| sed "s/^Version:.*/Version:        ${version}/" \
	| sed "s/^Release:.*/Release:        ${release}/" \
	| sed "s/^Source:.*/Source:         ${packagename}_${version}-${release}.tar.gz/" \
	| sed -ne '1,/%changelog/p' \
	> rpm/${packagename}.spec
rm /tmp/${packagename}.spec
cp rpm/${packagename}.spec $destdir/

test -e $tmpdir && rm -rf $tmpdir
mkdir $tmpdir
cp -r debian setup.py opsiconfd data scripts ${tmpdir}/
find ${tmpdir} -iname "*.pyc"   -exec rm "{}" \;
find ${tmpdir} -iname "*.marks" -exec rm "{}" \;
find ${tmpdir} -iname "*~"      -exec rm "{}" \;
find ${tmpdir} -iname "*.svn"   -exec rm -rf "{}" \; 2>/dev/null

cd ${tmpdir}/
dpkg-buildpackage -S
mv ${tmpdir}/../${packagename}_${version}-${release}.tar.gz $destdir/
mv ${tmpdir}/../${packagename}_${version}-${release}.dsc    $destdir/
rm -rf $tmpdir
echo "============================================================================================="
echo "source archive: ${destdir}/${packagename}_${version}-${release}.tar.gz"
echo "dsc file:       ${destdir}/${packagename}_${version}-${release}.dsc"
echo "spec file:      ${destdir}/${packagename}.spec"
echo "============================================================================================="
cd $cwd

