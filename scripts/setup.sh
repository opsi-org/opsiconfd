#!/bin/sh

echo 'Set depotserver name in /etc/hosts' 1>&2
# echo "127.0.0.1       localhost bonifax.uib.local" >/tmp/hosts
echo "127.0.0.1       localhost $OPSI_HOSTNAME" >/tmp/hosts
grep -v "127.0.0.1" /etc/hosts >>/tmp/hosts
cp /tmp/hosts /etc/hosts
rm /tmp/hosts


/workspace/scripts/setup-grafana.sh
/workspace/scripts/setup-mysql.sh

if [ -n "$JEMALLOC_VERSION" ]; then
	# installing jemalloc
	echo "installing jemalloc"
	cd /tmp
	wget https://github.com/jemalloc/jemalloc/releases/download/$JEMALLOC_VERSION/jemalloc-$JEMALLOC_VERSION.tar.bz2
	tar xvjf jemalloc-$JEMALLOC_VERSION.tar.bz2
	cd jemalloc-$JEMALLOC_VERSION
	./configure
	make
	sudo make install
fi

mkdir /var/log/opsi
mkdir /var/lib/opsi/workbench
# sudo opsi-backup restore /workspace/opsi_dev_backup.tar.bz2