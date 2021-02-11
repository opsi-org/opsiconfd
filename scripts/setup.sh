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

echo "install opsi-dev-tools"
pip3 install --trusted-host pypi.uib.gmbh --index-url http://pypi.uib.gmbh:8080/simple opsi-dev-tools

echo "install git hooks"
cd $HOME
git clone https://oauth2:UqZXUJsgG4dBGLBbTjDM@gitlab.uib.gmbh/uib/opsi-git-hooks.git .opsi-git-hooks
cd /workspace
opsi-dev-tool --git-install-hooks


mkdir /var/log/opsi
mkdir /var/lib/opsi/workbench
# sudo opsi-backup restore /workspace/opsi_dev_backup.tar.bz2