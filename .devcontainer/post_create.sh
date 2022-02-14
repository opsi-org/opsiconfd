echo "* Running as $(whoami)"

function install_jemalloc {
	echo "* Installing jemalloc"
	cd /tmp
	wget https://github.com/jemalloc/jemalloc/releases/download/$JEMALLOC_VERSION/jemalloc-$JEMALLOC_VERSION.tar.bz2
	tar xvjf jemalloc-$JEMALLOC_VERSION.tar.bz2
	cd jemalloc-$JEMALLOC_VERSION
	./configure
	make
	sudo make install
}

/workspace/scripts/setup-hosts.sh
/workspace/scripts/setup-grafana.sh
/workspace/scripts/setup-mysql.sh

# [ -n "$JEMALLOC_VERSION" ] && install_jemalloc

sudo mkdir -p /var/log/opsi
sudo mkdir -p /var/lib/opsi/depot
sudo mkdir -p /var/lib/opsi/public
sudo mkdir -p /var/lib/opsi/repository
sudo mkdir -p /var/lib/opsi/workbench
sudo mkdir -p /var/lib/opsiconfd
sudo mkdir -p /tftpboot
sudo ln -s /workspace/addons /var/lib/opsiconfd/addons

sudo chown -R $DEV_USER /workspace
