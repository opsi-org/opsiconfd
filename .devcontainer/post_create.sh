echo "* Running as $(whoami)"

sudo update-alternatives --set editor /usr/bin/vim.basic

sudo mkdir -p /var/log/opsi
sudo mkdir -p /var/lib/opsi/depot
sudo mkdir -p /var/lib/opsi/public
sudo mkdir -p /var/lib/opsi/repository
sudo mkdir -p /var/lib/opsi/workbench
sudo mkdir -p /var/lib/opsiconfd
sudo mkdir -p /tftpboot
sudo ln -s /workspace/addons /var/lib/opsiconfd/addons

sudo chown -R $DEV_USER /workspace
