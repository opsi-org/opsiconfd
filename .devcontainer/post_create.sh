# Remove mysql.conf to avoid timeout in opsi.opsi.service.server._config.get_host_key
sudo rm -f /etc/opsi/backends/mysql.conf
