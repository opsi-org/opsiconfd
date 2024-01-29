echo "* Running as $(whoami)"

update-alternatives --set editor /usr/bin/vim.basic

mkdir -p /var/log/opsi
mkdir -p /var/lib/opsi/depot
mkdir -p /var/lib/opsi/public
mkdir -p /var/lib/opsi/repository
mkdir -p /var/lib/opsi/workbench
mkdir -p /var/lib/opsiconfd
mkdir -p /tftpboot
ln -s /workspace/addons /var/lib/opsiconfd/addons

echo "* Fetch a test license"
mkdir -p /etc/opsi/licenses
wget --header="Authorization: Bearer ${OPSILICSRV_TOKEN}" "https://opsi-license-server.uib.gmbh/api/v1/licenses/test?usage=opsiconfd-dev-container" -O /etc/opsi/licenses/test.opsilic || true

echo "* Upgrade opsi-dev-cli"
opsi-dev-cli self upgrade --system || true

opsi-set-rights

echo "* Install git hooks"
cd /workspace
opsi-dev-tool git-hooks --install

echo "* Setup mysql"
#cat <<EOF | mysql -h $MYSQL_HOST -u root --password=${MYSQL_ROOT_PASSWORD}
#CREATE DATABASE IF NOT EXISTS ${MYSQL_DATABASE};
#DROP DATABASE IF EXISTS opsitest;
#CREATE DATABASE IF NOT EXISTS opsitest;
#CREATE USER IF NOT EXISTS ${MYSQL_USER}@'%' IDENTIFIED BY '${MYSQL_PASSWORD}';
#ALTER USER ${MYSQL_USER}@'%' IDENTIFIED BY '${MYSQL_PASSWORD}';
#GRANT ALL PRIVILEGES ON *.* TO ${MYSQL_USER}@'%';
#FLUSH PRIVILEGES;
#EOF
#zcat /confd-dev-data.sql.gz | \
#	sed 's/dev-server.uib.local/'${HOSTNAME}.${DOMAINNAME}'/g' | \
#	mysql -h $MYSQL_HOST -u root --password=${MYSQL_ROOT_PASSWORD} ${MYSQL_DATABASE}

cat <<EOF | mysql -h $MYSQL_HOST -u root --password=${MYSQL_ROOT_PASSWORD}
CREATE DATABASE IF NOT EXISTS ${MYSQL_DATABASE};
CREATE USER IF NOT EXISTS ${MYSQL_USER}@'%' IDENTIFIED BY '${MYSQL_PASSWORD}';
ALTER USER ${MYSQL_USER}@'%' IDENTIFIED BY '${MYSQL_PASSWORD}';
GRANT ALL PRIVILEGES ON *.* TO ${MYSQL_USER}@'%';
FLUSH PRIVILEGES;
EOF

echo "* Setup poetry venv"
cd /workspace
poetry lock --no-update
poetry install --no-interaction --no-ansi

if [ -n "$DEV_USER" ]; then
	echo "* Git config"
	chown -R $DEV_USER /workspace
	su - $DEV_USER -c 'git config --global core.editor "code --wait"'
fi

# Run CMD
exec "$@"
