#!/bin/sh

echo "* Running as $(whoami)"

cd /workspace

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

if [ -n "$DEV_USER" ]; then
	if [ -z "$SSH_AUTH_SOCK" ]; then
		VSCODE_AUTH_SOCK=$(ls -t /tmp/vscode-ssh-auth-*.sock 2> /dev/null | head -n1)
		[ -n "$VSCODE_AUTH_SOCK" ] && export SSH_AUTH_SOCK=$VSCODE_AUTH_SOCK
	fi
	ssh-add -L

	echo "* Git config"
	chown -R $DEV_USER /workspace
	su - $DEV_USER -c 'git config --global core.editor "code --wait"'

	echo "* Install git hooks"
	su - $DEV_USER -c 'opsi-dev-tool git-hooks --install'
fi

#echo "* Setup poetry venv"
#poetry lock --no-update
#poetry install --no-interaction --no-ansi
#[ -n "$DEV_USER" ] && chown -R $DEV_USER /workspace

# Run CMD
exec "$@"
