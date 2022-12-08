#!/usr/bin/env sh

echo "*** Setup mysql ***"
echo "MYSQL_ROOT_PASSWORD = ${MYSQL_ROOT_PASSWORD}"
echo "MYSQL_DATABASE = ${MYSQL_DATABASE}"
echo "MYSQL_USER = ${MYSQL_USER}"
echo "MYSQL_PASSWORD = ${MYSQL_PASSWORD}"

[ -d /var/run/mysqld ] || sudo install -m 755 -o mysql -g root -d /var/run/mysqld

echo "* Starting and waiting for mariadb server"
sudo supervisorctl start mariadb-server
while ! nc -v -z -w3 localhost 3306 >/dev/null 2>&1; do
	sleep 1
done

echo "* Create opsi user"
sudo mysql -u root -e "CREATE USER ${MYSQL_USER}@localhost IDENTIFIED BY '${MYSQL_PASSWORD}';"
sudo mysql -u root -e "GRANT ALL PRIVILEGES ON *.* TO ${MYSQL_USER}@localhost IDENTIFIED BY '${MYSQL_PASSWORD}';"
sudo mysql -u root -e "FLUSH PRIVILEGES"

echo "* Create opsi db"
sudo mysql -u root -e "CREATE DATABASE IF NOT EXISTS ${MYSQL_DATABASE};"

echo "* Create opsi test db"
sudo mysql -u root -e "DROP DATABASE IF EXISTS opsitest;"
sudo mysql -u root -e "CREATE DATABASE IF NOT EXISTS opsitest;"

echo "* Fill opsi database with dev data"
echo ${OPSI_HOSTNAME}
zcat /confd-dev-data.sql.gz | sed 's/dev-server.uib.local/'${OPSI_HOSTNAME}'/g' | \
	mariadb -h localhost -u ${MYSQL_USER} --password=${MYSQL_PASSWORD} ${MYSQL_DATABASE}
