#!/usr/bin/env sh

echo "*** Setup mysql ***"
echo "MYSQL_ROOT_PASSWORD = ${MYSQL_ROOT_PASSWORD}"
echo "MYSQL_DATABASE = ${MYSQL_DATABASE}"
echo "MYSQL_USER = ${MYSQL_USER}"
echo "MYSQL_PASSWORD = ${MYSQL_PASSWORD}"

sudo service mysql start

echo "* Create opsi user"
sudo mysql -u root -e "CREATE USER ${MYSQL_USER}@localhost IDENTIFIED BY '${MYSQL_PASSWORD}';"
sudo mysql -u root -e "GRANT ALL PRIVILEGES ON *.* TO ${MYSQL_USER}@localhost IDENTIFIED BY '${MYSQL_PASSWORD}';"
sudo mysql -u root -e "FLUSH PRIVILEGES"

echo "* Create opsi db"
sudo mysql -u root -e "CREATE DATABASE ${MYSQL_DATABASE};"

echo "* Create opsi test db"
sudo mysql -u root -e "DROP DATABASE IF EXISTS opsitest;"
sudo mysql -u root -e "CREATE DATABASE opsitest;"

echo "* Fill opsi database with dev data"
echo ${OPSI_HOSTNAME}
zcat /confd-dev-data.sql.gz | sed 's/dev-server.uib.local/'${OPSI_HOSTNAME}'/g' | \
	mariadb -h localhost -u ${MYSQL_USER} --password=${MYSQL_PASSWORD} ${MYSQL_DATABASE}
