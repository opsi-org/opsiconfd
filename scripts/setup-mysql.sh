#!/usr/bin/env sh

echo "setup mysql"
echo $MYSQL_ROOT_PASSWORD
echo $MYSQL_DATABASE
echo $MYSQL_USER
echo $MYSQL_PASSWORD

service mysql start


awk -v var="password" -v new_val=$MYSQL_ROOT_PASSWORD 'BEGIN{FS=OFS="="}match($1, "^\\s*" var "\\s*") {$2=" " new_val}1' /etc/mysql/debian.cnf | sudo tee /etc/mysql/debian.cnf

echo "set mysql root pw"
sudo mysqladmin -u root --password=$MYSQL_OLD_ROOT_PASSWORD password $MYSQL_ROOT_PASSWORD
# mysql -u root --password=$MYSQL_ROOT_PASSWORD  -e "UPDATE mysql.user SET Password=PASSWORD('$MYSQL_ROOT_PASSWORD') WHERE User='root'"
# mysql -u root --password=$MYSQL_ROOT_PASSWORD -e "DELETE FROM mysql.user WHERE User=''"
echo "remove test db"
mysql -u root --password=$MYSQL_ROOT_PASSWORD -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%'"
echo "FLUSH"
mysql -u root --password=$MYSQL_ROOT_PASSWORD -e "FLUSH PRIVILEGES"

echo "create opsi user"
mysql -u root --password=$MYSQL_ROOT_PASSWORD -e "CREATE USER $MYSQL_USER@localhost IDENTIFIED BY '$MYSQL_PASSWORD';"
mysql -u root --password=$MYSQL_ROOT_PASSWORD -e "GRANT ALL PRIVILEGES ON *.* TO $MYSQL_USER@localhost IDENTIFIED BY '$MYSQL_PASSWORD';"
mysql -u root --password=$MYSQL_ROOT_PASSWORD -e "FLUSH PRIVILEGES"
echo "create opsi db"
mysql -u root --password=$MYSQL_ROOT_PASSWORD -e "CREATE DATABASE $MYSQL_DATABASE;"
echo "create opsi test db"
mysql -u root --password=$MYSQL_ROOT_PASSWORD -e "CREATE DATABASE opsitest;"

# echo 'Restore opsi database'
echo $OPSI_HOSTNAME
zcat /confd-dev-data.sql.gz | sed 's/dev-server.uib.local/'$OPSI_HOSTNAME'/g'  | mariadb -h localhost -u $MYSQL_USER --password=$MYSQL_PASSWORD $MYSQL_DATABASE
# zcat /opsi-schema.sql | mariadb -h localhost -u $MYSQL_USER --password=$MYSQL_PASSWORD $MYSQL_DATABASE

service mysql stop