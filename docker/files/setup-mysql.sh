#!/usr/bin/env sh

echo "setup mysql"
echo $MYSQL_ROOT_PASSWORD
echo $MYSQL_DATABASE
echo $MYSQL_USER
echo $MYSQL_PASSWORD

service mysql start

# apt-get -y install expect

# SECURE_MYSQL=$(expect -c "
# set timeout 10
# spawn mysql_secure_installation
# expect \"Enter current password for root (enter for none):\"
# send \"$MYSQL_OLD_ROOT_PASSWORD\r\"
# expect \"Change the root password?\"
# send \"y\r\"
# expect \"New password:\"
# send \"$MYSQL_ROOT_PASSWORD\r\"
# expect \"Re-enter new password:\"
# send \"$MYSQL_ROOT_PASSWORD\r\"
# expect \"Remove anonymous users?\"
# send \"y\r\"
# expect \"Disallow root login remotely?\"
# send \"y\r\"
# expect \"Remove test database and access to it?\"
# send \"y\r\"
# expect \"Reload privilege tables now?\"
# send \"y\r\"
# expect eof
# ")

# echo "$SECURE_MYSQL"

# apt-get -y purge expect

echo "set mysql root pw"
sudo mysqladmin -u root --password=$MYSQL_OLD_ROOT_PASSWORD password $MYSQL_ROOT_PASSWORD
mysql -u root --password=$MYSQL_ROOT_PASSWORD -e "UPDATE mysql.user SET Password=PASSWORD('$MYSQL_ROOT_PASSWORD') WHERE User='root'"
# mysql -u root --password=$MYSQL_ROOT_PASSWORD -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')"
mysql -u root --password=$MYSQL_ROOT_PASSWORD -e "DELETE FROM mysql.user WHERE User=''"
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

echo 'Restore opsi database' 
echo $OPSI_HOSTNAME
zcat /opsi.sql.gz | sed 's/bonifax.uib.local/'$OPSI_HOSTNAME'/g'  | mariadb -h localhost -u opsi --password=opsi opsi

service mysql stop