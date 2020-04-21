#!/usr/bin/env sh

set -o errexit
set -o nounset

cmd="$*"

mysql_ready () {
	# Check that mysql is up and running:
	dockerize -wait 'tcp://mysql:3306' -timeout 5s
}

redis_ready () {
	# Check that redis is up and running:
	dockerize -wait 'tcp://redis:6379' -timeout 5s
}

until mysql_ready; do
	echo 'Waiting for MySQL...' 1>&2
done
echo 'MySQL is ready.' 1>&2

until redis_ready; do
	echo 'Waiting for Redis...' 1>&2
done
echo 'Redis is ready.' 1>&2

echo 'Restore opsi database' 1>&2
zcat /opsi.sql.gz | mariadb -h mysql -u opsi --password=opsi opsi

echo 'Set depotserver name in /etc/hosts' 1>&2
echo "127.0.0.1       localhost bonifax.uib.local" >/tmp/hosts
grep -v "127.0.0.1" /etc/hosts >>/tmp/hosts
cp /tmp/hosts /etc/hosts
rm /tmp/hosts

# Evaluating passed command (do not touch):
# shellcheck disable=SC2086
exec $cmd
