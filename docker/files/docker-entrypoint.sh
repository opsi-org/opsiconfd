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

zcat /opsi.sql.gz | mariadb -h mysql -u opsi --password=opsi opsi

# Evaluating passed command (do not touch):
# shellcheck disable=SC2086
exec $cmd

