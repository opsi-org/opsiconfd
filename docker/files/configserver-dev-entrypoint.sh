#!/usr/bin/env sh

[ -d /var/run/grafana ] || sudo install -m 755 -o grafana -g root -d /var/run/grafana
sudo chmod u+rwX,g+rwX,o+rwX -R /var/lib/grafana

[ -d /var/run/mysqld ] || sudo install -m 755 -o mysql -g root -d /var/run/mysqld

sed -i s'/^daemonize yes/daemonize no/' /etc/redis/redis.conf

cmd="/usr/bin/supervisord -c /etc/supervisor/configserver-dev-supervisord.conf"

exec $cmd
