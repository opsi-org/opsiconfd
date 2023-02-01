#!/usr/bin/env sh

set -o errexit
set -o nounset

cmd="/usr/bin/supervisord -c /etc/supervisor/opsiconfd-dev-supervisord.conf"

exec $cmd
