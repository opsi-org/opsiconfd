#!/bin/sh
echo OPSICONFD_GRAFANA_EXTERNAL_URL=http://$(hostname -f):3000 > docker/dev.env
echo OPSI_HOSTNAME=$(hostname -f) >> docker/dev.env