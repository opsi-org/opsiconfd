#!/bin/sh
echo OPSICONFD_GRAFANA_EXTERNAL_URL=http://$(hostname -f):3000 > .env
echo OPSI_HOSTNAME=$(hostname -f) >> .env
echo OPSI_DOMAIN=$(hostname -d) >> .env
echo DEV_USER=$USER >> .env