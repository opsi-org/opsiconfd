#!/bin/sh
echo OPSICONFD_GRAFANA_EXTERNAL_URL=http://$(hostname -f):3000 > .env
echo OPSI_HOSTNAME=$(hostname -f) >> .env
echo OPSI_DOMAIN=$(hostname -d) >> .env

if [ -z ${USER+x} ]; then
	echo DEV_USER=$DEV_USER >> .env
else
	echo DEV_USER=$USER >> .env
fi

echo JEMALLOC_VERSION=5.2.1 >> .env
echo OPSILICSRV_TOKEN=  >> .env
