#!/bin/sh
echo OPSI_HOSTNAME=$(hostname -f) >> .env
echo OPSI_DOMAIN=$(hostname -d) >> .env

if [ -z ${USER+x} ]; then
	echo DEV_USER=$DEV_USER >> .env
else
	echo DEV_USER=$USER >> .env
fi

echo OPSILICSRV_TOKEN=  >> .env
