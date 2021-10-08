#!/bin/sh

echo 'Setup /etc/hosts' 1>&2
echo "127.0.0.1       $OPSI_HOSTNAME $(hostname) mysql redis grafana localhost" > /tmp/hosts
grep -v "127.0.0.1" /etc/hosts | grep -v $OPSI_HOSTNAME >> /tmp/hosts
cp /tmp/hosts /etc/hosts
rm /tmp/hosts
