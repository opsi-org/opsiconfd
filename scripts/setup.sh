#!/bin/sh

echo 'Set depotserver name in /etc/hosts' 1>&2
# echo "127.0.0.1       localhost bonifax.uib.local" >/tmp/hosts
echo "127.0.0.1       localhost $OPSI_HOSTNAME" >/tmp/hosts
grep -v "127.0.0.1" /etc/hosts >>/tmp/hosts
cp /tmp/hosts /etc/hosts
rm /tmp/hosts


/workspace/scripts/setup-grafana.sh
/workspace/scripts/setup-mysql.sh

mkdir /var/log/opsi
mkdir /var/lib/opsi/workbench
# sudo opsi-backup restore /workspace/opsi_dev_backup.tar.bz2