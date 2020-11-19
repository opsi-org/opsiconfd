#!/bin/sh
echo "setup grafana"
echo $GF_SECURITY_ADMIN_USER
echo $GF_SECURITY_ADMIN_PASSWORD
echo $GF_INSTALL_PLUGINS

ORG_ID=1
USER_ID=2

# service grafana-server start

# grafana-cli --homepath "/usr/share/grafana" admin reset-admin-password $GF_SECURITY_ADMIN_PASSWORD
service grafana-server start
curl -XPOST -H "Content-Type: application/json" -d '{
  "name":"'$GF_SECURITY_ADMIN_USER'",
  "email":"'$GF_SECURITY_ADMIN_USER'@'$GF_SECURITY_ADMIN_USER'",
  "login":"'$GF_SECURITY_ADMIN_USER'",
  "password":"'$GF_SECURITY_ADMIN_PASSWORD'",
  "OrgId": '$ORG_ID'
}' http://admin:admin@localhost:3000/api/admin/users


curl -XPUT -H "Content-Type: application/json" -d '{"isGrafanaAdmin": true}' http://admin:admin@localhost:3000/api/admin/users/$USER_ID/permissions
curl -XPATCH -H "Content-Type: application/json" -d '{"role":"Admin"}' http://admin:admin@localhost:3000/api/orgs/$ORG_ID/users/$USER_ID
grafana-cli plugins install $GF_INSTALL_PLUGINS

service grafana-server stop