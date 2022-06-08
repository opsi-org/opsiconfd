#!/bin/sh
echo "*** Setup grafana ***"

ORG_ID=1
USER_ID=2
echo "GF_SECURITY_ADMIN_USER = ${GF_SECURITY_ADMIN_USER}"
echo "GF_SECURITY_ADMIN_PASSWORD = ${GF_SECURITY_ADMIN_PASSWORD}"
echo "GF_INSTALL_PLUGINS = ${GF_INSTALL_PLUGINS}"

[ -d /var/run/grafana ] || sudo install -m 755 -o grafana -g root -d /var/run/grafana
sudo chmod u+rwX,g+rwX,o+rwX -R /var/lib/grafana

# grafana-cli --homepath "/usr/share/grafana" admin reset-admin-password $GF_SECURITY_ADMIN_PASSWORD

echo "* Stopping grafana server"
sudo supervisorctl stop grafana-server

echo "* Installing grafana plugins"
sudo grafana-cli plugins install $GF_INSTALL_PLUGINS

echo "* Starting and waiting for grafana server"
sudo supervisorctl start grafana-server
while ! nc -v -z -w3 localhost 3000 >/dev/null 2>&1; do
	sleep 1
done

# echo "* Updating grafana admin user"
# curl -XPOST -H "Content-Type: application/json" -d '{
#   "name":"'${GF_SECURITY_ADMIN_USER}'",
#   "email":"'${GF_SECURITY_ADMIN_USER}'@'${GF_SECURITY_ADMIN_USER}'",
#   "login":"'${GF_SECURITY_ADMIN_USER}'",
#   "password":"'${GF_SECURITY_ADMIN_PASSWORD}'",
#   "OrgId": '${ORG_ID}'
# }' http://admin:admin@localhost:3000/api/admin/users
# echo ""

# curl -XPUT -H "Content-Type: application/json" -d '{"isGrafanaAdmin": true}' http://admin:admin@localhost:3000/api/admin/users/$USER_ID/permissions
# echo ""

# curl -XPATCH -H "Content-Type: application/json" -d '{"role":"Admin"}' http://admin:admin@localhost:3000/api/orgs/$ORG_ID/users/$USER_ID
# echo ""
