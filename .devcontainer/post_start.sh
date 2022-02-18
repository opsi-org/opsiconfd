echo "* Running as $(whoami)"

/workspace/scripts/setup-hosts.sh

echo "* Fetch a test license"
sudo mkdir -p /etc/opsi/licenses
sudo wget --header="Authorization: Bearer ${OPSILICSRV_TOKEN}" "https://opsi-license-server.uib.gmbh/api/v1/licenses/test?usage=opsiconfd-dev-container" -O /etc/opsi/licenses/test.opsilic || true

echo "* Upgrade opsi-dev-tool"
sudo opsi-dev-tool --self-upgrade || true

echo "* Restarting services"
sudo service redis-server restart
sudo service mysql restart
sudo service grafana-server restart

sudo chown -R $DEV_USER /workspace
sudo opsi-set-rights

echo "* Install git hooks"
cd $HOME
git clone https://oauth2:UqZXUJsgG4dBGLBbTjDM@gitlab.uib.gmbh/uib/opsi-git-hooks.git .opsi-git-hooks
cd /workspace
opsi-dev-tool git-hooks --install

echo "* Setup poetry venv"
cd /workspace
poetry lock --no-update
poetry install --no-interaction --no-ansi
