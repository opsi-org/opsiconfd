echo "* Running as $(whoami)"

/workspace/scripts/setup-hosts.sh

echo "* Fetch a test license"
sudo mkdir -p /etc/opsi/licenses
sudo wget --header="Authorization: Bearer ${OPSILICSRV_TOKEN}" "https://opsi-license-server.uib.gmbh/api/v1/licenses/test?usage=opsiconfd-dev-container" -O /etc/opsi/licenses/test.opsilic || true

echo "* Upgrade opsi-dev-cli"
sudo opsi-dev-cli self upgrade --system || true

echo "* Start services"
sudo supervisorctl status redis-server | grep RUNNING >/dev/null || sudo supervisorctl start redis-server
sudo supervisorctl status mariadb-server | grep RUNNING >/dev/null || sudo supervisorctl start mariadb-server
sudo supervisorctl status grafana-server | grep RUNNING >/dev/null || sudo supervisorctl start grafana-server

sudo chown -R $DEV_USER /workspace
sudo opsi-set-rights

echo "* Install git hooks"
cd $HOME
git clone .opsi-git-hooks
cd /workspace
opsi-dev-tool git-hooks --install

echo "* Git config"
git config --global core.editor "code --wait"

echo "* Setup poetry venv"
cd /workspace
poetry lock --no-update
poetry install --no-interaction --no-ansi
