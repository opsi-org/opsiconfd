echo "* Running as $(whoami)"

/workspace/scripts/setup-hosts.sh

echo "* Restarting services"
sudo service redis-server restart
sudo service mysql restart
sudo service grafana-server restart

sudo chown -R $DEV_USER /workspace

echo "* Install git hooks"
cd $HOME
git clone https://oauth2:UqZXUJsgG4dBGLBbTjDM@gitlab.uib.gmbh/uib/opsi-git-hooks.git .opsi-git-hooks
cd /workspace
opsi-dev-tool --git-install-hooks

echo "* Setup poetry venv"
cd /workspace
poetry lock --no-update
poetry install --no-interaction --no-ansi
