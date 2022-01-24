sudo --preserve-env /workspace/scripts/setup-hosts.sh
sudo service redis-server restart
sudo service mysql restart
sudo service grafana-server restart

sudo chown -R $DEV_USER /workspace
sudo -u $DEV_USER poetry lock --no-update
sudo -u $DEV_USER poetry install --no-interaction --no-ansi
