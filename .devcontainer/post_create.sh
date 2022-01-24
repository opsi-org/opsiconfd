sudo --preserve-env /workspace/scripts/setup.sh

sudo chown -R $DEV_USER /workspace
sudo -u $DEV_USER poetry config --local virtualenvs.in-project true
