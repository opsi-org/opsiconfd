sudo -E poetry run opsiconfd --workers=1 --log-level-stderr=5
sudo -E poetry run opsiconfd --backend-config-dir tests/opsi-config/backends --dispatch-config-file tests/opsi-config/backendManager/dispatch.conf --workers=1 --log-level-stderr=5
poetry run pytest -vv tests/test_config.py -k test_cmdline -s
poetry run pytest -vv tests
