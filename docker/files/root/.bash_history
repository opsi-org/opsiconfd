poetry run pytest --tb=short -o junit_family=xunit2 --junitxml=testreport.xml --cov-append --cov opsiconfd --cov-report term --cov-report xml -v tests
poetry run pytest -vv tests/test_config.py -k test_cmdline -s
poetry run pytest -vv tests
sudo -E poetry run opsiconfd --backend-config-dir=tests/opsi-config/backends --dispatch-config-file=tests/opsi-config/backendManager/dispatch.conf --addon-dirs=tests/data/addons --max-sessions-excludes="" --jsonrpc-time-to-cache=0 --workers=1 --log-level-stderr=5
sudo -E poetry run opsiconfd --workers=1 --log-level-stderr=5
