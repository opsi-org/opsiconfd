poetry run pytest --tb=short -o junit_family=xunit2 --junitxml=testreport.xml --cov-append --cov opsiconfd --cov-report term --cov-report xml -v tests
poetry run pytest --tb=short --log-cli-level=90 -vv tests/test_config.py -k test_cmdline -s
poetry run pytest --tb=short --log-cli-level=90 -vv tests
sudo -E poetry run opsiconfd --config-file tests/data/default-opsiconfd.conf --log-level-stderr=5 --max-session-per-ip=20000
sudo -E poetry run opsiconfd --zeroconf=false --workers=1 --log-level-stderr=5
