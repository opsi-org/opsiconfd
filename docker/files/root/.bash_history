poetry run pytest --tb=short -o junit_family=xunit2 --junitxml=testreport.xml --cov-append --cov opsiconfd --cov-report term --cov-report xml -v tests
poetry run pytest --tb=short -vv tests/test_config.py -k test_cmdline -s
poetry run pytest --tb=short -vv tests
sudo -E poetry run opsiconfd --config-file tests/data/default-opsiconfd.conf --log-level-stderr=5
sudo -E poetry run opsiconfd --workers=1 --log-level-stderr=5
