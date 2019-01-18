#! /bin/bash -e

py.test --junitxml=testreport.xml --cov-report xml --cov=opsiconfd tests/
pylint --rcfile=pylintrc opsiconfd/ > pylint.txt || echo 'pylint did not finish with return code 0'
flake8 --exit-zero --ignore=W191 opsiconfd/ > pep8.txt
