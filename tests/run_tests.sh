#!/bin/bash
docker exec -it docker_opsiconfd_1 poetry run pytest -s --cov opsiconfd  /src/tests/test_statistics.py #/src/tests/test_admininterface.py
# docker exec -it docker_opsiconfd_1 poetry run pytest -s --cov opsiconfd /src/tests/test_admininterface.py /src/tests/test_statistics.py
# docker exec -it docker_opsiconfd_1 poetry run pytest --cov opsiconfd /src/tests
#-k 'test_get_rpc_list_request' #'test_admin_interface_index' #>> test
# docker exec -it docker_opsiconfd_1 poetry run pytest -r a --cov opsiconfd /src/tests
# docker exec -it docker_opsiconfd_1 poetry run pytest --disable-warnings /src/tests