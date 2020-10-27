#!/bin/bash
docker exec -it docker_opsiconfd_1 poetry run pytest --cov -s opsiconfd /src/tests/test_productOrdering.py
