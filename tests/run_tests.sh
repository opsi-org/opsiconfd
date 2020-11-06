#!/bin/bash
docker exec -it docker_opsiconfd_1 poetry run pytest -v -s opsiconfd /src/tests