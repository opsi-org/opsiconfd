#!/bin/bash
docker exec -it docker_opsiconfd_1 poetry run pytest --cov opsiconfd /src/tests
