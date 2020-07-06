#!/bin/bash
docker exec -it docker_opsiconfd_1 poetry run pytest /src/tests
# docker exec -it docker_opsiconfd_1 poetry run pytest --disable-warnings /src/tests