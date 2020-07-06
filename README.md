# Configuration

The configuration is based on [ConfigArgParse](https://pypi.org/project/ConfigArgParse/).  
Configuration can be done by command line, config file, environment variable, and defaults.  
If a value is specified in more than one way, the folowing order of precedence is applied:  
command line argument > environment variable > config file value > default value

## Internal and external urls
In the communication between services (redis, grafana, opsiconfd, ...) the internal urls are used.
These can be different from the external urls of the services, for example when services are connected via a docker internal network or behind a proxy / load-balancer.

## workers and executor workers
JSON-RPC requests will be executed in a asyncio executor pool, because the opsi backend is not async currently.
Therefore, the maximum of concurrent JSON-RPC requests is limited by the number of workers and the size of the executor pool.  
**max concurrent JSON-RPC-requests = workers * executor-workers**  
If this limit is exceeded, new JSON-RPC requests will have to wait for a free worker.
Thus, long runinng JSON-RPC requests could block other requests.  

# Development
* Install docker and docker compose on your linux machine
* python-opsi has to be in the opsiconfd root directory (links dont work).
* Build und run the docker environment: `./docker/build_and_run.py --type dev`
* Run a bash in the opsiconfd docker container: `docker exec -it docker_opsiconfd_1 bash`
* Start opsiconfd in the opsiconfd container: `poetry run opsiconfd`
* Run local tests: `./tests/run_tests.sh`. Starts tests in docker container docker_opsiconfd_1.
