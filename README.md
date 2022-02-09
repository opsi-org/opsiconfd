![pipeline](https://gitlab.uib.gmbh/uib/opsiconfd/badges/devel/pipeline.svg)
![coverage](https://gitlab.uib.gmbh/uib/opsiconfd/badges/devel/coverage.svg)
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

# Development in Dev Container
* Install Remote-Containers: https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers
* Run task "Create .env file" or run `./scripts/devenv.sh`
* Open project in container:
	* \<F1\> -> Remote-Containers: Reopen in Container
	* or remote button in bottom left corner -> Reopen in Container
* In the container \<F5\> starts opsiconfd in debug mode (opsiconfd default)
* You can use the default debug settings or you can set the number of worker and the log level by selecting opsiconfd in the debug/run tab.

## Run Tests
* Start opsiconfd with `sudo -E poetry run opsiconfd --backend-config-dir tests/opsi-config/backends --dispatch-config-file tests/opsi-config/backendManager/dispatch.conf --addon-dirs tests/data/addons addons --workers=1 --log-level-stderr=5 --jsonrpc-time-to-cache=0`
* Select "Run Tests" on the Status Bar, use the Test Explorer or run `poetry run pytest -vv tests` in a terminal


## Memory usage / profiling
* https://bugs.python.org/issue41699

### valgrind
```
PYTHONMALLOC=malloc sudo -E valgrind --tool=memcheck --trace-children=yes --dsymutil=yes --leak-check=full --show-leak-kinds=all --log-file=/tmp/valgrind-out poetry run opsiconfd --workers=1 --log-level-stderr=5
```
* PYTHONMALLOC=debug
* PYTHONMALLOC=malloc_debug
