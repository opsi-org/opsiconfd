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
* Set OPSILICSRV_TOKEN in docker/opsiconfd-dev/.env if available
* Open project in container:
	* \<F1\> -> Remote-Containers: Reopen in Container
	* or remote button in bottom left corner -> Reopen in Container
* In the container \<F5\> starts opsiconfd in debug mode (opsiconfd default)
* You can use the default debug settings or you can set the number of worker and the log level by selecting opsiconfd in the debug/run tab.

## Run Tests
* Select "Run Tests" on the Status Bar, use the Test Explorer or run `uv run pytest --cov-append --cov opsiconfd --cov-report term --cov-report xml -vv tests` in a terminal


# Performance
## Redis
* Based on the Redis official benchmark, you can improve performance by upto 50% using unix sockets (versus TCP ports) on Redis.
* Check slow queries `SLOWLOG GET`
* Check queries `MONITOR`

## Memory usage / profiling
### py-spy
To analyze high CPU usage of opsiconfd processes py-spy can be very helpful.
```shell
py-spy top --full-filenames --pid <pid-of-opsiconfd-worker-or-manager>
```

### valgrind
```shell
PYTHONMALLOC=malloc sudo -E valgrind --tool=memcheck --trace-children=yes --dsymutil=yes --leak-check=full --show-leak-kinds=all --log-file=/tmp/valgrind-out uv run opsiconfd --workers=1 --log-level-stderr=5
```
* PYTHONMALLOC=debug
* PYTHONMALLOC=malloc_debug

# Segfaults and Core dumps

opsiconfd leverages Python's faulthandler module to output a backtrace to stderr, which is captured by systemd-journald.

Look for `Current thread xxxxxx (most recent call first)`.
Tracebacks starting with `Thread xxxxxx (most recent call first)` are from other running threads.

To obtain and analyze a coredump, follow these steps:

Install systemd-coredump
```shell
apt install systemd-coredump
```

Edit opsiconfd Unit-File
```shell
systemctl edit opsiconfd
```

Add:
```ini
[Service]
LimitCORE=infinity
```

Activate configuration change
```shell
systemctl daemon-reexec
systemctl restart opsiconfd
```

After a segfault run:
```shell
coredumpctl info opsiconfd
```

Analyze in gdb:
```shell
coredumpctl gdb

# or

gdb /usr/lib/opsiconfd/opsiconfd /var/lib/systemd/coredump/core.opsiconfd...

(gdb) bt
(gdb) info registers
(gdb) disassemble $pc-32, $pc+32
```

When Python's faulthandler is enabled, the backtrace will include additional entries after the actual crash, as faulthandler becomes active at that point. To identify the cause of the crash, examine the backtrace entries immediately preceding the faulthandler activation. For example:
```
#0  0x00007f868c46d9fc __pthread_kill_implementation (libc.so.6 + 0x969fc)
#1  0x00007f868c419476 __GI_raise (libc.so.6 + 0x42476)
#2  0x00007f868b22bb61 faulthandler_fatal_error (libpython3.13.so.1.0 + 0x5c4b61)
#3  0x00007f868c419520 __restore_rt (libc.so.6 + 0x42520)
#4  0x00007f868c5747fd __strlen_avx2 (libc.so.6 + 0x19d7fd)
#5  0x00007f868b11ce36 string_at (libpython3.13.so.1.0 + 0x4b5e36)    <<< segfault happend here
...
```

To simulate a segfault:
```shell
kill -s SIGSEGV <pid>
```

## Use Python with Debug Symbols
```shell
* Download a Python debug version from: https://github.com/astral-sh/python-build-standalone/releases/ (for example `cpython-3.13.5+20250702-x86_64-unknown-linux-gnu-debug-full.tar.zst`)
* extract: `tar xf cpython-3.13.5+20250702-x86_64-unknown-linux-gnu-debug-full.tar.zst`
* Build: `uv run --python ./python/install opsi-dev-cli pyinstaller build --skip-transifex --extra-args "--noupx"`
* Check for debug sections: `readelf -S dist/opsiconfd/_internal/libpython3.13.so | grep debug`
```
