#!/bin/sh
#
# On RecursionError (maximum recursion depth exceeded while calling a Python object) set LOG_LEVEL to DEBUG
#

#LOG_LEVEL="INFO"
LOG_LEVEL="DEBUG"

poetry install
poetry run rm .venv/lib/python3*/site-packages/pydantic/*.so
poetry run rm -r dist build
poetry run pyinstaller --log-level=$LOG_LEVEL \
    --hidden-import ipaddress \
    --hidden-import colorsys \
    --hidden-import gunicorn.glogging \
    --hidden-import uvicorn.workers \
    --hidden-import uvicorn.loops \
    --hidden-import uvicorn.loops.auto \
    --hidden-import uvicorn.loops.uvloop \
    --hidden-import uvicorn.lifespan \
    --hidden-import uvicorn.lifespan.on \
    --hidden-import uvicorn.protocols \
    --hidden-import uvicorn.protocols.http \
    --hidden-import uvicorn.protocols.http.h11_impl \
    --hidden-import uvicorn.protocols.http.httptools_impl \
    --hidden-import uvicorn.protocols.websockets \
    --hidden-import uvicorn.protocols.websockets.auto \
    --hidden-import pydantic.color \
    --hidden-import pydantic.validators \
    --hidden-import pydantic.datetime_parse \
    --hidden-import OPSI.Backend.Depotsever \
    --hidden-import OPSI.Backend.DHCPD \
    --hidden-import OPSI.Backend.File \
    --hidden-import OPSI.Backend.HostControl \
    --hidden-import OPSI.Backend.HostControlSafe \
    --hidden-import OPSI.Backend.JSONRPC \
    --hidden-import OPSI.Backend.MySQL \
    --hidden-import OPSI.Backend.OpsiPXEConfd \
    --hidden-import OPSI.Backend.Replicator \
    --hidden-import OPSI.Backend.SQLite \
    run-opsiconfd
mv dist/run-opsiconfd dist/opsiconfd
mv dist/opsiconfd/site-packages/wsgidav dist/opsiconfd/wsgidav

