#!/bin/sh

poetry install
poetry run rm .venv/lib/python3*/site-packages/pydantic/*.so
poetry run rm -r dist build
poetry run pyinstaller \
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
    --hidden-import OPSI.Backend.MySQL \
    run-opsiconfd
mv dist/run-opsiconfd dist/opsiconfd
mv dist/opsiconfd/site-packages/wsgidav dist/opsiconfd/wsgidav

