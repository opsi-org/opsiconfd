#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import glob
import codecs
import shutil
import platform
import subprocess

HIDDEN_IMPORTS = [
	"ipaddress",
	"colorsys",
	"gunicorn.glogging",
	"uvicorn.workers",
	"uvicorn.loops",
	"uvicorn.loops.auto",
	"uvicorn.loops.uvloop",
	"uvicorn.lifespan",
	"uvicorn.lifespan.on",
	"uvicorn.protocols",
	"uvicorn.protocols.http",
	"uvicorn.protocols.http.h11_impl",
	"uvicorn.protocols.http.httptools_impl",
	"uvicorn.protocols.websockets",
	"uvicorn.protocols.websockets.auto",
	"pydantic.color",
	"pydantic.validators",
	"pydantic.datetime_parse",
	"OPSI.Backend.Depotsever",
	"OPSI.Backend.DHCPD",
	"OPSI.Backend.File",
	"OPSI.Backend.HostControl",
	"OPSI.Backend.HostControlSafe",
	"OPSI.Backend.JSONRPC",
	"OPSI.Backend.MySQL",
	"OPSI.Backend.OpsiPXEConfd",
	"OPSI.Backend.Replicator",
	"OPSI.Backend.SQLite"
]
os.chdir(os.path.dirname(os.path.abspath(__file__)))

subprocess.check_call(["poetry", "install"])
subprocess.check_call(["poetry", "run", "rm", ".venv/lib/python3*/site-packages/pydantic/*.so"])

for d in ("dist", "build"):
	if os.path.isdir(d):
		shutil.rmtree(d)
	
cmd = ["poetry", "run", "pyinstaller", "--log-level", "INFO"]
for hi in HIDDEN_IMPORTS:
	cmd.extend(["--hidden-import", hi])
cmd.append("run-opsiconfd")
subprocess.check_call(cmd)

shutil.move("dist/run-opsiconfd", "dist/opsiconfd")
shutil.move("dist/opsiconfd/run-opsiconfd", "dist/opsiconfd/opsiconfd")
shutil.move("dist/opsiconfd/site-packages/wsgidav", "dist/opsiconfd/wsgidav")
