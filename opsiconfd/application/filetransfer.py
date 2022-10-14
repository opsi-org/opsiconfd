# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
filetransfer
"""

from pathlib import Path
from time import time
from uuid import UUID, uuid4

import aiofiles  # type: ignore[import]
from fastapi import APIRouter, FastAPI, status
from fastapi.requests import Request
from fastapi.responses import FileResponse, JSONResponse
from msgpack import dumps  # type: ignore[import]

from .. import contextvar_client_session

filetransfer_router = APIRouter()

STORAGE_DIR = "/tmp/opsiconfd-file-transfer"


def filetransfer_setup(app: FastAPI) -> None:
	app.include_router(filetransfer_router, prefix="/file-transfer")


# TODO: multipart upload / download
@filetransfer_router.post("")
@filetransfer_router.post("/")
async def post_file(request: Request) -> JSONResponse:
	session = contextvar_client_session.get()
	if not session or not session.user_store or not session.user_store.username:
		return JSONResponse({"error": "Permission denied"}, status_code=status.HTTP_403_FORBIDDEN)

	file_id = str(uuid4())
	storage_dir = Path(STORAGE_DIR)
	storage_dir.mkdir(exist_ok=True)
	file_path = storage_dir / file_id
	meta_path = file_path.with_suffix(".meta")
	meta_path.write_bytes(dumps({"created": time()}))
	async with aiofiles.open(file_path, mode="wb") as file:
		async for chunk in request.stream():
			await file.write(chunk)

	return JSONResponse({"file_id": file_id}, status_code=status.HTTP_201_CREATED)


@filetransfer_router.get("{file_id}")
@filetransfer_router.get("/{file_id}")
async def get_file(file_id: UUID) -> FileResponse:
	file_path = Path(STORAGE_DIR) / str(file_id)
	return FileResponse(str(file_path))


@filetransfer_router.delete("{file_id}")
@filetransfer_router.delete("/{file_id}")
async def delete_file(file_id: UUID) -> JSONResponse:
	file_path = Path(STORAGE_DIR) / str(file_id)
	meta_path = file_path.with_suffix(".meta")
	file_path.unlink(missing_ok=True)
	meta_path.unlink(missing_ok=True)
	return JSONResponse({"file_id": str(file_id)}, status_code=status.HTTP_200_OK)
