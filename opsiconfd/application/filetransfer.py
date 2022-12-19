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
from typing import Tuple
from uuid import UUID, uuid4

import aiofiles  # type: ignore[import]
import msgspec
from fastapi import APIRouter, FastAPI, Request, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse
from starlette.background import BackgroundTask
from werkzeug.http import parse_options_header

from opsiconfd import contextvar_client_session
from opsiconfd.config import FILE_TRANSFER_STORAGE_DIR

filetransfer_router = APIRouter()


def filetransfer_setup(app: FastAPI) -> None:
	app.include_router(filetransfer_router, prefix="/file-transfer")


def prepare_file(filename: str | None = None, content_type: str | None = None) -> Tuple[str, Path]:
	session = contextvar_client_session.get()
	if not session or not session.username:
		raise PermissionError()

	file_id = str(uuid4())
	storage_dir = Path(FILE_TRANSFER_STORAGE_DIR)
	storage_dir.mkdir(exist_ok=True)
	file_path = storage_dir / file_id
	meta_path = file_path.with_suffix(".meta")
	meta_path.write_bytes(
		msgspec.msgpack.encode(
			{
				"created": int(time()),
				"expires": int(time() + 3600),
				"username": session.username,
				"filename": filename,
				"content_type": content_type,
			}
		)
	)
	return file_id, file_path


def delete_file(file_id: UUID) -> None:
	file_path = Path(FILE_TRANSFER_STORAGE_DIR) / str(file_id)
	meta_path = file_path.with_suffix(".meta")
	file_path.unlink(missing_ok=True)
	meta_path.unlink(missing_ok=True)


@filetransfer_router.post("")
@filetransfer_router.post("/")
@filetransfer_router.post("raw")
@filetransfer_router.post("/raw")
async def filetransfer_post_file_raw(request: Request) -> JSONResponse:
	filename = None
	content_disposition = request.headers.get("content-disposition")
	if content_disposition:
		filename = parse_options_header(content_disposition)[1].get("filenname") or filename
	try:
		file_id, file_path = prepare_file(filename=filename, content_type=request.headers.get("content-type") or None)
	except PermissionError:
		return JSONResponse({"error": "Permission denied"}, status_code=status.HTTP_403_FORBIDDEN)

	async with aiofiles.open(file_path, mode="wb") as out_file:
		async for chunk in request.stream():
			await out_file.write(chunk)

	return JSONResponse({"file_id": file_id}, status_code=status.HTTP_201_CREATED)


@filetransfer_router.post("multipart")
@filetransfer_router.post("/multipart")
async def filetransfer_post_file_multipart(file: UploadFile) -> JSONResponse:
	try:
		file_id, file_path = prepare_file(filename=file.filename, content_type=file.content_type)
	except PermissionError:
		return JSONResponse({"error": "Permission denied"}, status_code=status.HTTP_403_FORBIDDEN)

	async with aiofiles.open(file_path, mode="wb") as out_file:
		while chunk := await file.read(1_000_000):
			await out_file.write(chunk)

	return JSONResponse({"file_id": file_id}, status_code=status.HTTP_201_CREATED)


@filetransfer_router.get("{file_id}")
@filetransfer_router.get("/{file_id}")
async def filetransfer_get_file(file_id: UUID, delete: bool = False) -> FileResponse:
	file_path = Path(FILE_TRANSFER_STORAGE_DIR) / str(file_id)
	meta_path = file_path.with_suffix(".meta")
	if not file_path.exists() or not file_path.exists():
		raise ValueError("Invalid file ID")
	meta = msgspec.msgpack.decode(meta_path.read_bytes())
	background = BackgroundTask(delete_file, file_id) if delete else None
	return FileResponse(path=file_path, filename=meta["filename"], media_type=meta["content_type"], background=background)


@filetransfer_router.delete("{file_id}")
@filetransfer_router.delete("/{file_id}")
async def filetransfer_delete_file(file_id: UUID) -> JSONResponse:
	delete_file(file_id)
	return JSONResponse({"file_id": str(file_id)}, status_code=status.HTTP_200_OK)
