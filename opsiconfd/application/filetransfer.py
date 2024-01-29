# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
filetransfer
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import aiofiles  # type: ignore[import]
from fastapi import APIRouter, FastAPI, Request, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse
from starlette.background import BackgroundTask
from werkzeug.http import parse_options_header

from opsiconfd import contextvar_client_session
from opsiconfd.config import FILE_TRANSFER_STORAGE_DIR
from opsiconfd.logging import logger
from opsiconfd.utils import utc_time_timestamp
from pydantic import BaseModel

if TYPE_CHECKING:
	from opsiconfd.session import OPSISession


filetransfer_router = APIRouter()


def filetransfer_setup(app: FastAPI) -> None:
	app.include_router(filetransfer_router, prefix="/file-transfer")


class FileMetaData(BaseModel):
	file_id: str
	created: int
	expires: int
	filename: str | None
	content_type: str | None
	username: str | None

	@property
	def file_path(self) -> Path:
		return Path(FILE_TRANSFER_STORAGE_DIR) / self.file_id

	@property
	def meta_path(self) -> Path:
		return Path(FILE_TRANSFER_STORAGE_DIR) / (self.file_id + ".meta")

	@staticmethod
	def read_meta(meta_path: Path) -> FileMetaData:
		return FileMetaData.model_validate_json(meta_path.read_bytes())

	def write_meta(self) -> None:
		self.meta_path.write_text(self.model_dump_json(), encoding="utf-8")


def _prepare_file(
	filename: str | None = None, content_type: str | None = None, validity: int = 24 * 3600, session: OPSISession | None = None
) -> FileMetaData:
	now = int(utc_time_timestamp())
	file_meta = FileMetaData(
		file_id=str(uuid4()),
		created=now,
		expires=now + int(validity),
		filename=filename,
		content_type=content_type,
		username=session.username if session else None,
	)
	file_meta.file_path.parent.mkdir(exist_ok=True)
	file_meta.file_path.touch()
	file_meta.meta_path.write_text(file_meta.model_dump_json(), encoding="utf-8")
	return file_meta


def prepare_file(filename: str | None = None, content_type: str | None = None, validity: int = 24 * 3600) -> FileMetaData:
	"""
	expiry: File expires in given seconds from now
	"""
	session = contextvar_client_session.get()
	if not session or not session.username:
		raise PermissionError()

	return _prepare_file(filename=filename, content_type=content_type, validity=validity, session=session)


def cleanup_file_storage() -> None:
	now = utc_time_timestamp()
	all_files = set()
	keep_files = set()
	storage_dir = Path(FILE_TRANSFER_STORAGE_DIR)
	storage_dir.mkdir(exist_ok=True)
	for path in storage_dir.iterdir():
		if not path.is_file():
			continue

		all_files.add(path)
		if path.suffix != ".meta":
			continue

		try:
			UUID(path.name)  # Test if filename is valid UUID
			file_meta = FileMetaData.read_meta(path)
			if file_meta.expires <= now:
				# Expired
				continue
		except Exception:  # pylint: disable=broad-except
			# Invalid meta data
			continue

		keep_files.add(path)
		keep_files.add(path.with_suffix(""))

	for path in all_files.difference(keep_files):
		try:
			path.unlink()
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err)


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
		file_meta = prepare_file(filename=filename, content_type=request.headers.get("content-type") or None)
	except PermissionError:
		return JSONResponse({"error": "Permission denied"}, status_code=status.HTTP_403_FORBIDDEN)

	async with aiofiles.open(file_meta.file_path, mode="wb") as out_file:
		async for chunk in request.stream():
			await out_file.write(chunk)

	return JSONResponse({"file_id": file_meta.file_id}, status_code=status.HTTP_201_CREATED)


@filetransfer_router.post("multipart")
@filetransfer_router.post("/multipart")
async def filetransfer_post_file_multipart(file: UploadFile) -> JSONResponse:
	try:
		file_meta = prepare_file(filename=file.filename, content_type=file.content_type)
	except PermissionError:
		return JSONResponse({"error": "Permission denied"}, status_code=status.HTTP_403_FORBIDDEN)

	async with aiofiles.open(file_meta.file_path, mode="wb") as out_file:
		while chunk := await file.read(1_000_000):
			await out_file.write(chunk)

	return JSONResponse({"file_id": file_meta.file_id}, status_code=status.HTTP_201_CREATED)


@filetransfer_router.get("{file_id}")
@filetransfer_router.get("/{file_id}")
async def filetransfer_get_file(file_id: UUID, delete: bool = False) -> FileResponse:
	file_path = Path(FILE_TRANSFER_STORAGE_DIR) / str(file_id)
	meta_path = file_path.with_suffix(".meta")
	if not file_path.exists() or not file_path.exists():
		raise ValueError("Invalid file ID")
	file_meta = FileMetaData.model_validate_json(meta_path.read_bytes())
	if file_meta.expires <= utc_time_timestamp():
		raise ValueError("Invalid file ID")
	background = BackgroundTask(delete_file, file_id) if delete else None
	return FileResponse(path=file_path, filename=file_meta.filename, media_type=file_meta.content_type, background=background)


@filetransfer_router.delete("{file_id}")
@filetransfer_router.delete("/{file_id}")
async def filetransfer_delete_file(file_id: UUID) -> JSONResponse:
	delete_file(file_id)
	return JSONResponse({"file_id": str(file_id)}, status_code=status.HTTP_200_OK)
