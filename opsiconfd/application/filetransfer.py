# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.application.filetransfer

This module provides FastAPI routes for file transfer functionalities.
It allows uploading, downloading, and managing temporary files.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import aiofiles  # type: ignore[import]
from fastapi import APIRouter, FastAPI, Request, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse
from opsicommon.utils import unix_timestamp
from pydantic import BaseModel
from starlette.background import BackgroundTask
from werkzeug.http import parse_options_header

from opsiconfd import contextvar_client_session
from opsiconfd.config import FILE_TRANSFER_STORAGE_DIR
from opsiconfd.logging import logger

if TYPE_CHECKING:
	from opsiconfd.session import OPSISession


filetransfer_router = APIRouter()


def filetransfer_setup(app: FastAPI) -> None:
	"""
	Registers the filetransfer router with the FastAPI application.

	Args:
		app: The FastAPI application instance.
	"""
	app.include_router(filetransfer_router, prefix="/file-transfer")


class FileMetaData(BaseModel):
	"""
	Represents metadata for a transferred file.

	Attributes:
		file_id: Unique identifier for the file.
		created: Timestamp of file creation (Unix epoch).
		expires: Timestamp of file expiration (Unix epoch).
		filename: Original name of the file.
		content_type: MIME type of the file.
		username: Username of the user who uploaded the file.
	"""

	file_id: str
	created: int
	expires: int
	filename: str | None
	content_type: str | None
	username: str | None

	@property
	def file_path(self) -> Path:
		"""
		Gets the full path to the file on the server.

		Returns:
			The Path object representing the file's location.
		"""
		return Path(FILE_TRANSFER_STORAGE_DIR) / self.file_id

	@property
	def meta_path(self) -> Path:
		"""
		Gets the full path to the metadata file on the server.

		Returns:
			The Path object representing the metadata file's location.
		"""
		return Path(FILE_TRANSFER_STORAGE_DIR) / (self.file_id + ".meta")

	@staticmethod
	def read_meta(meta_path: Path) -> FileMetaData:
		"""
		Reads and parses file metadata from a .meta file.

		Args:
			meta_path: Path to the metadata file.

		Returns:
			A FileMetaData instance.
		"""
		return FileMetaData.model_validate_json(meta_path.read_bytes())

	def write_meta(self) -> None:
		"""Writes the current metadata to its .meta file."""
		self.meta_path.write_text(self.model_dump_json(), encoding="utf-8")


def _prepare_file(
	filename: str | None = None, content_type: str | None = None, validity: int = 24 * 3600, session: OPSISession | None = None
) -> FileMetaData:
	"""
	Internal helper to prepare a file for transfer by creating metadata and placeholder files.

	Args:
		filename: The original name of the file.
		content_type: The MIME type of the file.
		validity: The duration in seconds for which the file should be valid.
		session: The opsi session of the user initiating the transfer.

	Returns:
		FileMetaData: Metadata for the prepared file.
	"""
	now = int(unix_timestamp())
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
	Prepares a file for transfer by creating metadata and placeholder files.

	This function checks for user authentication before proceeding.

	Args:
		filename: The original name of the file.
		content_type: The MIME type of the file.
		validity: The duration in seconds for which the file should be valid.
					Defaults to 24 hours.

	Returns:
		FileMetaData: Metadata for the prepared file.

	Raises:
		PermissionError: If the user is not authenticated.
	"""
	session = contextvar_client_session.get()
	if not session or not session.username:
		raise PermissionError()

	return _prepare_file(filename=filename, content_type=content_type, validity=validity, session=session)


def cleanup_file_storage() -> None:
	"""
	Removes expired files and their metadata from the storage directory.

	Iterates through the file transfer storage directory, identifies expired
	files based on their metadata, and deletes both the file and its
	corresponding .meta file. Invalid or unreadable metadata files are also
	cleaned up.
	"""
	now = unix_timestamp()
	all_files = set()
	keep_files = set()
	storage_dir = Path(FILE_TRANSFER_STORAGE_DIR)
	storage_dir.mkdir(parents=True, exist_ok=True)
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
		except Exception:
			# Invalid meta data
			continue

		keep_files.add(path)
		keep_files.add(path.with_suffix(""))

	for path in all_files.difference(keep_files):
		try:
			path.unlink()
		except Exception as err:
			logger.error(err)


def delete_file(file_id: UUID) -> None:
	"""
	Deletes a specific file and its metadata.

	Args:
		file_id: The UUID of the file to delete.
	"""
	file_path = Path(FILE_TRANSFER_STORAGE_DIR) / str(file_id)
	meta_path = file_path.with_suffix(".meta")
	file_path.unlink(missing_ok=True)
	meta_path.unlink(missing_ok=True)


@filetransfer_router.post("")
@filetransfer_router.post("/")
@filetransfer_router.post("raw")
@filetransfer_router.post("/raw")
async def filetransfer_post_file_raw(request: Request) -> JSONResponse:
	"""
	Handles raw file uploads.

	The file content is read directly from the request stream.
	Filename can be optionally provided via Content-Disposition header.

	Args:
		request: The FastAPI Request object.

	Returns:
		JSONResponse: A JSON response containing the file_id upon successful upload,
					  or an error message with a 403 status code if permission is denied.
	"""
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
	"""
	Handles multipart file uploads.

	Args:
		file: An UploadFile object representing the uploaded file.

	Returns:
		JSONResponse: A JSON response containing the file_id upon successful upload,
					  or an error message with a 403 status code if permission is denied.
	"""
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
	"""
	Retrieves a file by its ID.

	Args:
		file_id: The UUID of the file to retrieve.
		delete: If True, the file will be deleted after being sent.

	Returns:
		FileResponse: A response containing the file.

	Raises:
		ValueError: If the file ID is invalid or the file has expired.
	"""
	file_path = Path(FILE_TRANSFER_STORAGE_DIR) / str(file_id)
	meta_path = file_path.with_suffix(".meta")
	if not file_path.exists() or not file_path.exists():
		raise ValueError("Invalid file ID")
	file_meta = FileMetaData.model_validate_json(meta_path.read_bytes())
	if file_meta.expires <= unix_timestamp():
		raise ValueError("Invalid file ID")
	background = BackgroundTask(delete_file, file_id) if delete else None
	return FileResponse(path=file_path, filename=file_meta.filename, media_type=file_meta.content_type, background=background)


@filetransfer_router.delete("{file_id}")
@filetransfer_router.delete("/{file_id}")
async def filetransfer_delete_file(file_id: UUID) -> JSONResponse:
	"""
	Deletes a file by its ID.

	Args:
		file_id: The UUID of the file to delete.

	Returns:
		JSONResponse: A JSON response containing the file_id of the deleted file.
	"""
	delete_file(file_id)
	return JSONResponse({"file_id": str(file_id)}, status_code=status.HTTP_200_OK)
