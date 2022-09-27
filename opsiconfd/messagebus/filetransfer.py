# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2022 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.messagebus.filetransfer
"""

from __future__ import annotations

from asyncio import get_event_loop, sleep
from pathlib import Path
from time import time

from opsicommon.messagebus import (  # type: ignore[import]
	FileChunk,
	FileUploadRequestMessage,
	FileUploadResultMessage,
	Message,
)

from ..logging import logger
from . import file_uploads, get_messagebus_worker_id, terminals
from .redis import send_message


class FileUpload:  # pylint: disable=too-many-instance-attributes
	chunk_timeout = 300

	def __init__(self, file_upload_request: FileUploadRequestMessage, sender: str) -> None:
		super().__init__()
		self._file_upload_request = file_upload_request
		self._sender = sender
		self._loop = get_event_loop()
		self._should_stop = False
		self._chunk_number = 0
		self._last_chunk_time = time()

		if not self._file_upload_request.name:
			raise ValueError("Invalid name")
		if not self._file_upload_request.content_type:
			raise ValueError("Invalid content_type")

		destination_dir = None
		if self._file_upload_request.destination_dir:
			destination_dir = self._file_upload_request.destination_dir
		elif self._file_upload_request.terminal_id:
			terminal = terminals.get(self._file_upload_request.terminal_id)
			if terminal:
				destination_dir = terminal.get_cwd()
		if not destination_dir:
			raise ValueError("Invalid destination_dir")

		destination_path = Path(destination_dir)
		self._file_path: Path = (destination_path / self._file_upload_request.name).absolute()
		if not self._file_path.is_relative_to(destination_path):
			raise ValueError("Invalid name")

		orig_name = self._file_path.name
		ext = 0
		while self._file_path.exists():
			ext += 1
			self._file_path = self._file_path.with_name(f"{orig_name}.{ext}")
		self._file_path.touch()
		self._file_path.chmod(0o660)

		self._manager_task = self._loop.create_task(self._manager())

	@property
	def file_id(self) -> str:
		return self._file_upload_request.file_id

	@property
	def back_channel(self) -> str:
		return self._file_upload_request.back_channel

	async def _error(self, error: str) -> None:
		msg = FileUploadResultMessage(
			sender=self._sender,
			channel=self.back_channel,
			file_id=self.file_id,
			error={
				"code": 0,
				"message": error,
				"details": None,
			},
		)
		await send_message(msg)
		self._should_stop = True

	async def _manager(self) -> None:
		while not self._should_stop:
			if time() > self._last_chunk_time + self.chunk_timeout:
				logger.notice("File transfer timed out")
				await self._error("File transfer timed out while waiting for next chunk")
			await sleep(1)
		if self.file_id in file_uploads:
			del file_uploads[self.file_id]

	async def process_message(self, message: Message) -> None:
		if not isinstance(message, FileChunk):
			raise ValueError(f"Received invalid message type {message.type}")

		self._last_chunk_time = time()
		if message.number != self._chunk_number + 1:
			await self._error(f"Expected chunk number {self._chunk_number + 1}")
			return

		self._chunk_number = message.number

		await self._loop.run_in_executor(None, self._append_to_file, message.data)

		if message.last:
			logger.debug("Last chunk received")
			msg = FileUploadResultMessage(
				sender=self._sender,
				channel=self.back_channel,
				file_id=self.file_id,
				path=str(self._file_path),
			)
			await send_message(msg)
			self._should_stop = True

	def _append_to_file(self, data: bytes) -> None:
		with open(self._file_path, mode="ab") as file:
			file.write(data)


async def process_message(message: Message) -> None:
	file_upload = file_uploads.get(message.file_id)

	try:
		if isinstance(message, FileUploadRequestMessage):
			if file_upload:
				raise RuntimeError("File id already taken")
			file_uploads[message.file_id] = FileUpload(file_upload_request=message, sender=get_messagebus_worker_id())
			return

		if not file_upload:
			raise RuntimeError("Invalid file id")

		await file_upload.process_message(message)
	except Exception as err:  # pylint: disable=broad-except
		logger.warning(err, exc_info=True)

		msg = FileUploadResultMessage(
			sender=get_messagebus_worker_id(),
			channel=message.back_channel,
			file_id=message.file_id,
			error={
				"code": 0,
				"message": str(err),
				"details": None,
			},
		)
		await send_message(msg)
		if message.file_id in file_uploads:
			del file_uploads[message.file_id]
