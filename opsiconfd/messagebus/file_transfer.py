# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.messagebus.filetransfer
"""

from __future__ import annotations

from opsicommon.messagebus.file_transfer import process_messagebus_message, stop_running_file_transfers
from opsicommon.messagebus.message import FileDownloadAbortRequestMessage, FileDownloadRequestMessage

from opsiconfd.config import get_depotserver_id
from opsiconfd.logging import logger
from opsiconfd.utils import asyncio_create_task

from . import get_messagebus_worker_id
from .redis import ConsumerGroupMessageReader
from .redis import send_message as redis_send_message

filetransfer_request_reader = None


async def async_file_transfer_startup() -> None:
	asyncio_create_task(messagebus_filetransfer_start_request_worker())


async def async_file_transfer_shutdown() -> None:
	if filetransfer_request_reader:
		await filetransfer_request_reader.stop()
	await stop_running_file_transfers()


async def messagebus_filetransfer_start_request_worker() -> None:
	global filetransfer_request_reader
	messagebus_worker_id = get_messagebus_worker_id()

	channel = f"service:depot:{get_depotserver_id()}:filetransfer"

	# ID "0" means: Start reading pending messages (not ACKed) and continue reading new messages
	filetransfer_request_reader = ConsumerGroupMessageReader(
		consumer_group=channel,
		consumer_name=messagebus_worker_id,
	)
	await filetransfer_request_reader.set_channels({channel: "0"})
	async for redis_id, message, _context in filetransfer_request_reader.get_messages():
		try:
			if isinstance(message, (FileDownloadRequestMessage, FileDownloadAbortRequestMessage)):
				await process_messagebus_message(
					message=message,
					send_message=redis_send_message,
					sender=messagebus_worker_id,
					back_channel=f"{messagebus_worker_id}:filetransfer",
				)
			else:
				raise ValueError(f"Received invalid message type {message.type}")
		except Exception as err:
			logger.error(err, exc_info=True)
		# ACK Message
		await filetransfer_request_reader.ack_message(message.channel, redis_id)
