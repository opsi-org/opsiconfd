# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.messagebus.terminal
"""

from __future__ import annotations

from queue import Empty, Queue

from opsicommon.client.opsiservice import Messagebus, MessagebusListener
from opsicommon.messagebus import CONNECTION_SESSION_CHANNEL, CONNECTION_USER_CHANNEL
from opsicommon.messagebus.file_transfer import process_messagebus_message as process_file_message
from opsicommon.messagebus.message import (
	ChannelSubscriptionRequestMessage,
	FileChunkMessage,
	FileUploadRequestMessage,
	Message,
	TerminalCloseRequestMessage,
	TerminalDataWriteMessage,
	TerminalOpenRequestMessage,
	TerminalResizeRequestMessage,
)
from opsicommon.messagebus.terminal import process_messagebus_message, terminals
from starlette.concurrency import run_in_threadpool

from opsiconfd.backend import get_service_client
from opsiconfd.config import config, get_depotserver_id, get_server_role
from opsiconfd.logging import logger
from opsiconfd.utils import asyncio_create_task

from . import get_messagebus_worker_id
from .redis import ConsumerGroupMessageReader, MessageReader
from .redis import send_message as redis_send_message

terminal_request_reader: ConsumerGroupMessageReader | None = None
terminal_instance_reader: MessageReader | None = None


async def async_terminal_startup() -> None:
	if "messagebus_terminal" not in config.disabled_features:
		asyncio_create_task(messagebus_terminal_open_request_worker())
		asyncio_create_task(messagebus_terminal_instance_worker())


async def async_terminal_shutdown() -> None:
	if terminal_request_reader:
		await terminal_request_reader.stop()
	if terminal_instance_reader:
		await terminal_instance_reader.stop()
	for terminal in list(terminals.values()):
		await terminal.close()


async def messagebus_terminal_instance_worker_configserver() -> None:
	global terminal_instance_reader
	messagebus_worker_id = get_messagebus_worker_id()

	channel = f"{messagebus_worker_id}:terminal"
	terminal_instance_reader = MessageReader(name=channel)
	await terminal_instance_reader.set_channels({channel: CONNECTION_SESSION_CHANNEL})
	async for _redis_id, message, _context in terminal_instance_reader.get_messages():
		try:
			if isinstance(
				message, (TerminalDataWriteMessage, TerminalResizeRequestMessage, TerminalOpenRequestMessage, TerminalCloseRequestMessage)
			):
				await process_messagebus_message(message, redis_send_message, sender=messagebus_worker_id)
			elif isinstance(message, (FileChunkMessage, FileUploadRequestMessage)):
				if isinstance(message, FileUploadRequestMessage):
					if message.terminal_id and not message.destination_dir:
						terminal = terminals.get(message.terminal_id)
						if terminal:
							destination_dir = terminal.get_cwd()
							message.destination_dir = str(destination_dir)
				await process_file_message(message, redis_send_message, sender=messagebus_worker_id)
			else:
				raise ValueError(f"Received invalid message type {message.type}")
		except Exception as err:
			logger.error(err, exc_info=True)


async def messagebus_terminal_instance_worker_depotserver() -> None:
	message_queue: Queue[
		TerminalDataWriteMessage
		| TerminalResizeRequestMessage
		| TerminalOpenRequestMessage
		| TerminalCloseRequestMessage
		| FileChunkMessage
		| FileUploadRequestMessage
	] = Queue()
	messagebus_worker_id = get_messagebus_worker_id()

	class TerminalMessageListener(MessagebusListener):
		def messagebus_connection_established(self, messagebus: Messagebus) -> None:
			channel = f"{messagebus_worker_id}:terminal"
			if channel not in messagebus._subscribed_channels:
				message = ChannelSubscriptionRequestMessage(
					sender=CONNECTION_USER_CHANNEL,
					channel="service:messagebus",
					channels=[channel],
					operation="add",
				)
				logger.info("Messagebus connection established, subscribing %s", message.channels)
				messagebus.send_message(message)

		def message_received(self, message: Message) -> None:
			try:
				if isinstance(
					message,
					(
						TerminalDataWriteMessage,
						TerminalResizeRequestMessage,
						TerminalOpenRequestMessage,
						TerminalCloseRequestMessage,
						FileChunkMessage,
						FileUploadRequestMessage,
					),
				):
					message_queue.put(message, block=True)
			except Exception as err:
				logger.error(err, exc_info=True)

	service_client = await run_in_threadpool(get_service_client, "messagebus terminal", TerminalMessageListener())

	while True:
		try:
			try:
				message = await run_in_threadpool(message_queue.get, block=True, timeout=1.0)
			except Empty:
				continue
			if isinstance(message, (FileChunkMessage, FileUploadRequestMessage)):
				if isinstance(message, FileUploadRequestMessage):
					if message.terminal_id and not message.destination_dir:
						terminal = terminals.get(message.terminal_id)
						if terminal:
							destination_dir = terminal.get_cwd()
							message.destination_dir = str(destination_dir)
				await process_file_message(message, service_client.messagebus.async_send_message, sender=messagebus_worker_id)
			else:
				await process_messagebus_message(message, service_client.messagebus.async_send_message, sender=messagebus_worker_id)
		except Exception as err:
			logger.error(err, exc_info=True)


async def messagebus_terminal_instance_worker() -> None:
	if get_server_role() == "configserver":
		await messagebus_terminal_instance_worker_configserver()
	elif get_server_role() == "depotserver":
		await messagebus_terminal_instance_worker_depotserver()


async def messagebus_terminal_open_request_worker_configserver() -> None:
	global terminal_request_reader
	messagebus_worker_id = get_messagebus_worker_id()

	channel = f"service:depot:{get_depotserver_id()}:terminal"

	# ID "0" means: Start reading pending messages (not ACKed) and continue reading new messages
	terminal_request_reader = ConsumerGroupMessageReader(
		consumer_group=channel,
		consumer_name=messagebus_worker_id,
	)
	await terminal_request_reader.set_channels({channel: "0"})
	async for redis_id, message, _context in terminal_request_reader.get_messages():
		try:
			if isinstance(message, TerminalOpenRequestMessage):
				await process_messagebus_message(
					message=message,
					send_message=redis_send_message,
					sender=messagebus_worker_id,
					back_channel=f"{messagebus_worker_id}:terminal",
				)
			else:
				raise ValueError(f"Received invalid message type {message.type}")
		except Exception as err:
			logger.error(err, exc_info=True)
		# ACK Message
		await terminal_request_reader.ack_message(message.channel, redis_id)


async def messagebus_terminal_open_request_worker_depotserver() -> None:
	message_queue: Queue[TerminalOpenRequestMessage] = Queue()
	messagebus_worker_id = get_messagebus_worker_id()

	class TerminalOpenRequestMessageListener(MessagebusListener):
		def messagebus_connection_established(self, messagebus: Messagebus) -> None:
			channel = f"service:depot:{get_depotserver_id()}:terminal"
			if channel not in messagebus._subscribed_channels:
				message = ChannelSubscriptionRequestMessage(
					sender=CONNECTION_USER_CHANNEL,
					channel="service:messagebus",
					channels=[channel],
					operation="add",
				)
				logger.info("Messagebus connection established, subscribing %s", message.channels)
				messagebus.send_message(message)

		def message_received(self, message: Message) -> None:
			if isinstance(message, TerminalOpenRequestMessage):
				message_queue.put(message, block=True)

	service_client = await run_in_threadpool(get_service_client, "messagebus terminal", TerminalOpenRequestMessageListener())
	while True:
		try:
			term_message: TerminalOpenRequestMessage = await run_in_threadpool(message_queue.get, block=True, timeout=1.0)
		except Empty:
			continue
		await process_messagebus_message(
			message=term_message,
			send_message=service_client.messagebus.async_send_message,
			sender=messagebus_worker_id,
			back_channel=f"{messagebus_worker_id}:terminal",
		)


async def messagebus_terminal_open_request_worker() -> None:
	if get_server_role() == "configserver":
		await messagebus_terminal_open_request_worker_configserver()
	elif get_server_role() == "depotserver":
		await messagebus_terminal_open_request_worker_depotserver()
