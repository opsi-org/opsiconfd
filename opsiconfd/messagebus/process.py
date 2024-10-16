# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.messagebus.process
"""

from __future__ import annotations

from queue import Empty, Queue

from opsicommon.client.opsiservice import Messagebus, MessagebusListener
from opsicommon.messagebus import CONNECTION_SESSION_CHANNEL, CONNECTION_USER_CHANNEL
from opsicommon.messagebus.message import (
	ChannelSubscriptionRequestMessage,
	Message,
	ProcessDataWriteMessage,
	ProcessStartRequestMessage,
	ProcessStopRequestMessage,
)
from opsicommon.messagebus.process import process_messagebus_message, stop_running_processes
from starlette.concurrency import run_in_threadpool

from opsiconfd.backend import get_service_client
from opsiconfd.config import get_depotserver_id, get_server_role
from opsiconfd.logging import logger
from opsiconfd.utils import asyncio_create_task

from . import get_messagebus_worker_id
from .redis import ConsumerGroupMessageReader, MessageReader
from .redis import send_message as redis_send_message

process_instance_reader = None
process_request_reader = None


async def async_process_startup() -> None:
	asyncio_create_task(messagebus_process_start_request_worker())
	asyncio_create_task(messagebus_process_instance_worker())


async def async_process_shutdown() -> None:
	if process_request_reader:
		await process_request_reader.stop()
	if process_instance_reader:
		await process_instance_reader.stop()
	await stop_running_processes()


async def messagebus_process_instance_worker_configserver() -> None:
	global process_instance_reader

	messagebus_worker_id = get_messagebus_worker_id()
	channel = f"{messagebus_worker_id}:process"
	process_instance_reader = MessageReader(name=channel)
	await process_instance_reader.set_channels({channel: CONNECTION_SESSION_CHANNEL})
	async for _redis_id, message, _context in process_instance_reader.get_messages():
		try:
			if isinstance(message, (ProcessDataWriteMessage, ProcessStartRequestMessage, ProcessStopRequestMessage)):
				await process_messagebus_message(message, redis_send_message, sender=messagebus_worker_id)
			else:
				raise ValueError(f"Received invalid message type {message.type}")
		except Exception as err:
			logger.error(err, exc_info=True)


async def messagebus_process_instance_worker_depotserver() -> None:
	message_queue: Queue[ProcessDataWriteMessage | ProcessStartRequestMessage | ProcessStopRequestMessage] = Queue()
	messagebus_worker_id = get_messagebus_worker_id()

	class ProcessMessageListener(MessagebusListener):
		def messagebus_connection_established(self, messagebus: Messagebus) -> None:
			channel = f"{messagebus_worker_id}:process"
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
					(ProcessDataWriteMessage, ProcessStartRequestMessage, ProcessStopRequestMessage),
				):
					message_queue.put(message, block=True)
			except Exception as err:
				logger.error(err, exc_info=True)

	service_client = await run_in_threadpool(get_service_client, "messagebus process", ProcessMessageListener())

	while True:
		try:
			try:
				message = await run_in_threadpool(message_queue.get, block=True, timeout=1.0)
			except Empty:
				continue
			await process_messagebus_message(message, service_client.messagebus.async_send_message, sender=messagebus_worker_id)
		except Exception as err:
			logger.error(err, exc_info=True)


async def messagebus_process_instance_worker() -> None:
	if get_server_role() == "configserver":
		await messagebus_process_instance_worker_configserver()
	elif get_server_role() == "depotserver":
		await messagebus_process_instance_worker_depotserver()


async def messagebus_process_start_request_worker_configserver() -> None:
	global process_request_reader
	messagebus_worker_id = get_messagebus_worker_id()

	channel = f"service:depot:{get_depotserver_id()}:process"

	# ID "0" means: Start reading pending messages (not ACKed) and continue reading new messages
	process_request_reader = ConsumerGroupMessageReader(
		consumer_group=channel,
		consumer_name=messagebus_worker_id,
	)
	await process_request_reader.set_channels({channel: "0"})
	async for redis_id, message, _context in process_request_reader.get_messages():
		try:
			if isinstance(message, ProcessStartRequestMessage):
				await process_messagebus_message(
					message=message,
					send_message=redis_send_message,
					sender=messagebus_worker_id,
					back_channel=f"{messagebus_worker_id}:process",
				)
			else:
				raise ValueError(f"Received invalid message type {message.type}")
		except Exception as err:
			logger.error(err, exc_info=True)
		# ACK Message
		await process_request_reader.ack_message(message.channel, redis_id)


async def messagebus_process_start_request_worker_depotserver() -> None:
	message_queue: Queue[ProcessStartRequestMessage] = Queue()
	messagebus_worker_id = get_messagebus_worker_id()

	class ProcessStartRequestMessageListener(MessagebusListener):
		def messagebus_connection_established(self, messagebus: Messagebus) -> None:
			channel = f"service:depot:{get_depotserver_id()}:process"
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
			if isinstance(message, ProcessStartRequestMessage):
				message_queue.put(message, block=True)

	service_client = await run_in_threadpool(get_service_client, "messagebus process", ProcessStartRequestMessageListener())

	while True:
		try:
			start_message: ProcessStartRequestMessage = await run_in_threadpool(message_queue.get, block=True, timeout=1.0)
		except Empty:
			continue
		await process_messagebus_message(
			message=start_message,
			send_message=service_client.messagebus.async_send_message,
			sender=messagebus_worker_id,
			back_channel=f"{messagebus_worker_id}:process",
		)


async def messagebus_process_start_request_worker() -> None:
	if get_server_role() == "configserver":
		await messagebus_process_start_request_worker_configserver()
	elif get_server_role() == "depotserver":
		await messagebus_process_start_request_worker_depotserver()
