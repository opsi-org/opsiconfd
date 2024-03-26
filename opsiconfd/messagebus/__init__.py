# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.messagebus
"""

from __future__ import annotations

from functools import lru_cache
from uuid import UUID

from opsicommon.messagebus.message import MessageType
from opsicommon.types import forceHostId, forceStringLower, forceUnsignedInt, forceUserId

from opsiconfd.config import get_configserver_id
from opsiconfd.utils import force_nodename
from opsiconfd.worker import Worker

RESTRICTED_MESSAGE_TYPES = {MessageType.PROCESS_START_REQUEST.value: "vpn"}


@lru_cache()
def get_messagebus_worker_id() -> str:
	return get_user_id_for_service_worker(Worker.get_instance().id)


def get_user_id_for_host(host_id: str) -> str:
	return f"host:{forceHostId(host_id)}"


def get_user_id_for_user(user_id: str) -> str:
	return f"user:{forceUserId(user_id)}"


@lru_cache()
def get_user_id_for_service_node(node_name: str) -> str:
	return f"service_node:{forceStringLower(node_name)}"


@lru_cache()
def get_user_id_for_service_worker(worker_id: str) -> str:
	return f"service_worker:{forceStringLower(worker_id)}"


@lru_cache()
def get_config_service_channel(channel: str) -> str:
	if not channel.startswith("service:config:"):
		raise ValueError(f"Invalid config service channel: {channel!r}")
	configserver_id = get_configserver_id()
	return channel.replace("service:config:", f"service:depot:{configserver_id}:")


def check_channel_name(channel: str) -> str:
	if channel.startswith("session:"):
		channel = channel.lower()
		parts = channel.split(":")
		if len(parts) != 2:
			raise ValueError(f"Invalid session channel: {channel!r}")
		try:
			parts[1] = str(UUID(parts[-1])).lower()
		except ValueError as err:
			raise ValueError(f"Invalid session id: {parts[1]!r}") from err
		return channel

	if channel.startswith("service:"):
		channel = channel.lower()
		if channel == "service:messagebus":
			return channel
		if channel.startswith("service:depot:"):
			parts = channel.split(":")
			if len(parts) != 4:
				raise ValueError(f"Invalid service channel: {channel!r}")
			if parts[3] not in ("jsonrpc", "terminal", "process"):
				raise ValueError(f"Invalid service channel: {channel!r}")
			try:
				parts[2] = forceHostId(parts[2])
			except ValueError as err:
				raise ValueError(f"Invalid service channel: {channel!r}") from err
			return ":".join(parts)
		raise ValueError(f"Invalid service channel: {channel!r}")

	if channel.startswith("host:"):
		channel = channel.lower()
		parts = channel.split(":")
		if len(parts) < 2:
			raise ValueError(f"Invalid host channel: {channel!r}")
		try:
			parts[1] = forceHostId(parts[1])
			return ":".join(parts)
		except ValueError as err:
			raise ValueError(f"Invalid host channel: {channel!r}") from err

	if channel.startswith("user:"):
		channel = channel.lower()
		parts = channel.split(":")
		if len(parts) < 2:
			raise ValueError(f"Invalid user channel: {channel!r}")
		try:
			parts[1] = forceUserId(parts[1])
			return ":".join(parts)
		except ValueError as err:
			raise ValueError(f"Invalid user channel: {channel!r}") from err

	if channel.startswith("service_node:"):
		channel = channel.lower()
		parts = channel.split(":")
		if len(parts) != 2:
			raise ValueError(f"Invalid service_node channel: {channel!r}")
		try:
			parts[1] = force_nodename(parts[1])
			return ":".join(parts)
		except ValueError as err:
			raise ValueError(f"Invalid service_node channel: {channel!r}") from err

	if channel.startswith("service_worker:"):
		channel = channel.lower()
		parts = channel.split(":")
		if len(parts) < 3:
			raise ValueError(f"Invalid service_worker channel: {channel!r}")
		try:
			parts[1] = force_nodename(parts[1])
			parts[2] = str(forceUnsignedInt(parts[2]))
			return ":".join(parts)
		except ValueError as err:
			raise ValueError(f"Invalid service_worker channel: {channel!r}") from err

	if channel.startswith("event:"):
		parts = channel.split(":")
		if len(parts) == 2 and parts[-1] in (
			"test",
			"app_state_changed",
			"config_created",
			"config_updated",
			"config_deleted",
			"configState_created",
			"configState_updated",
			"configState_deleted",
			"log_updated",
			"user_connected",
			"user_disconnected",
			"host_created",
			"host_updated",
			"host_deleted",
			"host_connected",
			"host_disconnected",
			"productOnClient_created",
			"productOnClient_updated",
			"productOnClient_deleted",
		):
			return channel
		raise ValueError(f"Invalid event channel: {channel!r}")

	raise ValueError(f"Invalid channel: {channel!r}")
