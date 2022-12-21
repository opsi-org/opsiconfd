# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.messagebus
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict

from opsiconfd.worker import Worker

if TYPE_CHECKING:
	from .filetransfer import FileUpload
	from .terminal import Terminal

file_uploads: Dict[str, FileUpload] = {}
terminals: Dict[str, Terminal] = {}
messagebus_worker_id = ""  # pylint: disable=invalid-name


def get_messagebus_worker_id() -> str:
	global messagebus_worker_id  # pylint: disable=invalid-name,global-statement
	if not messagebus_worker_id:
		messagebus_worker_id = get_messagebus_user_id_for_service_worker(Worker.get_instance().id)
	return messagebus_worker_id


def get_messagebus_user_id_for_host(host_id: str) -> str:
	return f"host:{host_id}"


def get_object_channel_for_host(host_id: str) -> str:
	return f"host:{host_id}"


def get_messagebus_user_id_for_user(user_id: str) -> str:
	return f"user:{user_id}"


def get_messagebus_user_id_for_service_node(node_name: str) -> str:
	return f"service_node:{node_name}"


def get_messagebus_user_id_for_service_worker(worker_id: str) -> str:
	return f"service_worker:{worker_id}"
