# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.messagebus
"""


def get_messagebus_user_id_for_host(host_id: str) -> str:
	return f"host:{host_id}"


def get_messagebus_user_id_for_user(user_id: str) -> str:
	return f"user:{user_id}"


def get_messagebus_user_id_for_service_node(node_name: str) -> str:
	return f"service_node:{node_name}"


def get_messagebus_user_id_for_service_worker(node_name: str, worker_num: int) -> str:
	return f"service_worker:{node_name}:{worker_num}"
