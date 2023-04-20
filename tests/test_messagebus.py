# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.messagebus tests
"""

from typing import Type
import pytest

from opsiconfd.messagebus import check_channel_name


@pytest.mark.parametrize(
	"channel, expected, exc",
	(
		("session:2a0c1e04-f18c-494c-a7ab-b6f42cc71a0a", "session:2a0c1e04-f18c-494c-a7ab-b6f42cc71a0a", None),
		("session:2a0c1e04-f18c-494c-a7ab-b6f42cc71a0a:sub", None, ValueError),
		("session:1234", None, ValueError),
		("session", None, ValueError),
		("service:messagebus", "service:messagebus", None),
		("service:depot:depot.opsi.org:terminal", "service:depot:depot.opsi.org:terminal", None),
		("service:depot:depotid:terminal", None, ValueError),
		("service:depot:depot.opsi.org", None, ValueError),
		("service:depot:terminal", None, ValueError),
		("service:invalid", None, ValueError),
		("host:client.opsi.org", "host:client.opsi.org", None),
		("host:depot.opsi.org:sub:channel", "host:depot.opsi.org:sub:channel", None),
		("host:client", None, ValueError),
		("user:admin", "user:admin", None),
		("user:Admin:subchan", "user:admin:subchan", None),
		("user:invalid user", None, ValueError),
		("service_node:NODE1", "service_node:node1", None),
		("service_node:in valid", None, ValueError),
		("service_node:node2:invalid", None, ValueError),
		("service_worker:node1:11", "service_worker:node1:11", None),
		("service_worker:workername", None, ValueError),
		("event:user_connected", "event:user_connected", None),
		("event:productonclient_deleted", None, ValueError),
		("some:channel", None, ValueError),
		("EVENT:channel", None, ValueError),
	),
)
def test_check_channel_name(channel: str, expected: str, exc: Type[Exception] | None) -> None:
	if exc:
		with pytest.raises(exc):
			print(channel)
			check_channel_name(channel)
	else:
		assert check_channel_name(channel) == expected
