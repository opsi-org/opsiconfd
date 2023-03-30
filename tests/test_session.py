# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
session tests
"""

from opsiconfd.session import OPSISession

from .utils import clean_redis  # pylint: disable=unused-import


def test_session_serialize() -> None:
	client_addr = "172.10.11.12"
	session = OPSISession(client_addr=client_addr)
	data = session.serialize()
	session2 = OPSISession.from_serialized(data)
	assert session.serialize() == session2.serialize()
