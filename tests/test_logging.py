# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
login tests
"""

from OPSI.Backend.Base.ConfigData import LOG_SIZE_HARD_LIMIT

from .utils import (  # pylint: disable=unused-import
	config, clean_redis, ADMIN_USER, ADMIN_PASS
)


def test_log_hard_limit(test_client):  # pylint: disable=redefined-outer-name,unused-argument
	test_client.auth = (ADMIN_USER, ADMIN_PASS)

	client_id = "logtest.uib.local"
	rpc = {
		"id": 1,
		"method": "host_createOpsiClient",
		"params": [
			client_id
		]
	}
	res = test_client.post("/rpc", verify=False, json=rpc)
	assert res.status_code == 200

	log_line = "log_line_" * 100
	log_data = ""
	expected_size = 0
	while len(log_data) < LOG_SIZE_HARD_LIMIT + len(log_line) * 10:
		if len(log_data) < LOG_SIZE_HARD_LIMIT:
			expected_size = len(log_data)
		log_data += log_line + "\n"

	rpc = {"id": 1, "method": "log_write", "params": ["clientconnect", log_data, client_id, False]}
	res = test_client.post("/rpc", verify=False, json=rpc)
	assert res.status_code == 200
	res = res.json()
	assert res.get("error") is None

	rpc = {"id": 1, "method": "log_read", "params": ["clientconnect", client_id]}
	res = test_client.post("/rpc", verify=False, json=rpc)
	assert res.status_code == 200
	res = res.json()
	assert res.get("error") is None

	assert len(res["result"]) == expected_size

	for line in res["result"][:-1].split("\n"):
		assert line == log_line

	rpc = {
		"id": 1,
		"method": "host_delete",
		"params": [
			client_id
		]
	}
	res = test_client.post("/rpc", verify=False, json=rpc)
	assert res.status_code == 200
