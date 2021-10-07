# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
login tests
"""

import time
import pytest
import redis
import requests

from .utils import (  # pylint: disable=unused-import
	config, clean_redis, disable_request_warning,
	ADMIN_USER, ADMIN_PASS, OPSI_SESSION_KEY
)


login_test_data = [
	(None, 401, "Authorization header missing"),
	(("", ""), 401, "Authentication error"),
	((ADMIN_USER, ""), 401, "Authentication error"),
	((ADMIN_USER, "123"), 401, "Authentication error"),
	(("", ADMIN_PASS), 401, "Authentication error"),
	(("123", ADMIN_PASS), 401, "Authentication error")
]

@pytest.mark.parametrize("auth_data, expected_status_code, expected_text", login_test_data)
def test_login_error(config, auth_data, expected_status_code, expected_text):  # pylint: disable=redefined-outer-name,unused-argument
	res = requests.get(config.external_url, auth=(auth_data), verify=False)
	assert res.status_code == expected_status_code
	assert res.text == expected_text
	assert res.headers.get("set-cookie", None) is not None


def test_login_success(config):  # pylint: disable=redefined-outer-name,unused-argument
	res = requests.get(config.external_url, auth=(ADMIN_USER, ADMIN_PASS), verify=False)
	assert res.status_code == 200
	assert res.url.rstrip("/") == f"{config.external_url}/admin"


#@pytest.mark.skip(reason="test does not work in gitlab ci")
def test_max_sessions(config):  # pylint: disable=redefined-outer-name,unused-argument
	over_limit = 3
	for num in range(1, config.max_session_per_ip + 1 + over_limit):
		res = requests.get(f"{config.external_url}/admin/", auth=(ADMIN_USER, ADMIN_PASS), verify=False)
		if num > config.max_session_per_ip:
			assert res.status_code == 403
			assert res.text.startswith("Too many sessions")
		else:
			assert res.status_code == 200

	# Delete some sessions
	redis_client = redis.StrictRedis.from_url(config.redis_internal_url)
	num = 0
	for key in redis_client.scan_iter(f"{OPSI_SESSION_KEY}:*"):
		num += 1
		redis_client.delete(key)
		if num > over_limit:
			break

	res = requests.get(f"{config.external_url}/admin/", auth=(ADMIN_USER, ADMIN_PASS), verify=False)
	assert res.status_code == 200


def test_max_auth_failures(config):  # pylint: disable=redefined-outer-name,unused-argument
	over_limit = 3
	session = requests.Session()
	for num in range(1, config.max_auth_failures + 1 + over_limit):

		try:
			redis_client = redis.StrictRedis.from_url(config.redis_internal_url)
			now = round(time.time())*1000
			for key in redis_client.scan_iter(f"opsiconfd:stats:client:failed_auth:*"):
				print("=== key ==>>>", key)
			cmd = (
				f"ts.range opsiconfd:stats:client:failed_auth:127.0.0.1 "
				f"{(now-(config.auth_failures_interval*1000))} {now} aggregation count {(config.auth_failures_interval*1000)}"
			)
			num_failed_auth = redis_client.execute_command(cmd)
			num_failed_auth =  int(num_failed_auth[-1][1])
			print("=== num_failed_auth ==>>>", num_failed_auth)
		except Exception as err:
			print("===============", err)

		res = session.get(f"{config.external_url}/admin/", auth=("client.domain.tld", "hostkey"), verify=False)
		if num >= config.max_auth_failures + 1:
			assert res.status_code == 403
			assert "blocked" in res.text
		else:
			assert res.status_code == 401
			assert res.text == "Authentication error"
		time.sleep(0.5)
