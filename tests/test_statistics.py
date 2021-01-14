# -*- coding: utf-8 -*-

# This file is part of opsi.
# Copyright (C) 2020 uib GmbH <info@uib.de>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
:copyright: uib GmbH <info@uib.de>
:license: GNU Affero General Public License version 3
"""

import sys
import asyncio
import redis
import pytest

@pytest.fixture(name="config")
def fixture_config(monkeypatch):
	monkeypatch.setattr(sys, 'argv', ["opsiconfd"])
	from opsiconfd.config import config # pylint: disable=import-outside-toplevel
	return config

@pytest.fixture(name="metrics_collector")
def fixture_metrics_collector(monkeypatch):
	monkeypatch.setattr(sys, 'argv', ["opsiconfd"])
	from opsiconfd.statistics import MetricsCollector # pylint: disable=import-outside-toplevel
	return MetricsCollector()

@pytest.fixture(name="metrics_registry")
def fixture_metrics_registry(monkeypatch):
	monkeypatch.setattr(sys, 'argv', ["opsiconfd"])
	from opsiconfd.statistics import MetricsRegistry, Metric # pylint: disable=import-outside-toplevel
	metrics_registry = MetricsRegistry()
	metrics_registry.register(
		Metric(
			id="opsiconfd:pytest:metric",
			name="opsiconfd pytest metric",
			vars=["node_name", "worker_num"],
			retention=24 * 3600 * 1000,
			subject="worker",
			grafana_config=None
		)
	)
	return MetricsRegistry()


@pytest.fixture(name="redis_client")
@pytest.mark.asyncio
async def fixture_redis_client(config):
	redis_client = redis.StrictRedis.from_url(config.redis_internal_url) # pylint: disable=redefined-outer-name
	redis_client.set("opsiconfd:stats:num_rpcs", 5)
	await asyncio.sleep(2)
	yield redis_client
	redis_client.delete("opsiconfd:stats:num_rpcs")



redis_test_data = [
	(
		[
			"GET opsiconfd:stats:num_rpcs",
			"SET opsiconfd:stats:num_rpcs 10",
			"GET opsiconfd:stats:num_rpcs"
		],
		[
			b"5",
			b"OK",
			b"10"
		]
	),
	(
		[
			"GET opsiconfd:stats:num_rpcs",
			"SET opsiconfd:stats:num_rpcs 111",
			"DEL opsiconfd:stats:num_rpcs",
			"DEL opsiconfd:stats:num_rpcs"
		],
		[
			b"5",
			b"OK",
			1,
			0
		]
	)
]

@pytest.mark.parametrize("cmds, expected_results", redis_test_data)
@pytest.mark.asyncio
async def test_execute_redis_command(metrics_collector, redis_client, cmds, expected_results): # pylint: disable=redefined-outer-name

	for idx, cmd in enumerate(cmds):
		result = await metrics_collector._execute_redis_command(cmd) # pylint: disable=protected-access
		print(result)
		assert result == expected_results[idx]


test_data = [
	("ADD", 4711, "TS.ADD opsiconfd:stats:opsiconfd:pytest:metric * 4711 RETENTION 86400000 LABELS"),
	("INCRBY", 4711,"TS.INCRBY opsiconfd:stats:opsiconfd:pytest:metric 4711 * RETENTION 86400000 LABELS"),
]
@pytest.mark.parametrize("cmd, value, expected_result", test_data)
def test_redis_ts_cmd(metrics_registry, metrics_collector, cmd, value, expected_result):

	metrics = list(metrics_registry.get_metrics())

	result = metrics_collector._redis_ts_cmd(metrics[-1], cmd, value) # pylint: disable=protected-access
	print(result)
	assert result == expected_result

def test_redis_ts_cmd_error(metrics_registry, metrics_collector):

	metrics = list(metrics_registry.get_metrics())

	with pytest.raises(ValueError) as excinfo:
		metrics_collector._redis_ts_cmd(metrics[-1], "unknown CMD", 42) # pylint: disable=protected-access

	print(excinfo)
	assert excinfo.type == ValueError
	assert excinfo.value.__str__() == ValueError("Invalid command unknown CMD").__str__()

def test_metric_by_redis_key(metrics_registry):

	metric = metrics_registry.get_metric_by_redis_key("opsiconfd:stats:opsiconfd:pytest:metric")

	print(metric.__dict__)
	assert metric.get_name() == "opsiconfd pytest metric"
	assert metric.id == "opsiconfd:pytest:metric"
	assert metric.get_redis_key() == "opsiconfd:stats:opsiconfd:pytest:metric"

def test_metric_by_redis_key_error(metrics_registry):

	with pytest.raises(ValueError) as excinfo:
		metrics_registry.get_metric_by_redis_key("opsiconfd:stats:opsiconfd:notinredis:metric")

	assert excinfo.type == ValueError
	assert excinfo.value.__str__() == ValueError("Metric with redis key 'opsiconfd:stats:opsiconfd:notinredis:metric' not found").__str__()
	# print(excinfo.value.__eq__(ValueError("Metric with redis key 'opsiconfd:stats:opsiconfd:notinredis:metric' not found")))
	# print(type(excinfo.value))
	# print(type(ValueError("Metric with redis key 'opsiconfd:stats:opsiconfd:notinredis:metric' not found")))
