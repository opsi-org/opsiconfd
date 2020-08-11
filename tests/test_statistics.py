import os
import sys
import pytest
import redis
import json
import asyncio
import time

from opsiconfd.statistics import MetricsCollector


@pytest.fixture
def metrics_collector(monkeypatch):
	monkeypatch.setattr(sys, 'argv', ["opsiconfd"])
	from opsiconfd.statistics import MetricsCollector
	return MetricsCollector()

@pytest.fixture
def metrics_registry(monkeypatch):
	monkeypatch.setattr(sys, 'argv', ["opsiconfd"])
	from opsiconfd.statistics import MetricsRegistry, Metric
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


@pytest.fixture()
@pytest.mark.asyncio
async def redis_client():
	redis_client = redis.StrictRedis.from_url("redis://redis")
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
async def test_execute_redis_command(metrics_collector, redis_client, cmds, expected_results):

	for idx, cmd in enumerate(cmds):
		result = await metrics_collector._execute_redis_command(cmd)
		print(result)
		assert result == expected_results[idx]
		

test_data = [
	("ADD", 4711, "TS.ADD opsiconfd:stats:opsiconfd:pytest:metric * 4711 RETENTION 86400000 LABELS"),
	("INCRBY", 4711,"TS.INCRBY opsiconfd:stats:opsiconfd:pytest:metric 4711 * RETENTION 86400000 LABELS"),
]
@pytest.mark.parametrize("cmd, value, expected_result", test_data)
def test_redis_ts_cmd(metrics_registry, metrics_collector, cmd, value, expected_result):

	metrics = list(metrics_registry.get_metrics()) 

	result = metrics_collector._redis_ts_cmd(metrics[-1], cmd, value)
	print(result)
	assert result == expected_result
	
def test_redis_ts_cmd_error(metrics_registry, metrics_collector):

	metrics = list(metrics_registry.get_metrics()) 

	with pytest.raises(ValueError) as excinfo:
		result = metrics_collector._redis_ts_cmd(metrics[-1], "unknown CMD", 42)
	
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

