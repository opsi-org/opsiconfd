import os
import sys
import pytest
import redis
import json
import asyncio
import time

from opsiconfd.statistics import MetricsCollector


@pytest.fixture(scope="session")
def event_loop(request):
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


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
	time.sleep(5)
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
		time.sleep(5)

	# result = await redis_client.get("opsiconfd:stats:num_rpcs")
	# print(result)
	# assert result == b"10"

@pytest.mark.asyncio
async def test_redis_ts_cmd(metrics_registry, metrics_collector):

	metrics = list(metrics_registry.get_metrics()) 
	# for metric in :
	# 	print(metric.id)

	result = metrics_collector._redis_ts_cmd(metrics[-1], "ADD", 4711)
	print(result)
	assert result == "TS.ADD opsiconfd:stats:opsiconfd:pytest:metric * 4711 RETENTION 86400000 LABELS"
	