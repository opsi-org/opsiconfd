# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
statistic tests
"""

import asyncio
from asyncio import sleep
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from opsi.opsi.service.model.object import OpsiClient, OpsiDepotserver
from redis import ResponseError as RedisResponseError

from opsiconfd.config import config as server_config
from opsiconfd.metrics.collector import DepotMetricsCollector, NodeMetricsCollector, WorkerMetricsCollector
from opsiconfd.metrics.metric import ALL_METRICS, AggregationType, DepotMetric, NodeMetric, WorkerMetric, ZeroIfMissingType
from opsiconfd.metrics.registry import MetricsRegistry
from opsiconfd.metrics.statistics import TIME_BUCKET_DURATIONS_MS, _time_series_info, setup_metric_downsampling
from opsiconfd.worker import Worker

from .utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	Config,
	OpsiconfdTestClient,
	clean_mysql,
	clean_redis,
	config,
	get_config,
	test_client,
)


@pytest.fixture(name="metrics_collector")
def fixture_metrics_collector() -> WorkerMetricsCollector:
	return WorkerMetricsCollector(Worker.get_instance())


@pytest.fixture(name="metrics_registry")
def fixture_metrics_registry() -> MetricsRegistry:
	metrics_registry = MetricsRegistry()
	metrics_registry.register(
		WorkerMetric(
			id="opsiconfd:pytest:metric",
			name="opsiconfd pytest metric",
			retention=24 * 3600 * 1000,
			grafana_config=None,
		),
		DepotMetric(
			id="depot:avg_product_data_transfer_slots",
			name="Number of used product data transfer slots for depot {depot_id}",
			retention=2 * 3600 * 1000,
			aggregation=AggregationType.AVG,
			zero_if_missing=ZeroIfMissingType.NONE,
			grafana_config=None,
		),
	)
	return MetricsRegistry()


@pytest.fixture(name="reset_metrics_registry", autouse=True)
def fixture_reset_metrics_registry() -> None:
	MetricsRegistry.reset_singleton()


async def test_metrics_collector_add_value() -> None:
	metric1 = WorkerMetric(
		id="metric1",
		name="metric 1",
		aggregation=AggregationType.SUM,
		zero_if_missing=ZeroIfMissingType.NONE,
	)
	metric2 = WorkerMetric(
		id="metric2",
		name="metric 2",
		aggregation=AggregationType.SUM,
		zero_if_missing=ZeroIfMissingType.ONE,
	)
	metric3 = WorkerMetric(
		id="metric3",
		name="metric 3",
		aggregation=AggregationType.AVG,
		zero_if_missing=ZeroIfMissingType.CONTINUOUS,
	)
	metrics_registry = MetricsRegistry()
	metrics_registry._metrics_by_id = {}
	metrics_registry.register(metric1, metric2, metric3)
	metrics_collector = WorkerMetricsCollector(Worker.get_instance())

	cmds: list[str] = []

	async def _execute_redis_command(*cmd: str) -> None:
		nonlocal cmds
		cmds.extend(cmd)

	metrics_collector._execute_redis_command = _execute_redis_command  # ty: ignore[invalid-assignment]

	await metrics_collector.add_value("metric1", 1)
	await metrics_collector.add_value("metric2", 1)
	await metrics_collector.add_value("metric3", 1)

	await sleep(1.1)

	await metrics_collector.add_value("metric1", 1)
	await metrics_collector.add_value("metric2", 1)
	await metrics_collector.add_value("metric3", 1)

	await metrics_collector._write_values_to_redis()
	assert len(cmds) == 3
	metric_ids = []
	for cmd in cmds:
		assert cmd.endswith("LABELS node_name pytest worker_num 1")
		parts = cmd.split(" ")
		assert len(parts) == 13
		metric_id = parts[1].split(":")[2]
		metric_ids.append(metric_id)
		if metric_id == "metric3":
			# avg - should be 1.0 since we added two values of 1
			assert float(parts[3]) == 1.0
		else:
			# sum
			assert parts[3] == "2"
	assert sorted(metric_ids) == ["metric1", "metric2", "metric3"]

	# No new values
	# metric2 with zero_if_missing=None should add no value
	# metric2 with zero_if_missing="one" should add one value=0
	# metric3 with zero_if_missing="continuous" should add one value=0
	cmds = []
	await sleep(1.1)
	await metrics_collector._write_values_to_redis()
	assert len(cmds) == 2
	metric_ids = []
	for cmd in cmds:
		parts = cmd.split(" ")
		metric_id = parts[1].split(":")[2]
		metric_ids.append(metric_id)
		assert parts[3] == "0"
	assert sorted(metric_ids) == ["metric2", "metric3"]

	# Again no new values
	# metric2 with zero_if_missing=None should add no value
	# metric2 with zero_if_missing="one" should add non value
	# metric3 with zero_if_missing="continuous" should add one value=0
	cmds = []
	await sleep(1.1)
	await metrics_collector._write_values_to_redis()
	assert len(cmds) == 1
	metric_ids = []
	for cmd in cmds:
		parts = cmd.split(" ")
		metric_id = parts[1].split(":")[2]
		metric_ids.append(metric_id)
		assert parts[3] == "0"
	assert sorted(metric_ids) == ["metric3"]

	# Add new values
	# metric2 with zero_if_missing="one" should add an additional zero value before the new values
	cmds = []
	await sleep(1.1)

	await metrics_collector.add_value("metric1", 10)
	await metrics_collector.add_value("metric2", 10)
	await metrics_collector.add_value("metric3", 10)

	await metrics_collector._write_values_to_redis()
	assert len(cmds) == 4
	metric_ids = []
	metric2_values = {}
	for cmd in cmds:
		assert cmd.endswith("LABELS node_name pytest worker_num 1")
		parts = cmd.split(" ")
		assert len(parts) == 13
		metric_id = parts[1].split(":")[2]
		metric_ids.append(metric_id)
		if metric_id == "metric2":
			# timestamp: value
			metric2_values[int(parts[2])] = int(parts[3])

	assert sorted(metric_ids) == ["metric1", "metric2", "metric2", "metric3"]

	sorted_timestamps = sorted(metric2_values)
	assert metric2_values[sorted_timestamps[0]] == 0
	assert metric2_values[sorted_timestamps[1]] == 10
	assert sorted_timestamps[1] - sorted_timestamps[0] == metrics_collector._interval * 1000


async def test_execute_redis_command(
	config: Config,  # noqa: F811
	metrics_collector: WorkerMetricsCollector,
) -> None:
	for cmd, res in (
		(f"SET {config.redis_key('stats')}:num_rpcs 5", b"OK"),
		(f"GET {config.redis_key('stats')}:num_rpcs", b"5"),
		(f"SET {config.redis_key('stats')}:num_rpcs 10", b"OK"),
		(f"GET {config.redis_key('stats')}:num_rpcs", b"10"),
		(f"DEL {config.redis_key('stats')}:num_rpcs", 1),
		(f"DEL {config.redis_key('stats')}:num_rpcs", 0),
	):
		result = await metrics_collector._execute_redis_command(cmd)
		assert result == res


@pytest.mark.parametrize(
	"cmd, value, expected_result",
	[
		("ADD", 4711, "TS.ADD {redis_key_stats}:opsiconfd:pytest:metric * 4711 RETENTION 86400000 ON_DUPLICATE SUM LABELS"),
		("INCRBY", 4711, "TS.INCRBY {redis_key_stats}:opsiconfd:pytest:metric 4711 * RETENTION 86400000 ON_DUPLICATE SUM LABELS"),
	],
)
def test_redis_ts_cmd(
	config: Config,  # noqa: F811
	metrics_registry: MetricsRegistry,
	metrics_collector: WorkerMetricsCollector,
	cmd: str,
	value: int,
	expected_result: str,
) -> None:
	expected_result = expected_result.replace("{redis_key_stats}", config.redis_key("stats"))
	metrics = list(metrics_registry.get_metrics())

	result = metrics_collector._redis_ts_cmd(metrics[-1], cmd, value)
	assert result == expected_result


def test_redis_ts_cmd_error(metrics_registry: MetricsRegistry, metrics_collector: WorkerMetricsCollector) -> None:
	metrics = list(metrics_registry.get_metrics())

	with pytest.raises(ValueError) as excinfo:
		metrics_collector._redis_ts_cmd(metrics[-1], "unknown CMD", 42)

	assert excinfo.type is ValueError
	assert str(excinfo.value) == "Invalid command unknown CMD"


def test_metric_by_redis_key(config: Config, metrics_registry: MetricsRegistry) -> None:  # noqa: F811
	metric = metrics_registry.get_metric_by_redis_key(f"{config.redis_key('stats')}:opsiconfd:pytest:metric")

	assert metric.get_name() == "opsiconfd pytest metric"
	assert metric.id == "opsiconfd:pytest:metric"
	assert metric.get_redis_key() == f"{config.redis_key('stats')}:opsiconfd:pytest:metric"


def test_metric_by_redis_key_error(config: Config, metrics_registry: MetricsRegistry) -> None:  # noqa: F811
	with pytest.raises(ValueError) as excinfo:
		metrics_registry.get_metric_by_redis_key(f"{config.redis_key('stats')}:opsiconfd:notinredis:metric")

	assert excinfo.type is ValueError
	assert str(excinfo.value) == f"Metric with redis key '{config.redis_key('stats')}:opsiconfd:notinredis:metric' not found"


def test_depot_metrics_collector(config: Config, test_client: OpsiconfdTestClient, metrics_registry: MetricsRegistry) -> None:  # noqa: F811
	test_client.auth = (ADMIN_PASS, ADMIN_USER)
	client1 = OpsiClient(id="test-client-1.opsi.org")
	client2 = OpsiClient(id="test-client-2.opsi.org")
	client3 = OpsiClient(id="test-client-3.opsi.org")
	depot1 = OpsiDepotserver(id="test-depot-1.opsi.org")

	test_client.jsonrpc20("host_createObjects", [[client1, client2, client3, depot1]])

	metrics_collector = DepotMetricsCollector(depot1.id)

	# Test initialization
	assert metrics_collector._depot_id == depot1.id
	assert metrics_collector._labels == {"depot_id": depot1.id}
	assert metrics_collector._interval == 30  # 30 seconds interval

	# Test adding values
	cmds: list[str] = []

	async def _execute_redis_command(*cmd: str) -> None:
		nonlocal cmds
		cmds.extend(cmd)

	metrics_collector._execute_redis_command = _execute_redis_command  # ty: ignore[invalid-assignment]

	async def _test_add_values() -> None:
		await metrics_collector.add_value("depot:avg_product_data_transfer_slots", 5)
		await asyncio.sleep(1)
		await metrics_collector.add_value("depot:avg_product_data_transfer_slots", 3)
		await metrics_collector._write_values_to_redis()

	# Run the async test
	asyncio.run(_test_add_values())

	# Verify Redis commands
	assert len(cmds) == 1
	cmd = cmds[0].split()
	assert cmd[0] == "TS.ADD"
	assert cmd[1] == "pytest:stats:depot:avg_product_data_transfer_slots:test-depot-1.opsi.org"
	assert cmd[3] == "4.0"  # avg 5, 3 = 4
	assert cmd[9] == "depot_id"
	assert cmd[10] == "test-depot-1.opsi.org"

	slots = {}
	for client in [client1, client2, client3]:
		slots[client.id] = test_client.jsonrpc20(
			"depot_acquireTransferSlot", {"depot": depot1.id, "host": client.id, "slot_type": "opsiclientd_product_sync"}
		)["result"]

	async def _add_values() -> None:
		await metrics_collector._fetch_values()
		await metrics_collector._write_values_to_redis()

	asyncio.run(_add_values())

	assert len(cmds) == 2
	cmd = cmds[1].split()
	assert cmd[0] == "TS.ADD"
	assert cmd[1] == "pytest:stats:depot:avg_product_data_transfer_slots:test-depot-1.opsi.org"
	assert cmd[3] == "3.0"
	assert cmd[9] == "depot_id"
	assert cmd[10] == "test-depot-1.opsi.org"

	for client in [client1, client2, client3]:
		test_client.jsonrpc20(
			"depot_releaseTransferSlot",
			{"depot": depot1.id, "host": client.id, "slot_id": slots[client.id]["slot_id"], "slot_type": "opsiclientd_product_sync"},
		)

	asyncio.run(_add_values())

	assert len(cmds) == 3
	cmd = cmds[2].split()
	assert cmd[0] == "TS.ADD"
	assert cmd[1] == "pytest:stats:depot:avg_product_data_transfer_slots:test-depot-1.opsi.org"
	assert cmd[3] == "0.0"
	assert cmd[9] == "depot_id"
	assert cmd[10] == "test-depot-1.opsi.org"


def test_node_metrics_collector() -> None:
	metrics_collector = NodeMetricsCollector()

	asyncio.run(metrics_collector._fetch_values())
	assert next(iter(metrics_collector._values["node:avg_load"].values()))
	assert not metrics_collector._values["node:sum_network_bits_sent"]
	assert not metrics_collector._values["node:sum_network_bits_received"]
	assert not metrics_collector._values["node:avg_redis_cpu_time"]
	assert next(iter(metrics_collector._values["node:avg_redis_memory_used"].values()))
	assert metrics_collector._values["node:avg_mysql_processes"]
	assert metrics_collector._values["node:avg_mysql_queries"]

	asyncio.run(metrics_collector._fetch_values())
	assert next(iter(metrics_collector._values["node:avg_load"].values()))
	assert next(iter(metrics_collector._values["node:sum_network_bits_sent"].values()))
	assert next(iter(metrics_collector._values["node:sum_network_bits_received"].values()))
	assert next(iter(metrics_collector._values["node:avg_redis_cpu_time"].values()))
	assert next(iter(metrics_collector._values["node:avg_redis_memory_used"].values()))
	assert metrics_collector._values["node:avg_mysql_processes"]
	assert metrics_collector._values["node:avg_mysql_queries"]


def test_disable_metrics() -> None:
	MetricsRegistry.reset_singleton()
	metrics_registry = MetricsRegistry()
	assert sorted(metrics_registry._metrics_by_id) == sorted(m.id for m in ALL_METRICS)

	with get_config({"disabled_metrics": []}):
		MetricsRegistry.reset_singleton()
		metrics_registry = MetricsRegistry()
		assert sorted(metrics_registry._metrics_by_id) == sorted(m.id for m in ALL_METRICS)

	with get_config({"disabled_metrics": [ALL_METRICS[0].id]}):
		MetricsRegistry.reset_singleton()
		metrics_registry = MetricsRegistry()
		assert sorted(metrics_registry._metrics_by_id) == sorted(m.id for m in ALL_METRICS[1:])

	MetricsRegistry.reset_singleton()


@pytest.mark.parametrize(
	("response", "expected"),
	(
		([b"retentionTime", 1_000, b"rules", []], {"retentionTime": 1_000, "rules": []}),
		({b"retentionTime": 1_000, b"rules": []}, {"retentionTime": 1_000, "rules": []}),
	),
)
def test_time_series_info(response: list[Any] | dict[bytes, Any], expected: dict[str, Any]) -> None:
	"""RedisTimeSeries information supports legacy and parsed response formats."""
	client = MagicMock()
	client.execute_command.return_value = response

	assert _time_series_info(client, "test:key") == expected
	client.execute_command.assert_called_once_with("TS.INFO", "test:key")


def test_setup_metric_downsampling() -> None:
	"""Metric setup creates the expected series, labels, and rules."""
	MetricsRegistry.reset_singleton()
	metrics_registry = MetricsRegistry()
	metrics_registry._metrics_by_id = {}
	metrics_registry.register(
		NodeMetric(id="node:test", name="Node test {node_name}"),
		WorkerMetric(id="worker:test", name="Worker test {worker_num} on {node_name}"),
		DepotMetric(id="depot:test", name="Depot test {depot_id}"),
	)

	class MockRedisClient:
		"""Record Redis commands issued by metric setup."""

		def __init__(self) -> None:
			self.commands: list[tuple[Any, ...]] = []

		def execute_command(self, *command: Any) -> None:
			"""Record a Redis command."""
			self.commands.append(command)

	mock_redis_client = MockRedisClient()

	with (
		patch("opsiconfd.metrics.statistics.redis_client", return_value=mock_redis_client),
		patch("opsiconfd.metrics.statistics.get_unprotected_backend") as get_backend,
	):
		get_backend.return_value.host_getIdents.return_value = ["depot.example.test"]
		setup_metric_downsampling()

	create_commands = [command for command in mock_redis_client.commands if command[0] == "TS.CREATE"]
	rule_commands = [command for command in mock_redis_client.commands if command[0] == "TS.CREATERULE"]
	assert len(create_commands) == (1 + 3) * (1 + 1 + server_config.workers)
	assert len(rule_commands) == 3 * (1 + 1 + server_config.workers)
	assert any(command[5:] == ("node_name", server_config.node_name) for command in create_commands)
	assert any(command[5:] == ("node_name", server_config.node_name, "worker_num", 1) for command in create_commands)
	assert any(command[5:] == ("depot_id", "depot.example.test") for command in create_commands)
	for command in rule_commands:
		name = command[2].rsplit(":", 1)[1]
		assert command[3:] == ("AGGREGATION", "avg", TIME_BUCKET_DURATIONS_MS[name])


def test_setup_metric_downsampling_reconciles_existing_series() -> None:
	"""Metric setup updates changed state and is idempotent afterward."""
	metric = NodeMetric(
		id="node:reconcile-test",
		name="Reconcile test {node_name}",
		retention=2_000,
		downsampling=(("minute", 4_000, AggregationType.AVG), ("hour", 8_000, AggregationType.SUM)),
	)
	metrics_registry = MetricsRegistry()
	metrics_registry._metrics_by_id = {}
	metrics_registry.register(metric)
	orig_key = metric.get_redis_key(node_name=server_config.node_name)
	minute_key = f"{orig_key}:minute"
	hour_key = f"{orig_key}:hour"
	obsolete_key = f"{orig_key}:day"

	class MockRedisClient:
		"""Emulate the RedisTimeSeries commands needed by metric setup."""

		def __init__(self) -> None:
			self.commands: list[tuple[Any, ...]] = []
			self.series: dict[str, dict[str, Any]] = {
				orig_key: {
					"retentionTime": 1_000,
					"rules": [[minute_key, 30_000, "sum"], [obsolete_key, TIME_BUCKET_DURATIONS_MS["day"], "avg"]],
				},
				minute_key: {"retentionTime": 2_000, "rules": []},
				hour_key: {"retentionTime": 8_000, "rules": []},
				obsolete_key: {"retentionTime": 16_000, "rules": []},
			}

		def execute_command(self, *command: Any) -> Any:
			"""Execute a minimal RedisTimeSeries command against local state."""
			self.commands.append(command)
			name, key = command[:2]
			if name == "TS.CREATE":
				if key in self.series:
					raise RedisResponseError("TSDB: key already exists")
				self.series[key] = {"retentionTime": command[3], "rules": []}
				return "OK"
			if name == "TS.INFO":
				info = self.series[key]
				rules = [[rule_key.encode(), bucket, aggregation.encode()] for rule_key, bucket, aggregation in info["rules"]]
				return [b"retentionTime", info["retentionTime"], b"rules", rules]
			if name == "TS.ALTER":
				self.series[key]["retentionTime"] = command[3]
				return "OK"
			if name == "TS.DELETERULE":
				destination = command[2]
				self.series[key]["rules"] = [rule for rule in self.series[key]["rules"] if rule[0] != destination]
				return "OK"
			if name == "TS.CREATERULE":
				self.series[key]["rules"].append([command[2], command[5], command[4]])
				return "OK"
			raise AssertionError(f"Unexpected command: {command}")

		def unlink(self, key: str) -> None:
			"""Delete a time series destination."""
			self.series.pop(key)

	mock_redis_client = MockRedisClient()
	with (
		patch("opsiconfd.metrics.statistics.redis_client", return_value=mock_redis_client),
		patch("opsiconfd.metrics.statistics.get_unprotected_backend") as get_backend,
	):
		get_backend.return_value.host_getIdents.return_value = []
		setup_metric_downsampling()

	assert mock_redis_client.series[orig_key]["retentionTime"] == 2_000
	assert mock_redis_client.series[minute_key]["retentionTime"] == 4_000
	assert mock_redis_client.series[hour_key]["retentionTime"] == 8_000
	assert obsolete_key not in mock_redis_client.series
	assert mock_redis_client.series[orig_key]["rules"] == [
		[minute_key, TIME_BUCKET_DURATIONS_MS["minute"], "avg"],
		[hour_key, TIME_BUCKET_DURATIONS_MS["hour"], "sum"],
	]

	mock_redis_client.commands.clear()
	with (
		patch("opsiconfd.metrics.statistics.redis_client", return_value=mock_redis_client),
		patch("opsiconfd.metrics.statistics.get_unprotected_backend") as get_backend,
	):
		get_backend.return_value.host_getIdents.return_value = []
		setup_metric_downsampling()
	assert not any(command[0] in ("TS.ALTER", "TS.DELETERULE", "TS.CREATERULE") for command in mock_redis_client.commands)
