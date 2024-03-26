# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
statistic tests
"""

from asyncio import sleep

import pytest

from opsiconfd.metrics.collector import WorkerMetricsCollector
from opsiconfd.metrics.registry import MetricsRegistry, WorkerMetric
from opsiconfd.worker import Worker

from .utils import (  # noqa: F401
	Config,
	clean_redis,
	config,
	reset_singleton,
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
		)
	)
	return MetricsRegistry()


@pytest.fixture(name="reset_metrics_registry", autouse=True)
def fixture_reset_metrics_registry() -> None:
	reset_singleton(MetricsRegistry)


async def test_metrics_collector_add_value() -> None:
	metric1 = WorkerMetric(
		id="metric1",
		name="metric 1",
		aggregation="sum",
		zero_if_missing=None,
	)
	metric2 = WorkerMetric(
		id="metric2",
		name="metric 2",
		aggregation="sum",
		zero_if_missing="one",
	)
	metric3 = WorkerMetric(
		id="metric3",
		name="metric 3",
		aggregation="avg",
		zero_if_missing="continuous",
	)
	metrics_registry = MetricsRegistry()
	metrics_registry._metrics_by_id = {}
	metrics_registry.register(metric1, metric2, metric3)
	metrics_collector = WorkerMetricsCollector(Worker.get_instance())

	cmds: list[str] = []

	async def _execute_redis_command(*cmd: str) -> None:
		nonlocal cmds
		cmds.extend(cmd)

	metrics_collector._execute_redis_command = _execute_redis_command  # type: ignore[assignment]

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
			# avg
			assert parts[3] == "1.0"
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

	assert excinfo.type == ValueError
	assert str(excinfo.value) == "Invalid command unknown CMD"


def test_metric_by_redis_key(config: Config, metrics_registry: MetricsRegistry) -> None:  # noqa: F811
	metric = metrics_registry.get_metric_by_redis_key(f"{config.redis_key('stats')}:opsiconfd:pytest:metric")

	assert metric.get_name() == "opsiconfd pytest metric"
	assert metric.id == "opsiconfd:pytest:metric"
	assert metric.get_redis_key() == f"{config.redis_key('stats')}:opsiconfd:pytest:metric"


def test_metric_by_redis_key_error(config: Config, metrics_registry: MetricsRegistry) -> None:  # noqa: F811
	with pytest.raises(ValueError) as excinfo:
		metrics_registry.get_metric_by_redis_key(f"{config.redis_key('stats')}:opsiconfd:notinredis:metric")

	assert excinfo.type == ValueError
	assert str(excinfo.value) == f"Metric with redis key '{config.redis_key('stats')}:opsiconfd:notinredis:metric' not found"
