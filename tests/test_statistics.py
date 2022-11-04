# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
statistic tests
"""

import asyncio
from typing import AsyncGenerator, List

import pytest
from redis import StrictRedis

from opsiconfd.config import config
from opsiconfd.metrics.collector import WorkerMetricsCollector
from opsiconfd.metrics.registry import Metric, MetricsRegistry
from opsiconfd.worker import Worker

from .utils import clean_redis  # pylint: disable=unused-import


@pytest.fixture(name="metrics_collector")
def fixture_metrics_collector() -> WorkerMetricsCollector:
	return WorkerMetricsCollector(Worker.get_instance())


@pytest.fixture(name="metrics_registry")
def fixture_metrics_registry() -> MetricsRegistry:
	metrics_registry = MetricsRegistry()
	metrics_registry.register(
		Metric(
			id="opsiconfd:pytest:metric",
			name="opsiconfd pytest metric",
			vars=["node_name", "worker_num"],
			retention=24 * 3600 * 1000,
			subject="worker",
			grafana_config=None,
		)
	)
	return MetricsRegistry()


async def test_execute_redis_command(metrics_collector: WorkerMetricsCollector) -> None:
	for cmd, res in (
		("SET opsiconfd:stats:num_rpcs 5", b"OK"),
		("GET opsiconfd:stats:num_rpcs", b"5"),
		("SET opsiconfd:stats:num_rpcs 10", b"OK"),
		("GET opsiconfd:stats:num_rpcs", b"10"),
		("DEL opsiconfd:stats:num_rpcs", 1),
		("DEL opsiconfd:stats:num_rpcs", 0),
	):
		result = await metrics_collector._execute_redis_command(cmd)  # pylint: disable=protected-access
		assert result == res


@pytest.mark.parametrize(
	"cmd, value, expected_result",
	[
		("ADD", 4711, "TS.ADD opsiconfd:stats:opsiconfd:pytest:metric * 4711 RETENTION 86400000 ON_DUPLICATE SUM LABELS"),
		("INCRBY", 4711, "TS.INCRBY opsiconfd:stats:opsiconfd:pytest:metric 4711 * RETENTION 86400000 ON_DUPLICATE SUM LABELS"),
	],
)
def test_redis_ts_cmd(
	metrics_registry: MetricsRegistry, metrics_collector: WorkerMetricsCollector, cmd: str, value: int, expected_result: str
) -> None:

	metrics = list(metrics_registry.get_metrics())

	result = metrics_collector._redis_ts_cmd(metrics[-1], cmd, value)  # pylint: disable=protected-access
	assert result == expected_result


def test_redis_ts_cmd_error(metrics_registry: MetricsRegistry, metrics_collector: WorkerMetricsCollector) -> None:
	metrics = list(metrics_registry.get_metrics())

	with pytest.raises(ValueError) as excinfo:
		metrics_collector._redis_ts_cmd(metrics[-1], "unknown CMD", 42)  # pylint: disable=protected-access

	assert excinfo.type == ValueError
	assert str(excinfo.value) == "Invalid command unknown CMD"


def test_metric_by_redis_key(metrics_registry: MetricsRegistry) -> None:

	metric = metrics_registry.get_metric_by_redis_key("opsiconfd:stats:opsiconfd:pytest:metric")

	assert metric.get_name() == "opsiconfd pytest metric"
	assert metric.id == "opsiconfd:pytest:metric"
	assert metric.get_redis_key() == "opsiconfd:stats:opsiconfd:pytest:metric"


def test_metric_by_redis_key_error(metrics_registry: MetricsRegistry) -> None:

	with pytest.raises(ValueError) as excinfo:
		metrics_registry.get_metric_by_redis_key("opsiconfd:stats:opsiconfd:notinredis:metric")

	assert excinfo.type == ValueError
	assert str(excinfo.value) == "Metric with redis key 'opsiconfd:stats:opsiconfd:notinredis:metric' not found"
