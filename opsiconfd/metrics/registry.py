# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
metrics
"""

from __future__ import annotations

from collections.abc import Generator
from typing import TYPE_CHECKING, Any, Self, cast

from opsiconfd.config import config
from opsiconfd.metrics.metric import ALL_METRICS

if TYPE_CHECKING:
	from opsiconfd.metrics.metric import Metric


class MetricsRegistry:
	_instance: MetricsRegistry | None = None

	def __new__(cls, *args: Any, **kwargs: Any) -> Self:
		if not cls._instance:
			cls._instance = super().__new__(cls, *args, **kwargs)
		return cast(Self, cls._instance)

	def __init__(self) -> None:
		if getattr(self, "_initialized", False):
			return
		self._initialized = True
		self._metrics_by_id: dict[str, Metric] = {}
		for metric in ALL_METRICS:
			if config.disabled_metrics and metric.id in config.disabled_metrics:
				continue
			self.register(metric)

	@classmethod
	def reset_singleton(cls) -> None:
		cls._instance = None

	def register(self, *metric: Metric) -> None:
		for met in metric:
			self._metrics_by_id[met.id] = met

	def get_metric_ids(self) -> list[str]:
		return list(self._metrics_by_id)

	def get_metrics(self, *types: type[Metric]) -> Generator[Metric]:
		types = tuple(types)
		for metric in self._metrics_by_id.values():
			if not types or isinstance(metric, types):
				yield metric

	def get_metric_by_id(self, id: str) -> Metric:
		if id in self._metrics_by_id:
			return self._metrics_by_id[id]
		raise ValueError(f"Metric with id '{id}' not found")

	def get_metric_by_name(self, name: str) -> Metric:
		for metric in self._metrics_by_id.values():
			match = metric.name_regex.fullmatch(name)
			if match:
				return metric
		raise ValueError(f"Metric with name '{name}' not found")

	def get_metric_by_redis_key(self, redis_key: str) -> Metric:
		for metric in self._metrics_by_id.values():
			if redis_key == metric.redis_key_prefix or redis_key.startswith(metric.redis_key_prefix + ":"):
				return metric
		raise ValueError(f"Metric with redis key '{redis_key}' not found")
