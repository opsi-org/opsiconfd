# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
Tests for the monitoring integration
"""

from __future__ import annotations

import json
from collections.abc import Callable, Generator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from opsi.exception import (
	BackendBadValueError,
	BackendConfigurationError,
	BackendMissingDataError,
	BackendPermissionDeniedError,
	BackendUnableToConnectError,
	BackendUnaccomplishableError,
)
from opsi.opsi.service.model.object import ConfigState, OpsiClient, UnicodeConfig

from opsiconfd.backend.monitoring import Downtime, MonitoringClient, MonitoringConfig, get_monitoring_client
from opsiconfd.backend.monitoring.checkmk import CheckmkClient
from opsiconfd.backend.rpc.main import UnprotectedBackend
from opsiconfd.setup.files import MONITORING_ACL_LINES, migrate_acl_conf_add_monitoring

from .utils import backend, clean_mysql, default_acl, get_config  # noqa: F401

CLIENT_ID = "monitoring-test1.opsi.test"
OTHER_CLIENT_ID = "monitoring-test2.opsi.test"
PREFIX = "[opsi]"


# --- MonitoringConfig ---


def test_monitoring_config_defaults() -> None:
	cfg = MonitoringConfig()
	assert not cfg.enabled
	assert cfg.type == "checkmk"
	assert cfg.max_downtime_duration == 14400
	assert cfg.comment_prefix == PREFIX


def test_monitoring_config_from_dict() -> None:
	cfg = MonitoringConfig.from_dict(
		{
			"enabled": "true",
			"type": "Checkmk",
			"url": "https://checkmk.test/site/",
			"apiVersion": "v1",
			"username": "automation",
			"secret": "topsecret",
			"verifySsl": "/ca.pem",
			"timeout": 3,
			"maxDowntimeDuration": 60,
			"commentPrefix": "  ",
		}
	)
	assert cfg.enabled
	assert cfg.type == "checkmk"
	assert cfg.url == "https://checkmk.test/site"
	assert cfg.api_version == "v1"
	assert cfg.verify_ssl == "/ca.pem"
	assert cfg.timeout == 3.0
	assert cfg.max_downtime_duration == 60
	# Empty prefix is replaced by the default
	assert cfg.comment_prefix == PREFIX
	assert "topsecret" not in repr(cfg)


@pytest.mark.parametrize(
	"cfg, message",
	(
		(MonitoringConfig(enabled=True), "No url"),
		(MonitoringConfig(enabled=True, url="checkmk.test"), "http"),
		(MonitoringConfig(enabled=True, url="https://checkmk.test", type="unknown"), "Unsupported"),
	),
)
def test_get_monitoring_client_invalid_config(cfg: MonitoringConfig, message: str) -> None:
	with pytest.raises(BackendConfigurationError, match=message):
		get_monitoring_client(cfg)


def test_get_monitoring_client_checkmk() -> None:
	client = get_monitoring_client(MonitoringConfig(enabled=True, url="https://checkmk.test/site"))
	assert isinstance(client, CheckmkClient)


# --- CheckmkClient ---


@contextmanager
def mock_checkmk(handler: Callable[[httpx.Request], httpx.Response]) -> Generator[None]:
	real_client = httpx.Client

	def client_factory(**kwargs: object) -> httpx.Client:
		kwargs.pop("verify", None)
		return real_client(transport=httpx.MockTransport(handler), **kwargs)  # ty: ignore[invalid-argument-type]

	with (
		patch("opsiconfd.backend.monitoring.checkmk.httpx.Client", client_factory),
		patch("opsiconfd.backend.monitoring.checkmk.LOOKUP_INTERVAL", 0),
	):
		yield


def get_checkmk_client() -> CheckmkClient:
	return CheckmkClient(MonitoringConfig(enabled=True, url="https://checkmk.test/site", username="automation", secret="secret"))


def downtime_entry(downtime_id: int, host: str, service: str | None, comment: str) -> dict:
	return {
		"id": str(downtime_id),
		"extensions": {
			"id": downtime_id,
			"host_name": host,
			"service_description": service,
			"start_time": "2026-01-01T10:00:00+00:00",
			"end_time": "2026-01-01T11:00:00+00:00",
			"comment": comment,
			"site_id": "site",
		},
	}


@pytest.mark.parametrize("services", ([], ["Service nginx", "Service ssh"]))
def test_checkmk_set_downtime(services: list[str]) -> None:
	requests: list[httpx.Request] = []
	bodies: list[dict] = []

	def handler(request: httpx.Request) -> httpx.Response:
		requests.append(request)
		if request.method == "POST":
			bodies.append(json.loads(request.content))
			return httpx.Response(204)
		service = services[0] if services else None
		return httpx.Response(
			200,
			json={
				"value": [
					downtime_entry(1, "host1", None, "other downtime"),
					downtime_entry(7, "host1", service, bodies[0]["comment"]),
				]
			},
		)

	start = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
	end = start + timedelta(hours=1)
	with mock_checkmk(handler):
		downtimes = get_checkmk_client().set_downtime("host1", services, start, end, f"{PREFIX} Update")

	post = requests[0]
	downtime_type = "service" if services else "host"
	assert post.method == "POST"
	assert post.url.path == f"/site/check_mk/api/1.0/domain-types/downtime/collections/{downtime_type}"
	assert post.headers["Authorization"] == "Bearer automation secret"
	body = bodies[0]
	assert body["downtime_type"] == downtime_type
	assert body["host_name"] == "host1"
	assert body["start_time"] == "2026-01-01T10:00:00+00:00"
	assert body["end_time"] == "2026-01-01T11:00:00+00:00"
	assert body["comment"].startswith(f"{PREFIX} Update #")
	if services:
		assert body["service_descriptions"] == services
	else:
		assert "service_descriptions" not in body

	assert len(downtimes) == 1
	assert downtimes[0].id == "7"
	assert downtimes[0].site_id == "site"
	assert downtimes[0].service == (services[0] if services else None)


def test_checkmk_set_downtime_ids_not_found() -> None:
	def handler(request: httpx.Request) -> httpx.Response:
		if request.method == "POST":
			return httpx.Response(204)
		return httpx.Response(200, json={"value": []})

	start = datetime.now(UTC)
	with mock_checkmk(handler):
		assert get_checkmk_client().set_downtime("host1", [], start, start + timedelta(hours=1), f"{PREFIX} Update") == []


def test_checkmk_get_downtimes_ignores_invalid_entries() -> None:
	def handler(request: httpx.Request) -> httpx.Response:
		assert request.url.params["host_name"] == "host1"
		return httpx.Response(200, json={"value": [downtime_entry(1, "host1", None, "c"), {"id": "2", "extensions": {}}]})

	with mock_checkmk(handler):
		downtimes = get_checkmk_client().get_downtimes("host1")
	assert [d.id for d in downtimes] == ["1"]


def test_checkmk_delete_downtimes() -> None:
	bodies: list[dict] = []

	def handler(request: httpx.Request) -> httpx.Response:
		assert request.url.path == "/site/check_mk/api/1.0/domain-types/downtime/actions/delete/invoke"
		bodies.append(json.loads(request.content))
		return httpx.Response(204)

	now = datetime.now(UTC)
	downtimes = [
		Downtime(id="1", host="host1", service=None, start=now, end=now, comment="c", site_id="site"),
		Downtime(id="2", host="host1", service="svc", start=now, end=now, comment="c"),
	]
	with mock_checkmk(handler):
		get_checkmk_client().delete_downtimes(downtimes)
	assert bodies == [
		{"delete_type": "by_id", "downtime_id": "1", "site_id": "site"},
		{"delete_type": "by_id", "downtime_id": "2"},
	]


def test_checkmk_check_connection() -> None:
	def handler(request: httpx.Request) -> httpx.Response:
		assert request.url.path == "/site/check_mk/api/1.0/version"
		return httpx.Response(200, json={"site": "site", "edition": "community", "versions": {"checkmk": "2.4.0"}})

	with mock_checkmk(handler):
		assert get_checkmk_client().check_connection() == {"site": "site", "version": "2.4.0", "edition": "community"}


@pytest.mark.parametrize(
	"status, exception",
	(
		(400, BackendBadValueError),
		(404, BackendMissingDataError),
		(401, BackendUnaccomplishableError),
		(403, BackendUnaccomplishableError),
		(500, BackendUnaccomplishableError),
	),
)
def test_checkmk_error_mapping(status: int, exception: type[Exception]) -> None:
	def handler(request: httpx.Request) -> httpx.Response:
		return httpx.Response(status, json={"title": "Failed", "detail": "Something is wrong"})

	with mock_checkmk(handler), pytest.raises(exception, match="Something is wrong"):
		get_checkmk_client().check_connection()


def test_checkmk_connection_error() -> None:
	def handler(request: httpx.Request) -> httpx.Response:
		raise httpx.ConnectError("refused")

	with mock_checkmk(handler), pytest.raises(BackendUnableToConnectError):
		get_checkmk_client().check_connection()


# --- RPC methods ---


class FakeMonitoringClient(MonitoringClient):
	def __init__(self) -> None:
		super().__init__(MonitoringConfig(enabled=True, url="http://monitoring.test"))
		self.downtimes: list[Downtime] = []
		self._next_id = 1

	def _add(self, host: str, service: str | None, start: datetime, end: datetime, comment: str) -> Downtime:
		downtime = Downtime(id=str(self._next_id), host=host, service=service, start=start, end=end, comment=comment)
		self._next_id += 1
		self.downtimes.append(downtime)
		return downtime

	def check_connection(self) -> dict:
		return {"version": "2.4.0"}

	def get_downtimes(self, host: str) -> list[Downtime]:
		return [downtime for downtime in self.downtimes if downtime.host == host]

	def set_downtime(self, host: str, services: list[str], start: datetime, end: datetime, comment: str) -> list[Downtime]:
		return [self._add(host, service, start, end, comment) for service in services or [None]]  # ty: ignore[invalid-argument-type]

	def delete_downtimes(self, downtimes: list[Downtime]) -> None:
		ids = {downtime.id for downtime in downtimes}
		self.downtimes = [downtime for downtime in self.downtimes if downtime.id not in ids]


@pytest.fixture
def monitoring(backend: UnprotectedBackend) -> Generator[FakeMonitoringClient]:  # noqa: F811
	fake = FakeMonitoringClient()
	cfg = MonitoringConfig(enabled=True, url="http://monitoring.test", max_downtime_duration=3600)
	with (
		patch("opsiconfd.backend.rpc.monitoring.get_monitoring_client", return_value=fake),
		patch.object(backend, "_monitoring_config", cfg),
		patch.object(backend, "_assert_module"),
	):
		backend.host_createObjects([OpsiClient(id=CLIENT_ID), OpsiClient(id=OTHER_CLIENT_ID)])
		yield fake


def test_monitoring_get_info(backend: UnprotectedBackend, monitoring: FakeMonitoringClient) -> None:  # noqa: F811
	assert backend.monitoring_getInfo() == {"enabled": True, "type": "checkmk", "maxDowntimeDuration": 3600}


def test_monitoring_disabled(backend: UnprotectedBackend) -> None:  # noqa: F811
	with patch.object(backend, "_monitoring_config", MonitoringConfig()), patch.object(backend, "_assert_module"):
		assert backend.monitoring_getInfo()["enabled"] is False
		with pytest.raises(BackendConfigurationError, match="not enabled"):
			backend.monitoring_setDowntime(duration=60, hostId=CLIENT_ID)
		with pytest.raises(BackendConfigurationError, match="not enabled"):
			backend.monitoring_removeDowntime(hostId=CLIENT_ID)
		with pytest.raises(BackendConfigurationError, match="not enabled"):
			backend.monitoring_checkConnection()


def test_monitoring_check_connection(backend: UnprotectedBackend, monitoring: FakeMonitoringClient) -> None:  # noqa: F811
	assert backend.monitoring_checkConnection() == {"version": "2.4.0"}


def test_monitoring_set_host_downtime_as_client(backend: UnprotectedBackend, monitoring: FakeMonitoringClient) -> None:  # noqa: F811
	with patch.object(backend, "_get_client_id", return_value=CLIENT_ID):
		result = backend.monitoring_setDowntime(duration=600, comment="  Update\nof  nginx ")

	assert result["hostId"] == CLIENT_ID
	assert result["monitoringHost"] == CLIENT_ID
	assert result["services"] == []
	assert (datetime.fromisoformat(result["end"]) - datetime.fromisoformat(result["start"])).total_seconds() == 600
	assert len(result["downtimeIds"]) == 1
	assert len(monitoring.downtimes) == 1
	assert monitoring.downtimes[0].host == CLIENT_ID
	assert monitoring.downtimes[0].service is None
	assert monitoring.downtimes[0].comment == f"{PREFIX} Update of nginx"


def test_monitoring_set_service_downtime(backend: UnprotectedBackend, monitoring: FakeMonitoringClient) -> None:  # noqa: F811
	with patch.object(backend, "_get_client_id", return_value=CLIENT_ID):
		result = backend.monitoring_setDowntime(duration=600, services=["Service nginx", "Service nginx", " Service ssh "])
	assert result["services"] == ["Service nginx", "Service ssh"]
	assert [d.service for d in monitoring.downtimes] == ["Service nginx", "Service ssh"]
	assert monitoring.downtimes[0].comment == f"{PREFIX} Maintenance"


def test_monitoring_client_can_only_use_own_host(backend: UnprotectedBackend, monitoring: FakeMonitoringClient) -> None:  # noqa: F811
	with patch.object(backend, "_get_client_id", return_value=CLIENT_ID):
		backend.monitoring_setDowntime(duration=60, hostId=CLIENT_ID)
		for method in (backend.monitoring_setDowntime, backend.monitoring_removeDowntime, backend.monitoring_getDowntimes):
			kwargs = {"duration": 60} if method == backend.monitoring_setDowntime else {}
			with pytest.raises(BackendPermissionDeniedError):
				method(hostId=OTHER_CLIENT_ID, **kwargs)
	assert len(monitoring.downtimes) == 1


def test_monitoring_non_client_requires_existing_host(backend: UnprotectedBackend, monitoring: FakeMonitoringClient) -> None:  # noqa: F811
	with pytest.raises(BackendBadValueError, match="hostId"):
		backend.monitoring_setDowntime(duration=60)
	with pytest.raises(BackendMissingDataError, match="not found"):
		backend.monitoring_setDowntime(duration=60, hostId="unknown.opsi.test")

	result = backend.monitoring_setDowntime(duration=60, hostId=OTHER_CLIENT_ID)
	assert result["hostId"] == OTHER_CLIENT_ID
	assert monitoring.downtimes[0].host == OTHER_CLIENT_ID


@pytest.mark.parametrize("duration", (0, -1, 3601))
def test_monitoring_invalid_duration(backend: UnprotectedBackend, monitoring: FakeMonitoringClient, duration: int) -> None:  # noqa: F811
	with pytest.raises(BackendBadValueError, match="Duration"):
		backend.monitoring_setDowntime(duration=duration, hostId=CLIENT_ID)
	assert not monitoring.downtimes


@pytest.mark.parametrize("services", ([""], ["a" * 257], ["bad\nservice"], [f"service{i}" for i in range(51)]))
def test_monitoring_invalid_services(backend: UnprotectedBackend, monitoring: FakeMonitoringClient, services: list[str]) -> None:  # noqa: F811
	with pytest.raises(BackendBadValueError):
		backend.monitoring_setDowntime(duration=60, hostId=CLIENT_ID, services=services)
	assert not monitoring.downtimes


def test_monitoring_host_name_config_state(backend: UnprotectedBackend, monitoring: FakeMonitoringClient) -> None:  # noqa: F811
	backend.config_createObjects(
		UnicodeConfig(id="monitoring.host_name", possibleValues=[], defaultValues=[], editable=True, multiValue=False)
	)
	backend.configState_createObjects(ConfigState(configId="monitoring.host_name", objectId=CLIENT_ID, values=["short-name"]))

	result = backend.monitoring_setDowntime(duration=60, hostId=CLIENT_ID)
	assert result["monitoringHost"] == "short-name"
	result = backend.monitoring_setDowntime(duration=60, hostId=OTHER_CLIENT_ID)
	assert result["monitoringHost"] == OTHER_CLIENT_ID
	assert sorted(d.host for d in monitoring.downtimes) == sorted(["short-name", OTHER_CLIENT_ID])


def test_monitoring_get_and_remove_downtimes(backend: UnprotectedBackend, monitoring: FakeMonitoringClient) -> None:  # noqa: F811
	now = datetime.now(UTC)
	foreign = monitoring._add(CLIENT_ID, None, now, now, "Manual downtime")
	other_host = monitoring._add(OTHER_CLIENT_ID, None, now, now, f"{PREFIX} Other host")
	host_dt = backend.monitoring_setDowntime(duration=60, hostId=CLIENT_ID)["downtimeIds"][0]
	service_ids = []
	for service in ("svc1", "svc2"):
		service_ids.append(backend.monitoring_setDowntime(duration=60, hostId=CLIENT_ID, services=[service])["downtimeIds"][0])

	downtimes = backend.monitoring_getDowntimes(hostId=CLIENT_ID)
	assert sorted(d["id"] for d in downtimes) == sorted([host_dt, *service_ids])
	assert [d["id"] for d in backend.monitoring_getDowntimes(hostId=CLIENT_ID, services=["svc1"])] == [service_ids[0]]

	# Remove by id
	assert backend.monitoring_removeDowntime(downtimeIds=[host_dt, foreign.id], hostId=CLIENT_ID)["removed"] == 1
	# Remove by service
	assert backend.monitoring_removeDowntime(services=["svc1"], hostId=CLIENT_ID)["removed"] == 1
	assert [d["id"] for d in backend.monitoring_getDowntimes(hostId=CLIENT_ID)] == [service_ids[1]]
	# Remove all opsi downtimes of the host
	assert backend.monitoring_removeDowntime(hostId=CLIENT_ID)["removed"] == 1
	assert backend.monitoring_removeDowntime(hostId=CLIENT_ID)["removed"] == 0

	# Downtimes not created by opsi and downtimes of other hosts are untouched
	assert sorted(d.id for d in monitoring.downtimes) == sorted([foreign.id, other_host.id])


# --- Config file ---


def test_read_monitoring_config_file(backend: UnprotectedBackend, tmp_path: Path) -> None:  # noqa: F811
	conf = tmp_path / "monitoring.conf"
	conf.write_text(
		'module = "Monitoring"\nconfig = {"enabled": True, "url": "https://checkmk.test/site", "secret": "s3cr3t", "maxDowntimeDuration": 120}\n',
		encoding="utf-8",
	)
	with patch.object(backend, "_monitoring_config", backend._monitoring_config), get_config({"backend_config_dir": str(tmp_path)}):
		backend._read_monitoring_config_file()
		assert backend._monitoring_config.enabled
		assert backend._monitoring_config.url == "https://checkmk.test/site"
		assert backend._monitoring_config.secret == "s3cr3t"
		assert backend._monitoring_config.max_downtime_duration == 120

		# Invalid file disables the integration
		conf.write_text("config = {", encoding="utf-8")
		backend._read_monitoring_config_file()
		assert not backend._monitoring_config.enabled

		# Missing file disables the integration
		conf.unlink()
		backend._read_monitoring_config_file()
		assert not backend._monitoring_config.enabled


def test_default_monitoring_conf() -> None:
	conf = Path("opsiconfd_data/etc/backends/monitoring.conf")
	loc: dict = {}
	exec(compile(conf.read_bytes(), "<string>", "exec"), None, loc)  # noqa: S102
	cfg = MonitoringConfig.from_dict(loc["config"])
	assert cfg == MonitoringConfig(username="automation")


# --- Client protection of config state ---


def test_client_cannot_write_monitoring_host_name(backend: UnprotectedBackend, monitoring: FakeMonitoringClient) -> None:  # noqa: F811
	config_state = ConfigState(configId="monitoring.host_name", objectId=CLIENT_ID, values=[OTHER_CLIENT_ID])
	with patch.object(backend, "_get_client_id", return_value=CLIENT_ID):
		for method in (
			backend.configState_createObjects,
			backend.configState_updateObjects,
			backend.configState_insertObject,
			backend.configState_updateObject,
		):
			with pytest.raises(BackendPermissionDeniedError):
				method(config_state)
	assert not backend.configState_getObjects(configId="monitoring.host_name")


# --- ACL ---


def test_default_acl_monitoring(default_acl: dict) -> None:  # noqa: F811
	def types(method: str) -> set[str]:
		return {ace.type for ace in default_acl[method]}

	assert types("monitoring_checkConnection") == {"sys_group"}
	assert types("monitoring_getInfo") == {"sys_group", "opsi_depotserver", "opsi_client"}
	for method in ("monitoring_setDowntime", "monitoring_removeDowntime", "monitoring_getDowntimes"):
		assert types(method) == {"sys_group", "opsi_depotserver", "self"}


def test_migrate_acl_conf_add_monitoring(tmp_path: Path) -> None:
	default_acl_conf = Path("opsiconfd_data/etc/backendManager/acl.conf").read_text(encoding="utf-8")
	for line in MONITORING_ACL_LINES:
		assert line in default_acl_conf.split("\n")

	old_acl_conf = "\n".join(line for line in default_acl_conf.split("\n") if not line.startswith("monitoring_"))
	assert "monitoring_" not in old_acl_conf
	acl_file = tmp_path / "acl.conf"
	acl_file.write_text(old_acl_conf, encoding="utf-8")

	with get_config({"acl_file": str(acl_file)}):
		migrate_acl_conf_add_monitoring()
		migrated = acl_file.read_text(encoding="utf-8")
		migrated_lines = migrated.split("\n")
		get_all_idx = next(idx for idx, line in enumerate(migrated_lines) if line.startswith(".*_get.*"))
		assert migrated_lines.index(MONITORING_ACL_LINES[-1]) < get_all_idx
		assert tuple(line for line in migrated_lines if line.startswith("monitoring_")) == MONITORING_ACL_LINES
		assert [line for line in migrated_lines if not line.startswith("monitoring_")] == old_acl_conf.split("\n")
		assert (tmp_path / "acl.conf.pre-monitoring").read_text(encoding="utf-8") == old_acl_conf

		# Second run changes nothing
		(tmp_path / "acl.conf.pre-monitoring").unlink()
		migrate_acl_conf_add_monitoring()
		assert acl_file.read_text(encoding="utf-8") == migrated
		assert not (tmp_path / "acl.conf.pre-monitoring").exists()


def test_migrate_acl_conf_add_monitoring_without_catch_all(tmp_path: Path) -> None:
	acl_file = tmp_path / "acl.conf"
	acl_file.write_text("host_get.* : sys_group({admingroup})\n", encoding="utf-8")
	with get_config({"acl_file": str(acl_file)}):
		migrate_acl_conf_add_monitoring()
	lines = acl_file.read_text(encoding="utf-8").split("\n")
	assert lines[0] == "host_get.* : sys_group({admingroup})"
	assert tuple(lines[1:4]) == MONITORING_ACL_LINES
