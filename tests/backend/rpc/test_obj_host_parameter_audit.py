# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
test opsiconfd.backend.rpc host parameter audit logging
"""

from opsi.opsi.service.model.object import AuditLogEventType, ConfigState, OpsiClient, OpsiDepotserver, UnicodeConfig

from opsiconfd.backend.mysql import MySQLSession
from tests.utils import (  # noqa: F401
	UnprotectedBackend,
	backend,
	clean_mysql,
	clean_redis,
	get_config,
)


def _assert_host_parameter_message(
	message: str | None,
	scope: str,
	config_id: str,
	new_value: list[str] | None,
	username: str,
	host_id: str | None = None,
) -> None:
	assert message
	target = host_id or "server default"
	if new_value is None:
		expected_message = f"{config_id} was deleted by {username} for {target}."
	else:
		new_value_text = ", ".join(str(value) for value in new_value)
		expected_message = f"{config_id} was changed to '{new_value_text}' by {username} for {target}."
	assert message == expected_message


def test_host_parameter_default_server_value_audit_on_config_update_objects(backend: UnprotectedBackend) -> None:  # noqa: F811
	config = UnicodeConfig(
		id="test-host-parameter-audit-default-value",
		possibleValues=["enabled", "disabled"],
		defaultValues=["enabled"],
		editable=True,
		multiValue=False,
	)

	with get_config(
		{
			"audit_log_enabled": True,
			"audit_log_events": [AuditLogEventType.CONFIG_VALUE_SET.value],
		}
	):
		backend.config_updateObjects([config])

	audit_logs = backend.auditLog_getObjects(filter={"eventType": AuditLogEventType.CONFIG_VALUE_SET})
	assert len(audit_logs) == 1
	assert audit_logs[0].created
	assert audit_logs[0].actorType is None
	assert audit_logs[0].actorId == "opsiconfd"
	assert audit_logs[0].config
	assert audit_logs[0].config.configId == config.id
	assert audit_logs[0].config.scope == "default"
	assert audit_logs[0].config.newValue == ["enabled"]
	_assert_host_parameter_message(
		audit_logs[0].message,
		scope="default",
		config_id=config.id,
		new_value=["enabled"],
		username="opsiconfd",
	)


def test_host_parameter_config_state_audit_for_depot_and_client(backend: UnprotectedBackend) -> None:  # noqa: F811
	config_id = "test-host-parameter-audit-config-state-values"
	config = UnicodeConfig(
		id=config_id,
		possibleValues=["depot", "client"],
		defaultValues=["client"],
		editable=True,
		multiValue=False,
	)
	client = OpsiClient(id="test-host-parameter-audit-client.opsi.test", opsiHostKey="2bec332f4241b5aa0f13d149f9bac3bc")
	depot = OpsiDepotserver(id="test-host-parameter-audit-depot.opsi.test", opsiHostKey="32755d9188cd7f8a76f2281df2ab602e")
	backend.config_createObjects([config])
	backend.host_createObjects([client, depot])

	with get_config(
		{
			"audit_log_enabled": True,
			"audit_log_events": [AuditLogEventType.CONFIG_VALUE_SET.value],
		}
	):
		backend.configState_createObjects(
			[
				ConfigState(configId=config_id, objectId=depot.id, values=["depot"]),
				ConfigState(configId=config_id, objectId=client.id, values=["client"]),
			]
		)

	audit_logs = backend.auditLog_getObjects(filter={"eventType": AuditLogEventType.CONFIG_VALUE_SET})

	assert len(audit_logs) == 2
	logs_by_host_id = {audit_log.hostId: audit_log for audit_log in audit_logs}
	assert logs_by_host_id[depot.id].config
	assert logs_by_host_id[depot.id].config.configId == config_id
	assert logs_by_host_id[depot.id].config.scope == "depot"
	assert logs_by_host_id[depot.id].config.newValue == ["depot"]
	assert logs_by_host_id[client.id].config
	assert logs_by_host_id[client.id].config.configId == config_id
	assert logs_by_host_id[client.id].config.scope == "client"
	assert logs_by_host_id[client.id].config.newValue == ["client"]
	_assert_host_parameter_message(
		logs_by_host_id[depot.id].message,
		scope="depot",
		config_id=config_id,
		new_value=["depot"],
		username="opsiconfd",
		host_id=depot.id,
	)
	_assert_host_parameter_message(
		logs_by_host_id[client.id].message,
		scope="client",
		config_id=config_id,
		new_value=["client"],
		username="opsiconfd",
		host_id=client.id,
	)


def test_host_parameter_audit_event_selection_for_config_state_values(backend: UnprotectedBackend) -> None:  # noqa: F811
	config_id = "test-host-parameter-audit-event-selection"
	config = UnicodeConfig(
		id=config_id,
		possibleValues=["depot", "client"],
		defaultValues=["client"],
		editable=True,
		multiValue=False,
	)
	client = OpsiClient(id="test-host-parameter-audit-selected-client.opsi.test", opsiHostKey="12666ded4b9c95c93a8688508113fa8f")
	depot = OpsiDepotserver(id="test-host-parameter-audit-selected-depot.opsi.test", opsiHostKey="87f67dfdb9ee26db95ff713f0f85bb81")
	backend.config_createObjects([config])
	backend.host_createObjects([client, depot])

	with get_config(
		{
			"audit_log_enabled": True,
			"audit_log_events": [AuditLogEventType.CONFIG_VALUE_SET.value],
		}
	):
		backend.configState_updateObjects(
			[
				ConfigState(configId=config_id, objectId=depot.id, values=["depot"]),
				ConfigState(configId=config_id, objectId=client.id, values=["client"]),
			]
		)

	audit_logs = backend.auditLog_getObjects(filter={"eventType": AuditLogEventType.CONFIG_VALUE_SET})
	assert len(audit_logs) == 2
	logs_by_host_id = {audit_log.hostId: audit_log for audit_log in audit_logs}
	assert logs_by_host_id[depot.id].config
	assert logs_by_host_id[depot.id].config.configId == config_id
	assert logs_by_host_id[depot.id].config.scope == "depot"
	assert logs_by_host_id[depot.id].config.newValue == ["depot"]
	assert logs_by_host_id[client.id].config
	assert logs_by_host_id[client.id].config.configId == config_id
	assert logs_by_host_id[client.id].config.scope == "client"
	assert logs_by_host_id[client.id].config.newValue == ["client"]
	_assert_host_parameter_message(
		logs_by_host_id[client.id].message,
		scope="client",
		config_id=config_id,
		new_value=["client"],
		username="opsiconfd",
		host_id=client.id,
	)
	_assert_host_parameter_message(
		logs_by_host_id[depot.id].message,
		scope="depot",
		config_id=config_id,
		new_value=["depot"],
		username="opsiconfd",
		host_id=depot.id,
	)


def test_host_parameter_audit_uses_bulk_insert_for_config_state_update_objects(backend: UnprotectedBackend) -> None:  # noqa: F811
	config_id = "test-host-parameter-audit-bulk-insert"
	config = UnicodeConfig(
		id=config_id,
		possibleValues=["value"],
		defaultValues=["value"],
		editable=True,
		multiValue=False,
	)
	backend.config_createObjects([config])

	clients = [
		OpsiClient(
			id=f"test-host-parameter-audit-bulk-client-{idx}.opsi.test",
			opsiHostKey=f"{idx + 1:032x}",
		)
		for idx in range(25)
	]
	backend.host_createObjects(clients)
	config_states = [ConfigState(configId=config_id, objectId=client.id, values=["value"]) for client in clients]
	insert_counts = {"AUDIT_LOG": 0, "AUDIT_CONFIG": 0}

	def query_log(*args: object) -> None:
		statement = str(args[2])
		for table in insert_counts:
			if f"INSERT INTO `{table}`" in statement:
				insert_counts[table] += 1

	old_query_log = MySQLSession.query_log
	MySQLSession.query_log = query_log
	try:
		with get_config(
			{
				"audit_log_enabled": True,
				"audit_log_events": [AuditLogEventType.CONFIG_VALUE_SET.value],
			}
		):
			backend.configState_updateObjects(config_states)
	finally:
		MySQLSession.query_log = old_query_log

	assert insert_counts == {"AUDIT_LOG": 1, "AUDIT_CONFIG": 1}
	audit_logs = backend.auditLog_getObjects(filter={"eventType": AuditLogEventType.CONFIG_VALUE_SET})
	assert len(audit_logs) == len(clients)


def test_host_parameter_config_state_value_deleted_audit(backend: UnprotectedBackend) -> None:  # noqa: F811
	config_id = "test-host-parameter-audit-config-state-deleted"
	config = UnicodeConfig(
		id=config_id,
		possibleValues=["depot", "client"],
		defaultValues=["client"],
		editable=True,
		multiValue=False,
	)
	client = OpsiClient(id="test-host-parameter-audit-deleted-client.opsi.test", opsiHostKey="3bec332f4241b5aa0f13d149f9bac3bd")
	depot = OpsiDepotserver(id="test-host-parameter-audit-deleted-depot.opsi.test", opsiHostKey="42755d9188cd7f8a76f2281df2ab602f")
	backend.config_createObjects([config])
	backend.host_createObjects([client, depot])
	backend.configState_createObjects(
		[
			ConfigState(configId=config_id, objectId=depot.id, values=["depot"]),
			ConfigState(configId=config_id, objectId=client.id, values=["client"]),
		]
	)

	with get_config(
		{
			"audit_log_enabled": True,
			"audit_log_events": [AuditLogEventType.CONFIG_VALUE_DELETED.value],
		}
	):
		backend.configState_deleteObjects(
			[
				ConfigState(configId=config_id, objectId=depot.id),
				ConfigState(configId=config_id, objectId=client.id),
			]
		)

	audit_logs = backend.auditLog_getObjects(filter={"eventType": AuditLogEventType.CONFIG_VALUE_DELETED})
	assert len(audit_logs) == 2
	logs_by_host_id = {audit_log.hostId: audit_log for audit_log in audit_logs}
	assert logs_by_host_id[depot.id].config
	assert logs_by_host_id[depot.id].config.configId == config_id
	assert logs_by_host_id[depot.id].config.scope == "depot"
	assert logs_by_host_id[depot.id].config.newValue is None
	assert logs_by_host_id[client.id].config
	assert logs_by_host_id[client.id].config.configId == config_id
	assert logs_by_host_id[client.id].config.scope == "client"
	assert logs_by_host_id[client.id].config.newValue is None
	_assert_host_parameter_message(
		logs_by_host_id[depot.id].message,
		scope="depot",
		config_id=config_id,
		new_value=None,
		username="opsiconfd",
		host_id=depot.id,
	)
	_assert_host_parameter_message(
		logs_by_host_id[client.id].message,
		scope="client",
		config_id=config_id,
		new_value=None,
		username="opsiconfd",
		host_id=client.id,
	)


def test_host_parameter_config_default_value_deleted_audit(backend: UnprotectedBackend) -> None:  # noqa: F811
	config = UnicodeConfig(
		id="test-host-parameter-audit-config-deleted",
		possibleValues=["enabled", "disabled"],
		defaultValues=["enabled"],
		editable=True,
		multiValue=False,
	)
	backend.config_createObjects([config])

	with get_config(
		{
			"audit_log_enabled": True,
			"audit_log_events": [AuditLogEventType.CONFIG_VALUE_DELETED.value],
		}
	):
		backend.config_deleteObjects([config])

	audit_logs = backend.auditLog_getObjects(filter={"eventType": AuditLogEventType.CONFIG_VALUE_DELETED})
	assert len(audit_logs) == 1
	assert audit_logs[0].created
	assert audit_logs[0].actorType is None
	assert audit_logs[0].actorId == "opsiconfd"
	assert audit_logs[0].config
	assert audit_logs[0].config.configId == config.id
	assert audit_logs[0].config.scope == "default"
	assert audit_logs[0].config.newValue is None
	_assert_host_parameter_message(
		audit_logs[0].message,
		scope="default",
		config_id=config.id,
		new_value=None,
		username="opsiconfd",
	)
