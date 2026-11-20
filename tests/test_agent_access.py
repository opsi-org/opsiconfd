# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
test access of opsi agent users with the default acl.conf
"""

from opsi.opsi.service.model.object import OpsiClient, OpsiDepotserver

from opsiconfd.backend.auth import RPCACE

from .utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	UnprotectedBackend,
	backend,
	clean_mysql,
	clean_redis,
	default_acl,
	test_client,
)


def test_agent_user_access_with_default_acl(
	default_acl: dict[str, list[RPCACE]],  # noqa: F811
	backend: UnprotectedBackend,  # noqa: F811
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	client = OpsiClient(id="test-agent-access-client1.opsi.test", opsiHostKey="4587dec5913c501a28560d576768924e", oneTimePassword="secret")
	depot = OpsiDepotserver(id="test-agent-access-depot1.opsi.test", opsiHostKey="3d58924c50167a2ec547de0976855861")
	backend.host_createObjects([client, depot])

	# Create the agent user like an admin does in the admin interface
	password = "Secret123!"
	res = test_client.post(
		"/admin/create-user", auth=(ADMIN_USER, ADMIN_PASS), json={"user_id": "e2e-agent1", "password": password, "agent": True}
	)
	assert res.status_code == 200
	test_client.reset_cookies()
	test_client.auth = ("e2e-agent1", password)

	def rpc(method: str, params: list | None = None) -> dict:
		return test_client.post("/rpc", json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).json()

	# boot_getConfig is allowed (no client found and unknown devices are not booted)
	res = rpc("boot_getConfig", [None, None, 4, None, None, None, "unknown-client.opsi.test"])
	assert "error" not in res
	assert res["result"]["client_id"] is None
	assert res["result"]["depot_id"]

	# Everything else is denied, including reading hosts
	host_params = [[{"type": "OpsiClient", "id": client.id}]]
	for method, params in (
		("host_getObjects", []),
		("host_getHashes", []),
		("host_getIdents", ["str"]),
		("user_getObjects", []),
		("config_getObjects", []),
		("productOnClient_getObjects", []),
		("host_updateObjects", host_params),
		("host_deleteObjects", host_params),
	):
		res = rpc(method, params)
		assert "error" in res
		assert "No permission for method" in res["error"]["message"], method
