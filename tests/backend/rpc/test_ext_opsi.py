import pytest

from tests.utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	clean_mysql,
	clean_redis,
	get_config,
	test_client,
)

from .test_obj_product_on_client import check_products_on_client
from .test_obj_product_on_depot import create_test_pods


def create_test_client(test_client: OpsiconfdTestClient) -> dict[str, str]:  # noqa: F811
	client = {
		"type": "OpsiClient",
		"id": "test-backend-rpc-host-1.opsi.test",
		"opsiHostKey": "4587dec5913c501a28560d576768924e",
		"description": "description",
		"notes": "notes",
		"oneTimePassword": "secret",
	}
	# Create client 1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "host_insertObject", "params": [client]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	return client


@pytest.mark.parametrize("method", ["setProductActionRequest", "setProductActionRequestWithDependencies"])
def test_set_product_action_request_new(
	test_client: OpsiconfdTestClient,  # noqa: F811
	method: str,
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	pod1, pod2 = create_test_pods(test_client)
	client = create_test_client(test_client)
	desired_pocs = [
		{
			"productId": pod1["productId"],
			"productVersion": pod1["productVersion"],
			"packageVersion": pod1["packageVersion"],
			"productType": pod1["productType"],
			"clientId": client["id"],
			"actionRequest": "setup",
			"installationStatus": "not_installed",
		},
		{
			"productId": pod2["productId"],
			"productVersion": pod2["productVersion"],
			"packageVersion": pod2["packageVersion"],
			"productType": pod2["productType"],
			"clientId": client["id"],
			"actionRequest": "setup",
			"installationStatus": "not_installed",
		},
	]
	for _ in range(2):  # repeat to have another test with existing poc
		rpc = {"jsonrpc": "2.0", "id": 1, "method": method, "params": [pod1["productId"], client["id"], "setup"]}
		res = test_client.post("/rpc", json=rpc).json()
		assert "error" not in res
		rpc = {"jsonrpc": "2.0", "id": 1, "method": method, "params": [pod2["productId"], client["id"], "setup"]}
		res = test_client.post("/rpc", json=rpc).json()
		assert "error" not in res
		check_products_on_client(test_client, desired_pocs, ignore_version=True)
