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


def create_test_client(test_client: OpsiconfdTestClient) -> dict[str, str]:
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


def test_set_product_action_request_new(
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	pod1, pod2 = create_test_pods(test_client)
	client = create_test_client(test_client)

	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "setProductActionRequest",
		"params": [client["id"], pod1["productId"], "setup"],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	rpc = {
		"jsonrpc": "2.0",
		"id": 1,
		"method": "setProductActionRequest",
		"params": [client["id"], pod2["productId"], "setup"],
	}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	desired_pocs = [
		{
			"productId": pod1["productId"],
			"productVersion": pod1["productVersion"],
			"packageVersion": pod1["packageVersion"],
			"productType": pod1["productType"],
			"clientId": client["id"],
			"actionRequest": "none",
			"actionProgress": "none",
			"actionResult": "none",
			"installationStatus": "not_installed",
		},
		{
			"productId": pod2["productId"],
			"productVersion": pod1["productVersion"],
			"packageVersion": pod1["packageVersion"],
			"productType": pod1["productType"],
			"clientId": client["id"],
			"actionRequest": "none",
			"actionProgress": "none",
			"actionResult": "none",
			"installationStatus": "not_installed",
		},
	]
	check_products_on_client(test_client, desired_pocs)

	rpc = {"jsonrpc": "2.0", "id": 1, "method": "setProductActionRequest", "params": [client["id"], pod1["productId"], "setup"]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "setProductActionRequest", "params": [client["id"], pod2["productId"], "setup"]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	check_products_on_client(test_client, desired_pocs)
