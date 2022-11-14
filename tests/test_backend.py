# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webdav tests
"""

from pathlib import Path

import requests
from OpenSSL.crypto import FILETYPE_PEM, load_certificate, load_privatekey

from opsiconfd import get_contextvars, set_contextvars, set_contextvars_from_contex
from opsiconfd.backend import (
	execute_on_secondary_backends,
	get_backend,
	get_client_backend,
	get_mysql,
	get_option_store,
	get_server_role,
	get_session,
	get_user_store,
)
from opsiconfd.backend.rpc.opsiconfd import get_backend_interface

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	clean_redis,
	client_jsonrpc,
	config,
	depot_jsonrpc,
	get_config,
	test_client,
)


def test_get_session(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.get("/")
	cvars = get_contextvars()
	try:
		if test_client.context:
			set_contextvars_from_contex(test_client.context)
		assert get_session()
		assert get_user_store()
		get_option_store()
	finally:
		set_contextvars(cvars)


def test_get_client_backend(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.get("/")
	cvars = get_contextvars()
	try:
		if test_client.context:
			set_contextvars_from_contex(test_client.context)
		backend = get_client_backend()
		assert backend
		idents = backend.host_getIdents()  # pylint: disable=no-member
		assert len(idents) > 0
	finally:
		set_contextvars(cvars)


def test_get_backend_interface() -> None:
	assert len(get_backend_interface()) > 50


def test_get_server_role(tmp_path: Path) -> None:
	dispatch_config_file = tmp_path / "dispatch_mysql.conf"
	dispatch_config_file.write_text(".*         : mysql\n")
	with get_config({"dispatch_config_file": str(dispatch_config_file)}):
		assert get_server_role() == "config"

	dispatch_config_file = tmp_path / "dispatch_jsonrpc.conf"
	dispatch_config_file.write_text(".*         : jsonrpc\n")
	with get_config({"dispatch_config_file": str(dispatch_config_file)}):
		assert get_server_role() == "depot"


def test_get_mysql() -> None:
	mysql = get_mysql()  # pylint: disable=invalid-name
	with mysql.session() as session:
		host_ids = session.execute("SELECT hostId FROM HOST").fetchall()
		assert len(host_ids) > 0


def test_execute_on_secondary_backends() -> None:
	# TODO: load a secondary backend
	backend = get_backend()
	host = backend.host_getObjects()[0]  # pylint: disable=no-member
	execute_on_secondary_backends("host_updateObjects", hosts=[host])


def test_opsiconfd_backend_get_domain(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	client_id = "test-client-dom.opsi.org"
	host_key = "76768a28560d5924e4587dec5913c501"
	with client_jsonrpc(test_client, "", client_id, host_key):
		test_client.reset_cookies()
		test_client.auth = (client_id, host_key)
		try:
			rpc = {"id": 1, "method": "getDomain", "params": []}
			res = test_client.post("/rpc", json=rpc)
			res.raise_for_status()
		finally:
			test_client.reset_cookies()
			test_client.auth = (ADMIN_USER, ADMIN_PASS)


def test_opsiconfd_backend_host_get_tls_certificate_depot(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	host_id = "test-depot-cert.opsi.org"
	host_key = "aa768a25913c507dec18560d5924e458"
	with depot_jsonrpc(test_client, "", host_id, host_key):
		test_client.reset_cookies()
		test_client.auth = (host_id, host_key)
		try:
			rpc = {"id": 1, "method": "accessControl_authenticated", "params": []}
			res = test_client.post("/rpc", json=rpc)
			res.raise_for_status()

			rpc = {"id": 1, "method": "host_getTLSCertificate", "params": [host_id]}
			res = test_client.post("/rpc", json=rpc)
			res.raise_for_status()
			res_dict = res.json()

			load_privatekey(FILETYPE_PEM, res_dict["result"])
			cert = load_certificate(FILETYPE_PEM, res_dict["result"])
			assert cert.get_subject().CN == host_id
		finally:
			test_client.reset_cookies()
			test_client.auth = (ADMIN_USER, ADMIN_PASS)


def test_opsiconfd_backend_host_get_tls_certificate_client(
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	host_id = "test-client-cert.opsi.org"
	host_key = "07dec1856aa768a25913c50d5924e458"
	ip_address = "192.168.1.2"
	with client_jsonrpc(test_client, "", host_id, host_key, ip_address=ip_address):
		test_client.reset_cookies()
		test_client.auth = (host_id, host_key)
		try:
			rpc = {"id": 1, "method": "accessControl_authenticated", "params": []}
			res = test_client.post("/rpc", json=rpc)
			res.raise_for_status()

			rpc = {"id": 1, "method": "host_getTLSCertificate", "params": [host_id]}
			res = test_client.post("/rpc", json=rpc)
			res.raise_for_status()
			res_dict = res.json()

			load_privatekey(FILETYPE_PEM, res_dict["result"])
			cert = load_certificate(FILETYPE_PEM, res_dict["result"])
			sub_alt_name = ""
			for idx in range(cert.get_extension_count()):
				ext = cert.get_extension(idx)
				if ext.get_short_name() == b"subjectAltName":
					sub_alt_name = str(ext)
			assert f"IP Address:{ip_address}" in sub_alt_name

			rpc = {"id": 1, "method": "host_getTLSCertificate", "params": ["test-client2-cert.opsi.org"]}
			res = test_client.post("/rpc", json=rpc)
			res.raise_for_status()
			res_dict = res.json()
			assert res_dict["error"]["class"] == "BackendPermissionDeniedError"
		finally:
			test_client.reset_cookies()
			test_client.auth = (ADMIN_USER, ADMIN_PASS)


def _test_backend_options(client: OpsiconfdTestClient, base_url: str, host_id: str) -> None:  # pylint: disable=too-many-statements
	option_defaults = {
		"addProductOnClientDefaults": False,
		"addProductPropertyStateDefaults": False,
		"addConfigStateDefaults": False,
		"deleteConfigStateIfDefault": False,
		"returnObjectsOnUpdateAndCreate": False,
		"addDependentProductOnClients": False,
		"processProductOnClientSequence": False,
		"additionalReferentialIntegrityChecks": True,
	}

	rpc = {"id": 1, "method": "backend_getOptions", "params": []}
	res = client.post(f"{base_url}/rpc", json=rpc)
	res.raise_for_status()
	res_dict = res.json()
	cookie = list(client.cookies)[0]
	session_id = cookie.value
	assert res_dict["result"] == option_defaults

	rpc = {"id": 2, "method": "configState_getObjects", "params": [[], {"objectId": host_id}]}
	res = client.post(f"{base_url}/rpc", json=rpc)
	res.raise_for_status()
	res_dict = res.json()
	cookie = list(client.cookies)[0]
	assert session_id == cookie.value
	assert res_dict["result"] == []

	rpc = {"id": 3, "method": "backend_setOptions", "params": [{"addConfigStateDefaults": True}]}
	res = client.post(f"{base_url}/rpc", json=rpc)
	res.raise_for_status()
	res_dict = res.json()
	cookie = list(client.cookies)[0]
	assert session_id == cookie.value

	options = option_defaults.copy()
	options["addConfigStateDefaults"] = True
	rpc = {"id": 4, "method": "backend_getOptions", "params": []}
	res = client.post(f"{base_url}/rpc", json=rpc)
	res.raise_for_status()
	res_dict = res.json()
	cookie = list(client.cookies)[0]
	assert session_id == cookie.value
	assert res_dict["result"] == options

	rpc = {"id": 5, "method": "configState_getObjects", "params": [[], {"objectId": host_id}]}
	res = client.post(f"{base_url}/rpc", json=rpc)
	res.raise_for_status()
	res_dict = res.json()
	assert res_dict["result"]
	for config_state in res_dict["result"]:
		assert config_state["_is_generated_default"]
		assert config_state["objectId"] == host_id

	# Delete session (and option store)
	rpc = {"id": 6, "method": "backend_exit", "params": []}
	res = client.post(f"{base_url}/rpc", json=rpc)
	res.raise_for_status()
	res = res.json()

	rpc = {"id": 7, "method": "backend_getOptions", "params": []}
	res = client.post(f"{base_url}/rpc", json=rpc)
	res.raise_for_status()
	res_dict = res.json()
	cookie = list(client.cookies)[0]
	assert session_id != cookie.value
	assert res_dict["result"] == option_defaults


def test_backend_options_test_client(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	host_id = "test-client-options-tc.opsi.org"
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with client_jsonrpc(test_client, "", host_id):
		for _ in range(20):
			_test_backend_options(test_client, "", host_id)


def test_backend_options_requests() -> None:
	host_id = "test-client-options-rq.opsi.org"
	session = requests.session()
	session.auth = (ADMIN_USER, ADMIN_PASS)
	with client_jsonrpc(session, "https://localhost:4447", host_id):  # type: ignore[arg-type]
		for _ in range(20):
			_test_backend_options(session, "https://localhost:4447", host_id)  # type: ignore[arg-type]
