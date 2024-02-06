# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webdav tests
"""

from OpenSSL.crypto import FILETYPE_PEM, load_certificate, load_privatekey

from OPSI.Backend.Replicator import BackendReplicator  # type: ignore[import]
from opsiconfd.backend import (
	get_mysql,
	get_unprotected_backend,
)


from ..utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	clean_redis,
	client_jsonrpc,
	config,
	depot_jsonrpc,
	get_config,
	test_client,
	backend,
	UnprotectedBackend,
)


def test_get_protected_backend() -> None:
	# TODO
	assert len(get_unprotected_backend().get_interface()) > 50


def test_get_backend_interface() -> None:
	assert len(get_unprotected_backend().get_interface()) > 50


def test_get_mysql() -> None:
	mysql = get_mysql()
	with mysql.session() as session:
		host_ids = session.execute("SELECT hostId FROM HOST").fetchall()
		assert len(host_ids) > 0


def test_opsiconfd_backend_get_domain(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
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


def test_opsiconfd_backend_host_get_tls_certificate_depot(test_client: OpsiconfdTestClient) -> None:  # noqa: F811
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
	test_client: OpsiconfdTestClient,  # noqa: F811
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
			assert res_dict["error"]["class"] == "OpsiServicePermissionError"
		finally:
			test_client.reset_cookies()
			test_client.auth = (ADMIN_USER, ADMIN_PASS)


def test_backend_replicator_instance(backend: UnprotectedBackend) -> None:  # noqa: F811
	BackendReplicator(readBackend=backend, writeBackend=backend, cleanupFirst=False)
