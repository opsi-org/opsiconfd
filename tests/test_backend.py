# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
webdav tests
"""

from OpenSSL.crypto import FILETYPE_PEM, load_privatekey, load_certificate

from opsiconfd import set_contextvars_from_contex
from opsiconfd.backend import (
	get_session, get_user_store, get_option_store,
	get_backend, get_client_backend, get_backend_interface, get_server_role,
	get_mysql, execute_on_secondary_backends
)
from .utils import (  # pylint: disable=unused-import
	clean_redis, config, get_config, test_client, depot_jsonrpc, client_jsonrpc,
	ADMIN_USER, ADMIN_PASS
)


def test_get_session(test_client):  # pylint: disable=redefined-outer-name
	test_client.get("/")
	set_contextvars_from_contex(None)
	set_contextvars_from_contex(test_client.context)
	assert get_session()
	assert get_user_store()
	get_option_store()


def test_get_client_backend(test_client):  # pylint: disable=redefined-outer-name
	test_client.get("/")
	set_contextvars_from_contex(test_client.context)
	backend = get_client_backend()
	assert backend
	idents = backend.host_getIdents()  # pylint: disable=no-member
	assert len(idents) > 0


def test_get_backend_interface():
	assert len(get_backend_interface()) > 50


def test_get_server_role(tmp_path):
	dispatch_config_file = tmp_path / "dispatch_mysql.conf"
	dispatch_config_file.write_text(".*         : mysql\n")
	with get_config({"dispatch_config_file": str(dispatch_config_file)}):
		assert get_server_role() == "config"

	dispatch_config_file = tmp_path / "dispatch_jsonrpc.conf"
	dispatch_config_file.write_text(".*         : jsonrpc\n")
	with get_config({"dispatch_config_file": str(dispatch_config_file)}):
		assert get_server_role() == "depot"


def test_get_mysql():
	mysql = get_mysql()  # pylint: disable=invalid-name
	with mysql.session() as session:
		host_ids = session.execute("SELECT hostId FROM HOST").fetchall()
		assert len(host_ids) > 0


def test_execute_on_secondary_backends():
	# TODO: load a secondary backend
	backend = get_backend()
	host = backend.host_getObjects()[0]  # pylint: disable=no-member
	execute_on_secondary_backends("host_updateObjects", hosts=[host])


def test_opsiconfd_backend_get_domain(test_client):  # pylint: disable=redefined-outer-name
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
			assert res["result"] == "mz.uib.gmbh"
		finally:
			test_client.reset_cookies()
			test_client.auth = (ADMIN_USER, ADMIN_PASS)


def test_opsiconfd_backend_host_get_tls_certificate(test_client):  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	depot_id = "test-depot-cert.opsi.org"
	host_key = "aa768a25913c507dec18560d5924e458"
	with depot_jsonrpc(test_client, "", depot_id, host_key):
		test_client.reset_cookies()
		test_client.auth = (depot_id, host_key)
		try:
			rpc = {"id": 1, "method": "accessControl_authenticated", "params": []}
			res = test_client.post("/rpc", json=rpc)
			res.raise_for_status()

			rpc = {"id": 1, "method": "host_getTLSCertificate", "params": [depot_id]}
			res = test_client.post("/rpc", json=rpc)
			res.raise_for_status()
			res = res.json()

			load_privatekey(FILETYPE_PEM, res["result"])
			cert = load_certificate(FILETYPE_PEM, res["result"])
			assert cert.get_subject().CN == depot_id
		finally:
			test_client.reset_cookies()
			test_client.auth = (ADMIN_USER, ADMIN_PASS)
