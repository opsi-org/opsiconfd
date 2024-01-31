# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test depotserver
"""
from pathlib import Path
from typing import Generator

from _pytest.fixtures import FixtureFunction
from pytest import fixture

from opsiconfd.backend import get_unprotected_backend, reinit_backend
from opsiconfd.config import get_depotserver_id
from opsiconfd.setup import setup_depotserver
from tests.utils import ADMIN_PASS, ADMIN_USER, OpsiconfdTestClient, get_config, test_client  # pylint: disable=unused-import

CONFIGSERVER = "opsiserver43-cs"


@fixture(autouse=False)
def depotserver_setup(tmp_path: Path) -> Generator[None, None, None]:
	opsi_config_file = Path("/etc/opsi/opsi.conf")
	orig_opsi_conf = opsi_config_file.read_bytes()
	try:
		ssl_ca_cert = tmp_path / "opsi-ca-cert.pem"
		with get_config({"ssl_ca_cert": str(ssl_ca_cert)}):
			depot_id = get_depotserver_id()
			unattended_configuration = {
				"configserver": CONFIGSERVER,
				"username": "adminuser",
				"password": "adminuser",
				"depot_id": depot_id,
				"description": "pytest depotserver",
			}
			setup_depotserver(unattended_configuration)
			reinit_backend()
			yield
	finally:
		opsi_config_file.write_bytes(orig_opsi_conf)


def test_jsonrpc(depotserver_setup: FixtureFunction, test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name,unused-argument
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	with test_client as client:
		backend = get_unprotected_backend()
		assert backend._server_role == "depotserver"  # pylint: disable=protected-access
		idents = client.jsonrpc20(method="host_getIdents")["result"]
		assert idents == backend.host_getIdents()
		depot_id = get_depotserver_id()
		assert depot_id in idents
		assert CONFIGSERVER in [ident.split(".")[0] for ident in idents]
