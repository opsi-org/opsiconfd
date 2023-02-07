# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.general
"""

from datetime import datetime, timedelta

import pytest
from opsicommon.license import OPSI_CLIENT_INACTIVE_AFTER
from opsicommon.objects import LocalbootProduct, OpsiClient, ProductOnClient

from tests.utils import (  # pylint: disable=unused-import
	UnprotectedBackend,
	backend,
	clean_mysql,
)


@pytest.mark.parametrize(
	"last_seen_days, macos, linux, windows",
	[
		(OPSI_CLIENT_INACTIVE_AFTER - 1000, 1, 2, 6),
		(OPSI_CLIENT_INACTIVE_AFTER - 1, 1, 2, 6),
		(OPSI_CLIENT_INACTIVE_AFTER, 1, 1, 4),
		(OPSI_CLIENT_INACTIVE_AFTER + 1, 1, 1, 4),
		(OPSI_CLIENT_INACTIVE_AFTER + 1000, 1, 1, 4),
	],
)
def test_get_client_info(  # pylint: disable=too-many-locals
	backend: UnprotectedBackend, last_seen_days: int, macos: int, linux: int, windows: int  # pylint: disable=redefined-outer-name
) -> None:
	hosts = backend.host_getIdents(type="OpsiClient")
	assert len(hosts) == 0

	now = datetime.now()
	now_str = now.strftime("%Y-%m-%d %H:%M:%S")
	last_seen = now - timedelta(days=last_seen_days)
	last_seen_str = last_seen.strftime("%Y-%m-%d %H:%M:%S")

	client1 = OpsiClient(id="test-backend-rpc-general-1.opsi.org", lastSeen=now_str)
	client2 = OpsiClient(id="test-backend-rpc-general-2.opsi.org", lastSeen=now_str)
	client3 = OpsiClient(id="test-backend-rpc-general-3.opsi.org", lastSeen=last_seen_str)
	client4 = OpsiClient(id="test-backend-rpc-general-4.opsi.org", lastSeen=now_str)
	client5 = OpsiClient(id="test-backend-rpc-general-5.opsi.org", lastSeen=now_str)
	client6 = OpsiClient(id="test-backend-rpc-general-6.opsi.org", lastSeen=last_seen_str)
	client7 = OpsiClient(id="test-backend-rpc-general-7.opsi.org", lastSeen=now_str)
	client8 = OpsiClient(id="test-backend-rpc-general-8.opsi.org", lastSeen=now_str)
	client9 = OpsiClient(id="test-backend-rpc-general-9.opsi.org", lastSeen=last_seen_str)

	oca = LocalbootProduct(id="opsi-client-agent", productVersion="4.3.0.0", packageVersion="1")
	olca = LocalbootProduct(id="opsi-linux-client-agent", productVersion="4.3.0.0", packageVersion="1")
	omca = LocalbootProduct(id="opsi-mac-client-agent", productVersion="4.3.0.0", packageVersion="1")

	pocs = [
		ProductOnClient(
			productId=oca.id,
			productType=oca.getType(),
			clientId=client1.id,
			productVersion=oca.productVersion,
			packageVersion=oca.packageVersion,
			installationStatus="installed",
		),
		ProductOnClient(
			productId=oca.id,
			productType=oca.getType(),
			clientId=client2.id,
			productVersion=oca.productVersion,
			packageVersion=oca.packageVersion,
			installationStatus="not_installed",
		),
		ProductOnClient(
			productId=oca.id,
			productType=oca.getType(),
			clientId=client3.id,
			productVersion=oca.productVersion,
			packageVersion=oca.packageVersion,
			installationStatus="installed",
		),
		ProductOnClient(
			productId=olca.id,
			productType=olca.getType(),
			clientId=client4.id,
			productVersion=olca.productVersion,
			packageVersion=olca.packageVersion,
			installationStatus="installed",
		),
		ProductOnClient(
			productId=olca.id,
			productType=olca.getType(),
			clientId=client5.id,
			productVersion=olca.productVersion,
			packageVersion=olca.packageVersion,
			installationStatus="not_installed",
		),
		ProductOnClient(
			productId=olca.id,
			productType=olca.getType(),
			clientId=client6.id,
			productVersion=olca.productVersion,
			packageVersion=olca.packageVersion,
			installationStatus="installed",
		),
		ProductOnClient(
			productId=omca.id,
			productType=omca.getType(),
			clientId=client1.id,
			productVersion=omca.productVersion,
			packageVersion=omca.packageVersion,
			installationStatus="installed",
		),
	]

	backend.host_createObjects([client1, client2, client3, client4, client5, client6, client7, client8, client9])
	backend.product_createObjects([oca, olca, omca])
	backend.productOnClient_createObjects(pocs)

	info = backend._get_client_info()  # type: ignore[misc] # pylint: disable=protected-access
	print(info)
	assert info["macos"] == macos
	assert info["linux"] == linux
	assert info["windows"] == windows
