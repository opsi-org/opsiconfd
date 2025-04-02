# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
test opsiconfd.backend.rpc.obj_license_on_client
"""

import pytest
from opsicommon.exceptions import LicenseMissingError
from opsicommon.objects import (
	LicenseContract,
	LicenseOnClient,
	LicensePool,
	LocalbootProduct,
	OEMSoftwareLicense,
	OpsiClient,
	RetailSoftwareLicense,
	SoftwareLicense,
	SoftwareLicenseToLicensePool,
	VolumeSoftwareLicense,
)

from tests.utils import UnprotectedBackend, backend, clean_mysql, clean_redis  # noqa: F401


@pytest.mark.parametrize(
	"license_type",
	(OEMSoftwareLicense, VolumeSoftwareLicense, RetailSoftwareLicense),
)
def test_licenseOnClient_getOrCreateObject(
	backend: UnprotectedBackend,  # noqa: F811
	license_type: type[SoftwareLicense],
) -> None:
	max_installations = 1 if license_type is OEMSoftwareLicense else 3
	product1 = LocalbootProduct(
		id="test-backend-rpc-product-1",
		productVersion="5.3.0",
		packageVersion="2",
		licenseRequired=True,
		setupScript="setup.opsiscript",
		uninstallScript="uninstall.opsiscript",
	)
	product2 = LocalbootProduct(
		id="test-backend-rpc-product-2",
		productVersion="1.2.3",
		packageVersion="1",
		licenseRequired=True,
		setupScript="setup.opsiscript",
		uninstallScript="uninstall.opsiscript",
	)
	pool1 = LicensePool(id="test-pool-1", description="Test pool", productIds=[product1.id, product2.id])
	contract1 = LicenseContract(id="test-contract-1", description="test contract")
	license1 = license_type(id="test-license-1", licenseContractId=contract1.id, maxInstallations=3)
	lic2pool = SoftwareLicenseToLicensePool(softwareLicenseId=license1.id, licensePoolId=pool1.id, licenseKey="key")
	client1 = OpsiClient(id="test-client-1.opsi.org")
	client2 = OpsiClient(id="test-client-2.opsi.org")
	client3 = OpsiClient(id="test-client-3.opsi.org")
	client4 = OpsiClient(id="test-client-4.opsi.org")

	backend.host_createObjects([client1, client2, client3, client4])
	backend.product_createObjects([product1, product2])
	backend.licensePool_createObjects([pool1])
	backend.licenseContract_createObjects([contract1])
	backend.softwareLicense_createObjects([license1])
	backend.softwareLicenseToLicensePool_createObjects([lic2pool])

	for _ in range(2):
		# Acquire license and reacquire it
		clients = (client1, client2, client3) if max_installations == 3 else (client1,)
		for client in clients:
			license_on_client = backend.licenseOnClient_getOrCreateObject(
				clientId=client.id, productId=(product2 if client == client2 else product1).id
			)
			assert isinstance(license_on_client, LicenseOnClient)
			assert license_on_client.clientId == client.id
			assert license_on_client.softwareLicenseId == license1.id
			assert license_on_client.licenseKey == lic2pool.licenseKey
			assert license_on_client.licensePoolId == pool1.id

	for product in (product1, product2):
		# Acquire license for client4 which will fail
		with pytest.raises(
			LicenseMissingError,
			match=(
				r"License missing error: No license available for pool 'test-pool-1' and client 'test-client-4.opsi.org',"
				r" or all remaining licenses are bound to a different host."
			),
		):
			backend.licenseOnClient_getOrCreateObject(clientId=client4.id, productId=product.id)
