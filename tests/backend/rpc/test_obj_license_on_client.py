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
	AuditSoftware,
	AuditSoftwareToLicensePool,
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
		id="lic-test-product-1",
		productVersion="5.3.0",
		packageVersion="2",
		licenseRequired=True,
		setupScript="setup.opsiscript",
		uninstallScript="uninstall.opsiscript",
	)
	product2 = LocalbootProduct(
		id="lic-test-product-2",
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
	audit_software1 = AuditSoftware(
		name="lic-test-product-1",
		version="5.3.0",
		subVersion="",
		language="",
		architecture="",
		windowsSoftwareId="software-id-lic-test-product-1",
	)
	audit_software_to_license_pool1 = AuditSoftwareToLicensePool(
		name="lic-test-product-1",
		version="5.3.0",
		subVersion="",
		language="",
		architecture="",
		licensePoolId=pool1.id,
	)
	backend.host_createObjects([client1, client2, client3, client4])
	backend.product_createObjects([product1, product2])
	backend.licensePool_createObjects([pool1])
	backend.licenseContract_createObjects([contract1])
	backend.softwareLicense_createObjects([license1])
	backend.softwareLicenseToLicensePool_createObjects([lic2pool])
	backend.auditSoftware_createObjects([audit_software1])
	backend.auditSoftwareToLicensePool_createObjects([audit_software_to_license_pool1])

	for _ in range(2):
		# Acquire license and reacquire it
		clients = (client1, client2, client3) if max_installations == 3 else (client1,)
		for client in clients:
			for arg in "licensePoolId", "productId", "windowsSoftwareId":
				kwargs = {"clientId": client.id}
				if arg == "licensePoolId":
					kwargs[arg] = pool1.id
				elif arg == "productId":
					kwargs[arg] = product1.id if client == client1 else product2.id
				elif arg == "windowsSoftwareId":
					assert audit_software1.windowsSoftwareId
					kwargs[arg] = audit_software1.windowsSoftwareId

				license_on_client = backend.licenseOnClient_getOrCreateObject(**kwargs)
				assert isinstance(license_on_client, LicenseOnClient)
				assert license_on_client.clientId == client.id
				assert license_on_client.softwareLicenseId == license1.id
				assert license_on_client.licenseKey == lic2pool.licenseKey
				assert license_on_client.licensePoolId == pool1.id

	for with_license_on_client in (False, True):
		license_on_client = LicenseOnClient(
			softwareLicenseId=license1.id, licensePoolId=pool1.id, clientId=client4.id, licenseKey=lic2pool.licenseKey
		)
		if with_license_on_client:
			backend.licenseOnClient_createObjects([license_on_client])
		else:
			backend.licenseOnClient_deleteObjects([license_on_client])

		for product in (product1, product2):
			for arg in "licensePoolId", "productId", "windowsSoftwareId":
				kwargs = {"clientId": client4.id}
				if arg == "licensePoolId":
					kwargs[arg] = pool1.id
				elif arg == "productId":
					kwargs[arg] = product.id
				elif arg == "windowsSoftwareId":
					assert audit_software1.windowsSoftwareId
					kwargs[arg] = audit_software1.windowsSoftwareId

				if with_license_on_client:
					# Acquire license for client4 which will succeed because licenseOnClient is already present
					# although the number of licences is over the limit
					license_on_client = backend.licenseOnClient_getOrCreateObject(**kwargs)
				else:
					# Acquire license for client4 which will fail
					with pytest.raises(
						LicenseMissingError,
						match=(
							r"License missing error: No license available for pool 'test-pool-1' and client 'test-client-4.opsi.org',"
							r" or all remaining licenses are bound to a different host."
						),
					):
						backend.licenseOnClient_getOrCreateObject(**kwargs)
