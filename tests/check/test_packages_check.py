# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
check tests
"""

from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest
from opsicommon.objects import Config, ConfigState, LocalbootProduct, OpsiClient, OpsiDepotserver, ProductOnClient, ProductOnDepot

from opsiconfd.check.common import CheckStatus, check_manager
from opsiconfd.check.opsipackages import (
	OUTDATED_AFTER_DAYS,
	get_available_product_versions,
	opsi_locked_products_check,
	opsi_products_on_clients_check,
	opsi_products_on_depots_check,
)
from opsiconfd.config import get_configserver_id
from opsiconfd.setup.configs import CHECK_DEFAULT_IGNORE_PRODUCTS
from tests.utils import (  # noqa: F401
	cache_clear,
	clean_mysql,
	clean_redis,
	cleanup_checks,
	database_connection,
	get_unprotected_backend,
	test_client,
)


def _prepare_products(depot_installation_time: datetime | None = None) -> None:
	backend = get_unprotected_backend()

	depot = OpsiDepotserver(id="test-check-depot-1.opsi.test")
	client1 = OpsiClient(id="test-check-client-1.opsi.test")
	client1.setDefaults()
	client2 = OpsiClient(id="test-check-client-2.opsi.test")
	client2.setDefaults()
	config = Config(id="clientconfig.depot.id", description="Depot server", possibleValues=[depot.id], defaultValues=[depot.id])
	config_state = ConfigState(configId="clientconfig.depot.id", objectId=client1.id, values=[depot.id])
	oca1 = LocalbootProduct(id="opsi-client-agent", productVersion="4.3.0.1", packageVersion="1")
	oca2 = LocalbootProduct(id="opsi-client-agent", productVersion="4.3.6.1", packageVersion="1")
	oca3 = LocalbootProduct(id="opsi-client-agent", productVersion="4.3.0.0", packageVersion="1")
	oca_on_depot = ProductOnDepot(
		productId=oca1.id,
		productType=oca1.getType(),
		productVersion=oca1.productVersion,
		packageVersion=oca1.packageVersion,
		depotId=depot.id,
	)
	oca_on_configserver = ProductOnDepot(
		productId=oca2.id,
		productType=oca2.getType(),
		productVersion=oca2.productVersion,
		packageVersion=oca2.packageVersion,
		depotId=get_configserver_id(),
	)
	oca_on_client1 = ProductOnClient(
		productId=oca3.id,
		productVersion=oca3.productVersion,
		packageVersion=oca3.packageVersion,
		productType=oca3.getType(),
		clientId=client1.id,
		installationStatus="installed",
	)
	oca_on_client2 = ProductOnClient(
		productId=oca2.id,
		productVersion=oca2.productVersion,
		packageVersion=oca2.packageVersion,
		productType=oca2.getType(),
		clientId=client2.id,
		installationStatus="installed",
	)
	windomain1 = LocalbootProduct(id="windomain", productVersion="4.3.9.1", packageVersion="1")
	windomain2 = LocalbootProduct(id="windomain", productVersion="4.3.5.1", packageVersion="1")
	windomain3 = LocalbootProduct(id="windomain", productVersion="4.2.0.0", packageVersion="1")
	windomain_product_on_depot = ProductOnDepot(
		productId=windomain1.id,
		productType=windomain1.getType(),
		productVersion=windomain1.productVersion,
		packageVersion=windomain1.packageVersion,
		depotId=depot.id,
	)
	windomain_product_on_configserver = ProductOnDepot(
		productId=windomain2.id,
		productType=windomain2.getType(),
		productVersion=windomain2.productVersion,
		packageVersion=windomain2.packageVersion,
		depotId=get_configserver_id(),
	)
	windomain_product_on_client1 = ProductOnClient(
		productId=windomain3.id,
		productVersion=windomain3.productVersion,
		packageVersion=windomain3.packageVersion,
		productType=windomain3.getType(),
		clientId=client1.id,
		installationStatus="installed",
	)
	check_ignore_products = Config(
		id="opsi.check.ignore_products",
		description="Ignore products",
		possibleValues=CHECK_DEFAULT_IGNORE_PRODUCTS,
		defaultValues=CHECK_DEFAULT_IGNORE_PRODUCTS,
		editable=True,
		multiValue=True,
	)

	backend.config_createObjects([config])
	backend.host_createObjects([depot, client1, client2])
	backend.configState_createObjects([config_state])
	backend.product_createObjects([oca1, oca2, oca3, windomain1, windomain2, windomain3])
	backend.productOnDepot_createObjects([oca_on_depot, oca_on_configserver, windomain_product_on_depot, windomain_product_on_configserver])
	backend.productOnClient_createObjects([oca_on_client1, oca_on_client2, windomain_product_on_client1])

	backend.config_createObjects([check_ignore_products])

	if depot_installation_time:
		with backend._mysql.session() as session:
			session.execute(
				"UPDATE PRODUCT_ON_DEPOT SET installationTime = :installation_time", params={"installation_time": depot_installation_time}
			)


REPO_DATA = """{
  "schema_version": "1.1",
  "repository": {
    "name": "OPSI_PACKAGE-4.3-stable"
  },
  "metadata_files": [],
  "packages": {
    "opsi-client-agent": {
      "4.3.10.5-1": {
        "url": [
          "windows/localboot/opsi-client-agent_4.3.10.5-1.opsi"
        ],
        "size": 207155200,
        "md5_hash": "a89d298264eae7c837933d1c474d04ab",
        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "product_id": "opsi-client-agent",
        "product_version": "4.3.10.5",
        "package_version": "1",
        "name": "opsi.org client agent",
        "priority": 95,
        "product_dependencies": [],
        "package_dependencies": [],
        "description": "opsi windows client agent",
        "compatibility": [
          {
            "os": "windows",
            "arch": "all"
          }
        ],
        "changelog_url": "https://changelog.opsi.org/OPSI_PACKAGE-4.3-stable/OPSI_PACKAGE/opsi-client-agent/changelog.txt",
        "release_notes_url": null,
        "icon_url": null,
        "zsync_url": [
          "windows/localboot/opsi-client-agent_4.3.10.5-1.opsi.zsync"
        ],
        "release_date": "<<release_date_opsi-client-agent>>"
      }
    },
    "opsi-script": {
      "4.12.17.2-6": {
        "url": [
          "windows/localboot/opsi-script_4.12.17.2-6.opsi",
          "linux/localboot/opsi-script_4.12.17.2-6.opsi",
          "macos/localboot/opsi-script_4.12.17.2-6.opsi"
        ],
        "size": 32962560,
        "md5_hash": "0570032518e88b7dd038a9d1281a4cf3",
        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "product_id": "opsi-script",
        "product_version": "4.12.17.2",
        "package_version": "6",
        "name": "script",
        "priority": 0,
        "product_dependencies": [],
        "package_dependencies": [],
        "description": "The opsi-script script interpreter of the opsi client agent",
        "compatibility": [
          {
            "os": "windows",
            "arch": "all"
          },
          {
            "os": "linux",
            "arch": "x64"
          },
          {
            "os": "macos",
            "arch": "x64"
          }
        ],
        "changelog_url": "https://changelog.opsi.org/OPSI_PACKAGE-4.3-stable/OPSI_PACKAGE/opsi-script/changelog.txt",
        "release_notes_url": null,
        "icon_url": null,
        "zsync_url": [
          "windows/localboot/opsi-script_4.12.17.2-6.opsi.zsync",
          "linux/localboot/opsi-script_4.12.17.2-6.opsi.zsync",
          "macos/localboot/opsi-script_4.12.17.2-6.opsi.zsync"
        ],
        "release_date": "<<release_date_opsi-script>>"
      }
    },
    "hwaudit": {
      "4.3.1.0-1": {
        "url": [
          "macos/localboot/hwaudit_4.3.1.0-1.opsi",
          "linux/localboot/hwaudit_4.3.1.0-1.opsi",
          "windows/localboot/hwaudit_4.3.1.0-1.opsi"
        ],
        "size": 85329920,
        "md5_hash": "348d5db77c21a9bd5b11c60af2ae0b61",
        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "product_id": "hwaudit",
        "product_version": "4.3.1.0",
        "package_version": "1",
        "name": "Client Hardwareinventory Windows / Linux / OSX",
        "priority": 0,
        "product_dependencies": [],
        "package_dependencies": [],
        "description": "Hardwareinventarisierung",
        "compatibility": [
          {
            "os": "macos",
            "arch": "x64"
          },
          {
            "os": "linux",
            "arch": "x64"
          },
          {
            "os": "windows",
            "arch": "all"
          }
        ],
        "changelog_url": "https://changelog.opsi.org/OPSI_PACKAGE-4.3-stable/OPSI_PACKAGE/hwaudit/changelog.txt",
        "release_notes_url": null,
        "icon_url": null,
        "zsync_url": [
          "macos/localboot/hwaudit_4.3.1.0-1.opsi.zsync",
          "linux/localboot/hwaudit_4.3.1.0-1.opsi.zsync",
          "windows/localboot/hwaudit_4.3.1.0-1.opsi.zsync"
        ],
        "release_date": "2025-01-01T06:31:10.335578Z"
      }
    }
  }
}
"""


def test_get_available_product_versions() -> None:
	now = datetime.now(tz=timezone.utc)
	yesterday = now - timedelta(days=1)
	repo_data = REPO_DATA.replace("<<release_date_opsi-client-agent>>", yesterday.isoformat()).replace(
		"<<release_date_opsi-script>>", now.isoformat()
	)
	with mock.patch("opsiconfd.check.opsipackages._fetch_repo_file", return_value=repo_data.encode("utf-8")):
		product_ids = [
			"opsi-script",
			"opsi-client-agent",
			"opsi-linux-client-agent",
			"opsi-mac-client-agent",
			"hwaudit",
			"win10",
			"hwinvent",
		]
		available_packages = get_available_product_versions(product_ids)
		assert available_packages == {"opsi-client-agent": "4.3.10.5-1", "opsi-script": "4.12.17.2-6", "hwaudit": "4.3.1.0-1"}

		available_packages = get_available_product_versions(product_ids, min_age_seconds=3600)
		assert available_packages == {"opsi-client-agent": "4.3.10.5-1", "hwaudit": "4.3.1.0-1"}

		available_packages = get_available_product_versions(product_ids, min_age_seconds=25 * 3600)
		assert available_packages == {"hwaudit": "4.3.1.0-1"}


@pytest.mark.parametrize("relase_age", [OUTDATED_AFTER_DAYS - 1, OUTDATED_AFTER_DAYS + 1])
def test_check_products_on_depots(relase_age: int) -> None:
	_prepare_products()
	check_manager.register(opsi_products_on_depots_check)

	now = datetime.now(tz=timezone.utc)
	release_date = now - timedelta(days=relase_age)
	repo_data = REPO_DATA.replace("<<release_date_opsi-client-agent>>", release_date.isoformat()).replace(
		"<<release_date_opsi-script>>", release_date.isoformat()
	)
	with mock.patch("opsiconfd.check.opsipackages._fetch_repo_file", return_value=repo_data.encode("utf-8")):
		result = check_manager.get("products_on_depots").run(clear_cache=True)

	if relase_age < OUTDATED_AFTER_DAYS:
		assert result.check_status == CheckStatus.OK
		assert result.message == "All important products are up to date on all depots."
		assert result.upgrade_issue is None
		assert len(result.partial_results) == 0
	else:
		assert result.check_status == CheckStatus.ERROR
		assert "Out of 3 products on 2 depots checked, 2 mandatory products are not installed, 2 are out of date." in result.message
		assert result.upgrade_issue == "4.3"
		found = 0
		for partial_result in result.partial_results:
			if (
				partial_result.details.get("depot_id") == "test-check-depot-1.opsi.test"
				and partial_result.details.get("product_id") == "opsi-script"
			):
				found += 1
				assert partial_result.check_status == CheckStatus.ERROR
				assert "not installed" in partial_result.message
				assert partial_result.upgrade_issue == "4.3"
			if (
				partial_result.details.get("depot_id") == "test-check-depot-1.opsi.test"
				and partial_result.details.get("product_id") == "opsi-client-agent"
			):
				found += 1
				assert partial_result.check_status == CheckStatus.ERROR
				assert "is outdated" in partial_result.message
				assert partial_result.upgrade_issue == "4.3"
		assert found == 2


@pytest.mark.parametrize("installation_age", [OUTDATED_AFTER_DAYS - 1, OUTDATED_AFTER_DAYS + 1])
def test_check_products_on_clients(installation_age: int) -> None:
	now = datetime.now(tz=timezone.utc)
	installation_date = now - timedelta(days=installation_age)

	_prepare_products(depot_installation_time=installation_date)

	check_manager.register(opsi_products_on_clients_check)
	result = check_manager.get("products_on_clients").run(clear_cache=True)

	if installation_age < OUTDATED_AFTER_DAYS:
		assert result.check_status == CheckStatus.OK
		assert result.message == "All products are up to date on all clients."
		assert result.upgrade_issue is None
		assert len(result.partial_results) == 0
	else:
		assert result.check_status == CheckStatus.ERROR
		assert result.message == "Out-of-date products were found on 1 out of 2 clients checked."
		assert result.upgrade_issue == "4.3"

		assert len(result.partial_results) == 1

		partial_result = result.partial_results[0]
		assert partial_result.check_status == CheckStatus.ERROR
		assert "is outdated" in partial_result.message
		assert partial_result.upgrade_issue == "4.3"


def test_check_locked_products() -> None:
	_prepare_products()
	backend = get_unprotected_backend()

	check_manager.register(opsi_locked_products_check)
	result = check_manager.get("locked_products").run(clear_cache=True)

	assert result.check_status == CheckStatus.OK

	# Lock product on depot and check again. Should return ERROR
	depot = OpsiDepotserver(id="test-check-depot-1.opsi.test")
	product = LocalbootProduct(id="locked-product", productVersion="4.3.0.1", packageVersion="1")
	product_on_depot = ProductOnDepot(
		locked=True,
		productId=product.id,
		productType=product.getType(),
		productVersion=product.productVersion,
		packageVersion=product.packageVersion,
		depotId=depot.id,
	)

	backend.host_createObjects([depot])
	backend.product_createObjects([product])
	backend.productOnDepot_createObjects([product_on_depot])

	result = check_manager.get("locked_products").run(clear_cache=True)
	assert result.check_status == CheckStatus.WARNING
