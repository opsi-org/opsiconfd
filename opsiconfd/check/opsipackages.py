# # -*- coding: utf-8 -*-

# # opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# # Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# # All rights reserved.
# # License: AGPL-3.0

# """
# health check
# """


from dataclasses import dataclass
from datetime import datetime, timezone

import requests
from opsicommon.package.repo_meta import RepoMetaPackageCollection
from opsicommon.utils import compare_versions, prepare_proxy_environment

from opsiconfd.backend import get_unprotected_backend
from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager, exc_to_result
from opsiconfd.logging import logger

OPSI_PACKAGES_HOST = "opsipackages.43.opsi.org"
OPSI_REPO_FILE = f"https://{OPSI_PACKAGES_HOST}/stable/packages.msgpack.zstd"
MANDATORY_OPSI_PRODUCTS = ("opsi-script", "opsi-client-agent")
MANDATORY_IF_INSTALLED = ("opsi-script", "opsi-client-agent", "opsi-linux-client-agent", "opsi-macos-client-agent")


def get_available_product_versions(product_ids: list[str]) -> dict:
	available_packages = {}
	session = prepare_proxy_environment(OPSI_PACKAGES_HOST)

	res = session.get(OPSI_REPO_FILE, timeout=10, stream=True)
	res.raise_for_status()

	col = RepoMetaPackageCollection()
	col.read_metafile_data(res.raw.read())
	for product_id in product_ids:
		if product_id in col.packages:
			available_packages[product_id] = list(col.packages[product_id])[0]
		else:
			available_packages[product_id] = "0.0"

	return available_packages


def get_enabled_hosts() -> list[str]:
	backend = get_unprotected_backend()
	config_states = backend.configState_getValues(["opsi.check.enabled", "opsi.check.downtime.start", "opsi.check.downtime.end"])
	downtime_hosts = []
	now = datetime.now().astimezone()
	server_timezone = now.tzinfo
	for host in config_states:
		if not config_states[host].get("opsi.check.downtime.end"):
			continue

		if config_states[host].get("opsi.check.downtime.start"):
			downtime_start = datetime.fromisoformat(config_states[host].get("opsi.check.downtime.start")[0])
		else:
			downtime_start = datetime(year=2024, month=1, day=1, tzinfo=timezone.utc)
		if downtime_start.tzinfo is None:
			downtime_start = downtime_start.replace(tzinfo=server_timezone)

		downtime_end = datetime.fromisoformat(config_states[host].get("opsi.check.downtime.end")[0])
		if downtime_end.tzinfo is None:
			downtime_end = downtime_end.replace(tzinfo=server_timezone)

		if downtime_start < now and downtime_end > now:
			downtime_hosts.append(host)
	return [host for host in config_states if config_states[host].get("opsi.check.enabled", [True])[0] and host not in downtime_hosts]


@dataclass()
class OpsiProductsOnDepotsCheck(Check):
	id: str = "products_on_depots"
	name: str = "Products on depots"
	description: str = "Check opsi package versions on depots"
	documentation: str = """
		## Products on depots

		It is checked whether the following products are installed and up-to-date on the depots:

		* opsi-script
		* opsi-client-agent

		If opsi-linux-client-agent and opsi-macos-client-agent are installed, these packages are also checked.
		Here, an outdated package is considered a warning and an uninstalled package is considered an error.
	"""
	cache_partial_checks: bool = True

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="All important products are up to date on all depots.",
			check_status=CheckStatus.OK,
		)
		with exc_to_result(result):
			result.message = "All important products are up to date on all depots."

			backend = get_unprotected_backend()
			installed_products = [p.id for p in backend.product_getObjects()]

			not_installed = 0
			outdated = 0
			try:
				available_packages = get_available_product_versions(installed_products + list(MANDATORY_OPSI_PRODUCTS))
			except requests.RequestException as err:
				result.check_status = CheckStatus.ERROR
				result.message = f"Failed to get package info from repository '{OPSI_REPO_FILE}': {err}"
				return result

			depots = backend.host_getIdents(type="OpsiDepotserver")
			packages_not_on_repo = []

			enabled_hosts = get_enabled_hosts()
			for depot_id in depots:
				if depot_id not in enabled_hosts:
					continue
				for product_id, available_version in available_packages.items():
					partial_result = CheckResult(
						check=self,
						details={"depot_id": depot_id, "product_id": product_id},
					)
					try:
						product_on_depot = backend.productOnDepot_getObjects(productId=product_id, depotId=depot_id)[0]
					except IndexError:
						if product_id not in MANDATORY_OPSI_PRODUCTS:
							continue
						not_installed = not_installed + 1
						partial_result.check_status = CheckStatus.ERROR
						partial_result.message = f"Mandatory product {product_id!r} is not installed on depot {depot_id!r}."
						partial_result.upgrade_issue = "4.3"
						result.add_partial_result(partial_result)
						continue

					product_version_on_depot = f"{product_on_depot.productVersion}-{product_on_depot.packageVersion}"
					partial_result.details["version"] = product_version_on_depot
					partial_result.details["available_version"] = available_version

					if compare_versions(available_version, ">", product_version_on_depot):
						outdated = outdated + 1
						if product_id in MANDATORY_OPSI_PRODUCTS or (
							product_id in installed_products and product_id in MANDATORY_IF_INSTALLED
						):
							partial_result.check_status = CheckStatus.ERROR
							partial_result.message = (
								f"Mandatory product {product_id!r} is outdated on depot {depot_id!r}. Installed version {product_version_on_depot!r}"
								f" < available version {available_version!r}."
							)
							partial_result.upgrade_issue = "4.3"
						else:
							partial_result.check_status = CheckStatus.WARNING
							partial_result.message = (
								f"Product {product_id!r} is outdated on depot {depot_id!r}. Installed version {product_version_on_depot!r}"
								f" < available version {available_version!r}."
							)
					elif available_version == "0.0":
						logger.info("Could not find product %r on repository %s.", product_id, OPSI_REPO_FILE)
						logger.info("Removing product %r from checked list.", product_id)
						packages_not_on_repo.append(product_id)
						continue
					else:
						partial_result.check_status = CheckStatus.OK
						partial_result.message = (
							f"Installed version of product {product_id!r} on depot {depot_id!r} is {product_version_on_depot!r}."
						)

					if product_on_depot.productType == "NetbootProduct" and compare_versions(
						available_version, ">", product_version_on_depot
					):
						partial_result.upgrade_issue = "4.3"

					result.add_partial_result(partial_result)

			for package in packages_not_on_repo:
				if package in available_packages:
					del available_packages[package]
			result.details = {
				"products": len(available_packages),
				"depots": len(depots),
				"not_installed": not_installed,
				"outdated": outdated,
			}
			if not_installed > 0 or outdated > 0:
				result.message = (
					f"Out of {len(available_packages)} products on {len(depots)} depots checked, "
					f"{not_installed} mandatory products are not installed, {outdated} are out of date."
				)
		return result


@dataclass()
class OpsiProductOnClientCheck(Check):
	id: str = "product_on_client"
	name: str = "Product on client"
	description: str = "Check opsi package versions on clients"
	client_id: str = ""
	product_id: str = ""
	available_version: str = ""
	partial_check: bool = True

	def __post_init__(self) -> None:
		super().__post_init__()
		self.id = f"{self.id}:{self.client_id}:{self.product_id}"
		self.name = f"{self.name} {self.product_id!r} on {self.client_id!r}"
		self.description = f"{self.description} {self.product_id!r} on {self.client_id!r}"

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message=f"Product '{self.product_id}' is up to date on client '{self.client_id}'.",
			check_status=CheckStatus.OK,
		)
		with exc_to_result(result):
			backend = get_unprotected_backend()
			product_on_client = backend.productOnClient_getObjects(
				attributes=["productVersion", "packageVersion"],
				clientId=self.client_id,
				productId=self.product_id,
				installationStatus="installed",
			)[0]
			version = f"{product_on_client.productVersion}-{product_on_client.packageVersion}"
			if compare_versions(version, ">=", self.available_version):
				return result
			if self.product_id in MANDATORY_OPSI_PRODUCTS or self.product_id in MANDATORY_IF_INSTALLED:
				result.check_status = CheckStatus.ERROR
			else:
				result.check_status = CheckStatus.WARNING
			result.message = f"Product {self.product_id!r} is outdated on client {self.client_id!r}. Installed version {version!r} < depot version {self.available_version!r}"
			result.upgrade_issue = "4.3"

		return result


@dataclass()
class OpsiProductsOnClientsCheck(Check):
	id: str = "products_on_clients"
	name: str = "Products on clients"
	description: str = "Check opsi package versions on clients"
	documentation: str = """
		## Products on clients

		Checks whether newer versions of the products installed on the client are available in the depot.
		If an older version is installed, the Health Check issues a warning.
	"""

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="All products are up to date on all clients.",
			check_status=CheckStatus.OK,
		)
		with exc_to_result(result):
			backend = get_unprotected_backend()
			now = datetime.now()
			enabled_hosts = get_enabled_hosts()
			depots = backend.host_getObjects(attributes=["id"], type="OpsiDepotserver")
			client_ids = {
				host.id
				for host in backend.host_getObjects(attributes=["id", "lastSeen"], type="OpsiClient")
				if host.lastSeen and (now - datetime.fromisoformat(host.lastSeen)).days < 90 and host.id in enabled_hosts
			}
			if not client_ids:
				return result

			for depot in depots:
				if depot.id not in get_enabled_hosts():
					continue
				clients_on_depot = set()
				for depot_client_hash in backend.configState_getClientToDepotserver(clientIds=client_ids, depotIds=[depot.id]):
					clients_on_depot.add(depot_client_hash["clientId"])
				try:
					available_products = backend.productOnDepot_getObjects(
						depotId=depot.id, attributes=["productId", "productVersion", "packageVersion"]
					)
				except requests.RequestException as err:
					result.check_status = CheckStatus.ERROR
					result.message = f"Failed to get product info from depot '{depot.id}': {err}"
					return result
				for product in available_products:
					product_id = product.productId
					available_version = f"{product.productVersion}-{product.packageVersion}"
					for product_on_client in backend.productOnClient_getObjects(
						attributes=["productVersion", "packageVersion"],
						clientId=client_ids,
						productId=product_id,
						installationStatus="installed",
					):
						check = OpsiProductOnClientCheck(
							client_id=product_on_client.clientId,
							product_id=product_id,
							available_version=available_version,
						)
						client_ids.remove(product_on_client.clientId)

						self.add_partial_checks(check)
		return result


opsi_products_on_depots_check = OpsiProductsOnDepotsCheck()
opsi_products_on_clients_check = OpsiProductsOnClientsCheck()
check_manager.register(opsi_products_on_depots_check, opsi_products_on_clients_check)
