# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

from opsicommon.package.repo_meta import RepoMetaPackageCollection
from opsicommon.utils import compare_versions

from opsiconfd.backend import get_mysql, get_unprotected_backend
from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager
from opsiconfd.check.utils import get_enabled_hosts
from opsiconfd.logging import logger
from opsiconfd.utils import get_requests_session

OPSI_PACKAGES_HOST = "opsipackages.43.opsi.org"
OPSI_REPO_FILE = f"https://{OPSI_PACKAGES_HOST}/stable/packages.msgpack.zstd"
# Packages that must be installed and up to date on all depots
MANDATORY_DEPOT_PIDS = ("opsi-script", "opsi-client-agent")
# Packages that must be up to date on all depots and clients if installed
MANDATORY_IF_INSTALLED_PIDS = ("opsi-script", "opsi-client-agent", "opsi-linux-client-agent", "opsi-macos-client-agent")
# The number of days after which a package is considered outdated
OUTDATED_AFTER_DAYS = 7


def _fetch_repo_file() -> bytes:
	session = get_requests_session(OPSI_PACKAGES_HOST)
	res = session.get(OPSI_REPO_FILE, timeout=10, stream=True)
	res.raise_for_status()
	return res.raw.read()


def get_available_product_versions(product_ids: Iterable[str], min_age_seconds: int = 0) -> dict[str, str]:
	available_packages: dict[str, str] = {}

	now = datetime.now(tz=timezone.utc)
	col = RepoMetaPackageCollection()
	col.read_metafile_data(_fetch_repo_file())
	for package in col.get_packages():
		if package.product_id not in product_ids:
			continue
		age = (now - package.release_date).total_seconds() if package.release_date else 0
		logger.debug("Package %r was released on %r (%d seconds ago)", package.product_id, package.release_date, age)
		if age < min_age_seconds:
			logger.debug("Package %r is too young (%d seconds)", package.product_id, age)
			continue

		available_packages[package.product_id] = f"{package.product_version}-{package.package_version}"
	return available_packages


@dataclass()
class OpsiProductsOnDepotsCheck(Check):
	id: str = "products_on_depots"
	name: str = "Products On Depots"
	description: str = "Check opsi package versions on depots"
	documentation: str = f"""
		## {name} [{id}]

		It is checked whether the following products are installed and up-to-date on the depots:

		* opsi-script
		* opsi-client-agent

		If opsi-linux-client-agent and opsi-macos-client-agent are installed, these packages are also checked.
		Here, an outdated package is considered a warning and an uninstalled package is considered an error.
	"""

	def _check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="All important products are up to date on all depots.",
			check_status=CheckStatus.OK,
		)
		result.message = "All important products are up to date on all depots."

		mysql = get_mysql()
		check_product_ids: set[str] = set(MANDATORY_DEPOT_PIDS)
		depot_ids: set[str] = set()
		product_on_depot: dict[str, dict[str, tuple[str, str]]] = {}

		with mysql.session() as session:
			for row in session.execute("""
				SELECT
					pod.depotId,
					pod.productId,
					pod.productType,
					pod.productVersion,
					pod.packageVersion
				FROM
					PRODUCT_ON_DEPOT AS pod
			""").fetchall():
				depot_id = row[0]
				product_id = row[1]
				depot_ids.add(depot_id)
				check_product_ids.add(product_id)
				if depot_id not in product_on_depot:
					product_on_depot[depot_id] = {}
				product_on_depot[depot_id][product_id] = (row[2], f"{row[3]}-{row[4]}")

		# Filter out depot ids that are not enabled
		depot_ids = get_enabled_hosts(depot_ids)

		mandatory_not_installed = 0
		outdated = 0
		try:
			available_product_versions = get_available_product_versions(check_product_ids, min_age_seconds=OUTDATED_AFTER_DAYS * 24 * 3600)
		except Exception as err:
			result.check_status = CheckStatus.ERROR
			result.message = f"Failed to get package info from repository '{OPSI_REPO_FILE}': {err}"
			return result

		for depot_id in depot_ids:
			for product_id, available_version in available_product_versions.items():
				is_mandatory_depot = product_id in MANDATORY_DEPOT_PIDS
				is_mandatory = is_mandatory_depot or product_id in MANDATORY_IF_INSTALLED_PIDS
				partial_result = CheckResult(
					check=self,
					details={
						"depot_id": depot_id,
						"product_id": product_id,
						"installed_version": None,
						"available_version": available_version,
					},
				)
				try:
					product_type, product_version_on_depot = product_on_depot[depot_id][product_id]
				except KeyError:
					if is_mandatory_depot:
						mandatory_not_installed += 1
						partial_result.check_status = CheckStatus.ERROR
						partial_result.message = f"Mandatory product {product_id!r} is not installed on depot {depot_id!r}."
						partial_result.upgrade_issue = "4.3"
						result.add_partial_result(partial_result)
					continue

				partial_result.details["installed_version"] = product_version_on_depot
				if compare_versions(product_version_on_depot, ">=", available_version):
					continue

				outdated += 1
				partial_result.check_status = CheckStatus.ERROR if is_mandatory else CheckStatus.WARNING
				partial_result.message = (
					f"{'Mandatory product' if is_mandatory else 'Product'} {product_id!r} is outdated on depot {depot_id!r}. "
					f"Installed version {product_version_on_depot!r} < available version {available_version!r}."
				)
				if is_mandatory or product_type == "NetbootProduct":
					partial_result.upgrade_issue = "4.3"

				result.add_partial_result(partial_result)

		result.details = {
			"products": len(check_product_ids),
			"depots": len(depot_ids),
			"not_installed": mandatory_not_installed,
			"outdated": outdated,
		}
		if mandatory_not_installed > 0 or outdated > 0:
			result.message = (
				f"Out of {len(check_product_ids)} products on {len(depot_ids)} depots checked, "
				f"{mandatory_not_installed} mandatory products are not installed, {outdated} are out of date."
			)
		return result


@dataclass()
class OpsiProductsOnClientsCheck(Check):
	id: str = "products_on_clients"
	name: str = "Products On Clients"
	description: str = "Check opsi package versions on clients"
	documentation: str = f"""
		## {name} [{id}]

		Checks whether newer versions of the products installed on the client are available in the depot.
		If an older version is installed, the Health Check issues a warning.
	"""

	def _check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="All products are up to date on all clients.",
			check_status=CheckStatus.OK,
		)

		backend = get_unprotected_backend()
		now = datetime.now()
		enabled_hosts = get_enabled_hosts()
		client_ids = {
			host.id
			for host in backend.host_getObjects(attributes=["id", "lastSeen"], type="OpsiClient")
			if host.lastSeen and (now - datetime.fromisoformat(host.lastSeen)).days < 90 and host.id in enabled_hosts
		}
		if not client_ids:
			return result

		mysql = get_mysql()
		depot_ids: set[str] = set()
		product_on_depot: dict[str, dict[str, str]] = {}
		product_on_client: dict[str, dict[str, str]] = {}

		ignore_product_ids = []
		opsi_check_ignore_products = backend.config_getObjects(id="opsi.check.ignore_products")
		if opsi_check_ignore_products:
			ignore_product_ids = opsi_check_ignore_products[0].defaultValues

		with mysql.session() as session:
			for row in session.execute(
				"""
				SELECT
					pod.depotId,
					pod.productId,
					pod.productVersion,
					pod.packageVersion
				FROM
					PRODUCT_ON_DEPOT AS pod
				WHERE
					pod.productType = "LocalbootProduct" AND
					pod.productId NOT IN :ignore_product_ids AND
					pod.installationTime <= :installation_time
			""",
				{
					"ignore_product_ids": ignore_product_ids,
					"installation_time": datetime.now(tz=timezone.utc) - timedelta(days=OUTDATED_AFTER_DAYS),
				},
			).fetchall():
				depot_id = row[0]
				product_id = row[1]
				depot_ids.add(depot_id)
				if depot_id not in product_on_depot:
					product_on_depot[depot_id] = {}
				product_on_depot[depot_id][product_id] = f"{row[2]}-{row[3]}"

			for row in session.execute(
				"""
				SELECT
					poc.clientId,
					poc.productId,
					poc.productVersion,
					poc.packageVersion
				FROM
					PRODUCT_ON_CLIENT AS poc
				WHERE
					poc.productType = "LocalbootProduct" AND
					poc.installationStatus = "installed" AND
					poc.productId NOT IN :ignore_product_ids AND
					poc.clientId IN :client_ids
			""",
				{"ignore_product_ids": ignore_product_ids, "client_ids": list(client_ids)},
			).fetchall():
				client_id = row[0]
				if client_id not in product_on_client:
					product_on_client[client_id] = {}
				product_on_client[client_id][row[1]] = f"{row[2]}-{row[3]}"

		# Filter out depot ids that are not enabled
		depot_ids = depot_ids.intersection(enabled_hosts)

		outdated_clients = set()
		for depot_id in depot_ids:
			client_ids_on_depot = set()
			for depot_to_client in backend.configState_getClientToDepotserver(clientIds=list(client_ids), depotIds=[depot_id]):
				client_ids_on_depot.add(depot_to_client["clientId"])

			if not client_ids_on_depot:
				logger.debug("No clients on depot %s", depot_id)
				continue

			for product_id, depot_version in product_on_depot.get(depot_id, {}).items():
				is_mandatory = product_id in MANDATORY_IF_INSTALLED_PIDS

				for client_id, pocs in product_on_client.items():
					client_version = pocs.get(product_id)
					if not client_version or compare_versions(client_version, ">=", depot_version):
						continue

					outdated_clients.add(client_id)
					partial_result = CheckResult(
						check=self,
						check_status=CheckStatus.ERROR if is_mandatory else CheckStatus.WARNING,
						message=(
							f"{'Mandatory product' if is_mandatory else 'Product'} {product_id!r} is outdated on client {client_id!r}. "
							f"Installed version {client_version!r} < depot version {depot_version!r}"
						),
						details={
							"client_id": client_id,
							"product_id": product_id,
							"depot_id": depot_id,
							"installed_version": client_version,
							"available_version": depot_version,
						},
						upgrade_issue="4.3" if is_mandatory else None,
					)
					result.add_partial_result(partial_result)

		num_outdated = len(outdated_clients)
		num_clients = len(client_ids)
		if num_outdated > 0:
			result.message = (
				f"Out-of-date products were found on {num_outdated} out of {num_clients} client{'s' if num_clients > 1 else ''} checked."
			)
		return result


@dataclass()
class OpsiLockedProductsDepotCheck(Check):
	id: str = "locked_products_depot"
	name: str = "Locked Products Depot"
	description: str = "Check for locked products on depots"
	documentation: str = f"""
		## {name} [{id}]

		Checks if there are any locked products on this depot.
	"""
	depot_id: str = ""

	def _check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message=f"No locked products found on depot: '{self.depot_id}'.",
			check_status=CheckStatus.OK,
		)
		backend = get_unprotected_backend()
		locked_products = []

		locked_products.extend(backend.productOnDepot_getObjects(depotId=self.depot_id, locked=True))
		if locked_products:
			result.message = f"Locked products found on depot: '{self.depot_id}'"
			result.check_status = CheckStatus.WARNING
			result.details = {"locked_products": [product.productId for product in locked_products]}
		return result


@dataclass()
class OpsiLockedProductsCheck(Check):
	id: str = "locked_products"
	name: str = "Locked Products"
	description: str = "Check for locked products"
	documentation: str = f"""
		## {name} [{id}]

		Checks if there are locked products on any depot.
	"""

	def _check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="No locked products found.",
			check_status=CheckStatus.OK,
		)
		backend = get_unprotected_backend()
		depots = backend.host_getIdents(type="OpsiDepotserver")
		enabled_hosts = get_enabled_hosts(host_ids=depots)
		for depot in depots:
			if depot not in enabled_hosts:
				continue
			check = OpsiLockedProductsDepotCheck(depot_id=depot)
			self.add_partial_checks(check)

		return result


opsi_products_on_depots_check = OpsiProductsOnDepotsCheck()
opsi_products_on_clients_check = OpsiProductsOnClientsCheck()
opsi_locked_products_check = OpsiLockedProductsCheck()
check_manager.register(opsi_products_on_depots_check, opsi_products_on_clients_check, opsi_locked_products_check)
