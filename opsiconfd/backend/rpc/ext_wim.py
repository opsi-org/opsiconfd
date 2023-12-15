# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
rpc methods wim
"""
from __future__ import annotations

import itertools
import os
from typing import TYPE_CHECKING, Protocol

from opsicommon.exceptions import BackendMissingDataError
from opsicommon.objects import ProductProperty
from opsicommon.package.wim import wim_info
from opsicommon.types import forceList, forceObjectClass, forceProductId

from opsiconfd.config import get_depotserver_id
from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


class RPCExtWIMMixin(Protocol):  # pylint: disable=too-few-public-methods
	def _wim_get_product_property(self: BackendProtocol, product_id: str, property_id: str) -> ProductProperty:
		product_filter = {"productId": product_id, "propertyId": property_id}
		properties = self.productProperty_getObjects(**product_filter)
		logger.debug("Properties: %s", properties)

		if not properties:
			raise RuntimeError(f"Property {property_id!r} not found for product {product_id!r}")
		if len(properties) > 1:
			logger.debug("Found more than one property, trying to be more specific")
			products_on_depot = self.productOnDepot_getObjects(depotId=self._depot_id, productId=product_id)
			if not products_on_depot:
				raise RuntimeError(f"Product {product_id!r} on depot {self._depot_id!r}")
			if len(products_on_depot) > 1:
				raise RuntimeError(f"Multiple products {product_id!r} on depot {self._depot_id!r}")

			product_on_depot = products_on_depot[0]
			product_filter["packageVersion"] = product_on_depot.packageVersion
			product_filter["productVersion"] = product_on_depot.productVersion
			logger.debug("Filter: %s", product_filter)
			properties = self.productProperty_getObjects(**product_filter)
			logger.debug("Properties: %s", properties)

			if not properties:
				raise RuntimeError(f"Property {property_id!r} not found for product {product_id!r}")
			if len(properties) > 1:
				raise RuntimeError("Multiple product properties found")

		return properties[0]

	def _wim_write_image_information(
		self: BackendProtocol,
		product_id: str,
		image_names: list[str],
		languages: list[str] | None = None,
		default_language: str | None = None,
	) -> None:
		"""
		Writes information about the `image_names` to the property *imagename* of the product with the given `product_id`.

		If `languages` are given these will be written to the property *system_language*.
		If an additional `default_language` is given this will be selected as the default.
		"""
		product_id = forceProductId(product_id)
		product_property = self._wim_get_product_property(product_id, "imagename")
		product_property.possibleValues = image_names
		if product_property.defaultValues:
			if product_property.defaultValues[0] not in image_names:
				logger.info("Mismatching default value, setting first imagename as default")
				product_property.defaultValues = [image_names[0]]
		else:
			logger.info("No default values found, setting first imagename as default")
			product_property.defaultValues = [image_names[0]]

		product_property = forceObjectClass(product_property, ProductProperty)
		self._product_property_insert_object(product_property=product_property, ace=[], create=False, set_null=False)
		logger.notice("Wrote imagenames to property 'imagename' of product %r.", product_id)

		if not languages:
			return

		logger.debug("Writing detected languages")
		for product_property in (
			self._wim_get_product_property(product_id, "system_language"),
			self._wim_get_product_property(product_id, "winpe_uilanguage"),
			self._wim_get_product_property(product_id, "winpe_uilanguage_fallback"),
		):
			product_property.possibleValues = forceList(languages)
			if default_language and default_language in languages:
				logger.debug("Setting language default to %r", default_language)
				product_property.defaultValues = [default_language]

			logger.debug(
				"%r possibleValues=%r, defaultValues=%r", product_property, product_property.possibleValues, product_property.defaultValues
			)
			product_property = forceObjectClass(product_property, ProductProperty)
			self._product_property_insert_object(product_property=product_property, ace=[], create=False, set_null=False)
			logger.notice("Wrote languages to property %r of product %r.", product_property.propertyId, product_property.productId)

	@rpc_method(check_acl=False)
	def updateWIMConfig(self: BackendProtocol, productId: str) -> None:  # pylint: disable=invalid-name
		"""
		Update the configuration of a Windows netboot product based on the information in it's install.wim.

		IMPORTANT: This does only work on the configserver!
		"""
		product_id = forceProductId(productId)

		if not self.product_getObjects(id=product_id):
			raise BackendMissingDataError(f"No product with ID {product_id!r}")

		depot_id = get_depotserver_id()
		if not self.productOnDepot_getObjects(depotId=depot_id, productId=product_id):
			raise BackendMissingDataError(f"No product {product_id!r} on {depot_id!r}")

		depot = self.host_getObjects(id=depot_id, type="OpsiDepotserver")
		depot = depot[0]
		logger.debug("Working with %s", depot)

		depot_path = depot.depotLocalUrl
		if not depot_path.startswith("file://"):
			raise ValueError(f"Unable to handle the depot remote local url {depot_path!r}.")

		depot_path = depot_path[7:]
		logger.debug("Created path %s", depot_path)
		product_path = os.path.join(depot_path, product_id)
		wim_search_path = os.path.join(product_path, "installfiles", "sources")

		for filename in ("install.wim", "install.esd"):
			wim_path = os.path.join(wim_search_path, filename)

			if os.path.exists(wim_path):
				logger.debug("Found image file %s", filename)
				break
		else:
			raise IOError(f"Unable to find install.wim / install.esd in {wim_search_path!r}")

		self.updateWIMConfigFromPath(wim_path, product_id)

	@rpc_method(check_acl=False)
	def updateWIMConfigFromPath(self: BackendProtocol, path: str, targetProductId: str) -> None:  # pylint: disable=invalid-name
		"""
		Update the configuration of `targetProductId` based on the information in the install.wim at the given `path`.

		IMPORTANT: This does only work on the configserver!
		"""
		if not targetProductId:
			return

		images = wim_info(path).images
		image_names = [image.name for image in images]
		languages = list(
			set(itertools.chain(*[img.windows_info.languages for img in images if img.windows_info and img.windows_info.languages]))
		)
		default_languages = list(
			{img.windows_info.default_language for img in images if img.windows_info and img.windows_info.default_language}
		)

		default_language = None
		if len(default_languages) == 1:
			default_language = default_languages[0]
			logger.info("Default language %s found for wim %s", default_language, path)
		elif len(default_languages) > 1:
			logger.info("Multiple default languages %s found for wim %s, not setting a default", default_languages, path)
		else:
			logger.info("No default language found for wim %s", path)

		self._wim_write_image_information(
			targetProductId,
			image_names,
			languages,
			default_language,
		)
