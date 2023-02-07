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

from OPSI.Util.WIM import parseWIM, writeImageInformation  # type: ignore[import]
from opsicommon.exceptions import BackendMissingDataError  # type: ignore[import]
from opsicommon.types import forceProductId  # type: ignore[import]

from opsiconfd.config import get_depotserver_id
from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


class RPCExtWIMMixin(Protocol):  # pylint: disable=too-few-public-methods
	@rpc_method
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

	@rpc_method
	def updateWIMConfigFromPath(self: BackendProtocol, path: str, targetProductId: str) -> None:  # pylint: disable=invalid-name
		"""
		Update the configuration of `targetProductId` based on the information in the install.wim at the given `path`.

		IMPORTANT: This does only work on the configserver!
		"""
		if not targetProductId:
			return

		images = parseWIM(path)
		default_languages: set[str] = {image.default_language for image in images if image.default_language}
		default_language = None
		if len(default_languages) == 1:
			default_language = list(default_languages)[0]
		elif len(default_languages) > 1:
			logger.info("Multiple default languages: %s", default_language)
			logger.info("Not setting a default.")
		else:
			logger.info("Unable to find a default language.")

		writeImageInformation(
			self,
			targetProductId,
			[image.name for image in images],
			list(set(itertools.chain(*[image.languages for image in images if image.languages]))),
			default_language,
		)
