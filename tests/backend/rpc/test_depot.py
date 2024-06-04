# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
test opsiconfd.backend.rpc.depot
"""

import shutil
from pathlib import Path

from opsicommon.objects import NetbootProduct
from tests.utils import UnprotectedBackend, backend, clean_mysql  # noqa: F401

from unittest.mock import patch


def test_depot_createDriverLinks(
	backend: UnprotectedBackend,  # noqa: F811
	tmp_path: Path,
) -> None:
	product = NetbootProduct(id="win11-x64-drivers-test", productVersion="1", packageVersion="1")
	backend.product_createObjects([product])
	client_data_dir = tmp_path / product.id
	drivers_dir = client_data_dir / "drivers"
	client_data_dir.mkdir()
	shutil.copytree("tests/data/windows_drivers", drivers_dir)
	with patch("opsiconfd.backend.rpc.depot.DEPOT_DIR", str(tmp_path)):
		backend.depot_createDriverLinks(productId=product.id)
