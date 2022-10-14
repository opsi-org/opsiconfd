# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test application.filetransfer
"""

from pathlib import Path
from time import time

import msgpack  # type: ignore[import]

from opsiconfd.application.filetransfer import STORAGE_DIR

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	test_client,
)


def test_raw_file_upload_download_delete(test_client: OpsiconfdTestClient) -> None:  # pylint: disable=redefined-outer-name
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	data = b"file-data"
	res = test_client.post("/file-transfer", data=data)
	assert res.status_code == 201
	file_id = res.json()["file_id"]
	assert file_id
	file_path = Path(STORAGE_DIR) / file_id
	meta_path = file_path.with_suffix(".meta")
	assert file_path.read_bytes() == data
	meta = msgpack.loads(meta_path.read_bytes())
	assert abs(time() - meta["created"]) < 10

	res = test_client.get(f"/file-transfer/{file_id}")
	assert res.status_code == 200
	assert res.content == data

	res = test_client.delete(f"/file-transfer/{file_id}")
	assert res.status_code == 200
	assert res.json()["file_id"] == file_id

	assert not file_path.exists()
	assert not meta_path.exists()
