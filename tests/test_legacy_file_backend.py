# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""Tests for reading the retired opsi file backend format."""

from pathlib import Path
from unittest.mock import Mock

from opsi.opsi.service.model.object import HostGroup, OpsiClient, OpsiConfigserver

from opsiconfd.setup.legacy_file_backend import LegacyFileBackendReader, import_legacy_file_backend


def test_read_host_keys_and_unescape(tmp_path: Path) -> None:
	"""Legacy host keys and escaped INI values are decoded."""
	host_key_file = tmp_path / "pckeys"
	host_key_file.write_text("# comment\nCLIENT.TEST.INVALID: 0123456789abcdef\ninvalid\n", encoding="utf-8")
	reader = LegacyFileBackendReader(base_dir=tmp_path, host_key_file=host_key_file)

	assert reader.read_host_keys() == {"client.test.invalid": "0123456789abcdef"}
	assert reader.unescape(r"line 1\nline 2\; \# 100%%") == "line 1\nline 2; # 100%"


def test_read_legacy_file_backend(tmp_path: Path) -> None:
	"""A representative legacy backend is converted to modern objects."""
	base_dir = tmp_path / "config"
	for directory in ("clients", "depots", "products"):
		(base_dir / directory).mkdir(parents=True)
	(base_dir / "config.ini").write_text(
		"""[clientconfig.test]
type = UnicodeConfig
description = Test\\nconfig
editable = true
multivalue = false
possiblevalues = ["one", "two"]
defaultvalues = ["one"]
""",
		encoding="utf-8",
	)
	(base_dir / "depots" / "server.test.invalid.ini").write_text(
		"""[depotserver]
description = Config server
network = 192.0.2.0/24
ismasterdepot = true
[depotshare]
localurl = file:///var/lib/opsi/depot
remoteurl = smb://server.test.invalid/opsi_depot
webdavurl = webdavs://server.test.invalid:4447/depot
[repository]
localurl = file:///var/lib/opsi/repository
remoteurl = webdavs://server.test.invalid:4447/repository
maxbandwidth = 0
[test-product-state]
producttype = LocalbootProduct
productversion = 1.0
packageversion = 1
locked = false
[generalconfig]
clientconfig.test = ["two"]
""",
		encoding="utf-8",
	)
	(base_dir / "clients" / "client.test.invalid.ini").write_text(
		"""[info]
description = Client
[test-product-state]
producttype = LocalbootProduct
productversion = 1.0
packageversion = 1
[LocalbootProduct_product_states]
test-product = installed:none
[test-product-install]
choice = ["value"]
[generalconfig]
clientconfig.test = ["one"]
""",
		encoding="utf-8",
	)
	(base_dir / "products" / "test-product_1.0-1.localboot").write_text(
		"""[Package]
version: 1
[Product]
type: localboot
id: test-product
name: Test product
description: Product description
advice:
version: 1.0
priority: 0
licenseRequired: false
productClasses:
setupScript: setup.ins
[ProductProperty]
type: unicode
name: choice
description: Choice
values: ["value"]
default: ["value"]
editable: false
multivalue: false
[ProductDependency]
action: setup
requiredProduct: dependency
requiredStatus: installed
requirementType: before
""",
		encoding="utf-8",
	)
	(base_dir / "clientgroups.ini").write_text(
		"""[parent]
description = Parent
client.test.invalid = yes
[child]
parentgroupid = parent
""",
		encoding="utf-8",
	)
	(base_dir / "productgroups.ini").write_text("[products]\ntest-product = 1\n", encoding="utf-8")
	host_key_file = tmp_path / "pckeys"
	host_key_file.write_text(
		"server.test.invalid: 0123456789abcdef0123456789abcdef\nclient.test.invalid: abcdef0123456789abcdef0123456789\n",
		encoding="utf-8",
	)

	data = LegacyFileBackendReader(base_dir, host_key_file, "server.test.invalid").read()

	assert data.counts() == {
		"hosts": 2,
		"products": 1,
		"configs": 1,
		"groups": 3,
		"product_dependencies": 1,
		"product_properties": 1,
		"product_on_depots": 1,
		"product_on_clients": 1,
		"product_property_states": 1,
		"config_states": 2,
		"objects_to_groups": 2,
	}
	assert isinstance(data.hosts[0], OpsiConfigserver)
	assert isinstance(data.hosts[1], OpsiClient)
	assert data.configs[0].description == "Test\nconfig"
	assert [group.id for group in data.groups if isinstance(group, HostGroup)] == ["parent", "child"]
	assert data.product_on_clients[0].installationStatus == "installed"

	backend = Mock()
	import_legacy_file_backend(data, backend)
	assert backend.host_insertObject.call_count == 2
	assert backend.product_insertObject.call_count == 1
	assert backend.objectToGroup_insertObject.call_count == 2
