# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
setup tests
"""

from unittest.mock import PropertyMock, patch

from opsicommon.objects import (
	ConfigState,
	LocalbootProduct,
	OpsiClient,
	OpsiDepotserver,
	ProductOnClient,
	ProductOnDepot,
	UnicodeConfig,
)

from opsiconfd.setup.configs import _auto_correct_depot_urls, _cleanup_product_on_clients, _get_windows_domain, setup_configs
from tests.utils import UnprotectedBackend, backend, clean_mysql  # noqa: F401


def test_get_windows_domain() -> None:
	class Proc:
		stdout = ""

	with patch("opsiconfd.setup.configs.run", PropertyMock(return_value=Proc())):
		Proc.stdout = (
			"SID for local machine MACHINE is: S-1-5-21-3621911554-2635998167-701618891\n"
			"SID for domain DOMAIN is: S-1-5-21-3621911554-701618891-2635998167\n"
		)
		assert _get_windows_domain() == "DOMAIN"

		Proc.stdout = "SID for local machine MACHINE is: S-1-5-21-3621911554-2635998167-701618891\nCould not fetch domain SID\n"
		assert _get_windows_domain() == "MACHINE"


def test_fix_urls(backend: UnprotectedBackend) -> None:  # noqa: F811
	depot = OpsiDepotserver(
		id="test-depot-1.opsi.org",
		depotLocalUrl="file:///var/lib/opsi/depot",
		depotRemoteUrl="smb:///test-depot-1.opsi.org/opsi_depot",
		depotWebdavUrl="webdavs:///test-depot-1.opsi.org:4447/opsi-web-interface",
		repositoryLocalUrl="file:///var/lib/opsi/repository",
		repositoryRemoteUrl="webdavs://test-depot-1.opsi.org:4447/repository",
		workbenchLocalUrl="file:///var/lib/opsi/workbench",
		workbenchRemoteUrl="webdavs:///test-depot-1.opsi.org:4447/workbench",
	)
	backend.host_createObjects([depot])
	_auto_correct_depot_urls(backend)

	depot_corrected = backend.host_getObjects(id=depot.id)[0]
	assert depot_corrected.depotLocalUrl == "file:///var/lib/opsi/depot"
	assert depot_corrected.depotRemoteUrl == "smb://test-depot-1.opsi.org/opsi_depot"
	assert depot_corrected.depotWebdavUrl == "webdavs://test-depot-1.opsi.org:4447/opsi-web-interface"
	assert depot_corrected.repositoryLocalUrl == "file:///var/lib/opsi/repository"
	assert depot_corrected.repositoryRemoteUrl == "webdavs://test-depot-1.opsi.org:4447/repository"
	assert depot_corrected.workbenchLocalUrl == "file:///var/lib/opsi/workbench"
	assert depot_corrected.workbenchRemoteUrl == "webdavs://test-depot-1.opsi.org:4447/workbench"


def test_cleanup_product_on_clients(backend: UnprotectedBackend) -> None:  # noqa: F811
	depot1 = OpsiDepotserver(id="test-cleanup-depot-1.opsi.test")
	client1 = OpsiClient(id="test-cleanup-host-1.opsi.test")
	product1 = LocalbootProduct(
		id="test-cleanup-product1",
		productVersion="1",
		packageVersion="1",
		priority=100,
		setupScript="setup.opsiscript",
		uninstallScript="uninstall.opsiscript",
		alwaysScript="always.opsiscript",
		onceScript="once.opsiscript",
	)
	product2 = LocalbootProduct(
		id="test-cleanup-product2",
		productVersion="1",
		packageVersion="1",
		priority=0,
		setupScript="setup.opsiscript",
		uninstallScript="uninstall.opsiscript",
		alwaysScript="always.opsiscript",
		onceScript="once.opsiscript",
	)
	product_on_depot1 = ProductOnDepot(
		productId=product1.id,
		productType=product1.getType(),
		productVersion=product1.productVersion,
		packageVersion=product1.packageVersion,
		depotId=depot1.id,
	)
	product_on_client1 = ProductOnClient(
		productId=product1.id,
		productType=product1.getType(),
		productVersion=product1.productVersion,
		packageVersion=product1.packageVersion,
		clientId=client1.id,
		installationStatus="installed",
		actionRequest="setup",
	)
	product_on_client2 = ProductOnClient(
		productId=product2.id,
		productType=product2.getType(),
		productVersion=product2.productVersion,
		packageVersion=product2.packageVersion,
		clientId=client1.id,
		installationStatus="installed",
		actionRequest="setup",
	)
	config_state = ConfigState(configId="clientconfig.depot.id", objectId=client1.id, values=[depot1.id])

	backend.host_createObjects([depot1, client1])
	backend.configState_createObjects([config_state])
	backend.product_createObjects([product1, product2])
	backend.productOnDepot_createObjects([product_on_depot1])
	backend.productOnClient_createObjects([product_on_client1, product_on_client2])

	# product2 is not installed on depot, actionRequest must be set to "none"
	_cleanup_product_on_clients(backend)

	pocs = backend.productOnClient_getObjects(clientId=client1.id)
	assert len(pocs) == 2
	for poc in pocs:
		assert poc.productId in (product1.id, product2.id)
		if poc.productId == product1.id:
			assert poc.actionRequest == "setup"
		elif poc.productId == product2.id:
			assert poc.actionRequest == "none"


def test_migrate_bootimage_append(backend: UnprotectedBackend) -> None:  # noqa: F811
	client1 = OpsiClient(id="test-migrate-append-1.opsi.test")
	client2 = OpsiClient(id="test-migrate-append-2.opsi.test")
	client3 = OpsiClient(id="test-migrate-append-3.opsi.test")
	legacy_config = UnicodeConfig(
		id="opsi-linux-bootimage.append",
		description="Extra options to append to kernel command line",
		possibleValues=[
			"acpi=off",
			"irqpoll",
			"noapic",
			"pci=nomsi",
			"vga=normal",
			"reboot=b",
			"mem=2G",
			"nomodeset",
			"ramdisk_size=2097152",
			"dhclienttimeout=N",
		],
		defaultValues=["vga=normal"],
		editable=True,
		multiValue=True,
	)
	config_state1 = ConfigState(
		configId=legacy_config.id, objectId=client1.id, values=["acpi=off", "reboot= b , w", "irqpoll", "pci=nomsi", "mem=2G"]
	)
	config_state2 = ConfigState(
		configId=legacy_config.id,
		objectId=client2.id,
		values=[
			"dhclienttimeout=N",
			"reboot=b, k,w",
			"vga=normal ",
			"noapic",
			"modprobe.blacklist=pcspkr, snd_pcsp",
		],
	)

	backend.host_createObjects([client1, client2, client3])
	backend.config_createObjects([legacy_config])
	backend.configState_createObjects([config_state1, config_state2])

	setup_configs()

	configs = {c.id: c for c in backend.config_getObjects(id=["opsi-linux-bootimage.append", "netboot.linux-bootimage.cmdline.*"])}
	assert len(configs["netboot.linux-bootimage.cmdline.pwh"].possibleValues[0]) == 8
	assert (
		configs["opsi-linux-bootimage.append"].description
		== "**OBSOLETE**, please use the specific configs instead: netboot.linux-bootimage.cmdline.*"
	)
	assert configs["opsi-linux-bootimage.append"].defaultValues == ["vga=normal"]

	new_states = sorted(
		backend.configState_getObjects(configId="netboot.linux-bootimage.cmdline.*"), key=lambda s: (s.objectId, s.configId)
	)
	assert len(new_states) == 9

	assert new_states[0].objectId == client1.id
	assert new_states[0].configId == "netboot.linux-bootimage.cmdline.acpi"
	assert new_states[0].values == ["off"]

	assert new_states[1].objectId == client1.id
	assert new_states[1].configId == "netboot.linux-bootimage.cmdline.irqpoll"
	assert new_states[1].values == [True]

	assert new_states[2].objectId == client1.id
	assert new_states[2].configId == "netboot.linux-bootimage.cmdline.mem"
	assert new_states[2].values == ["2G"]

	assert new_states[3].objectId == client1.id
	assert new_states[3].configId == "netboot.linux-bootimage.cmdline.pci"
	assert new_states[3].values == ["nomsi"]

	assert new_states[4].objectId == client1.id
	assert new_states[4].configId == "netboot.linux-bootimage.cmdline.reboot"
	assert new_states[4].values == ["b", "w"]

	assert new_states[5].objectId == client2.id
	assert new_states[5].configId == "netboot.linux-bootimage.cmdline.modprobe.blacklist"
	assert new_states[5].values == ["pcspkr", "snd_pcsp"]

	assert new_states[6].objectId == client2.id
	assert new_states[6].configId == "netboot.linux-bootimage.cmdline.noapic"
	assert new_states[6].values == [True]

	assert new_states[7].objectId == client2.id
	assert new_states[7].configId == "netboot.linux-bootimage.cmdline.reboot"
	assert new_states[7].values == ["b", "k", "w"]

	assert new_states[8].objectId == client2.id
	assert new_states[8].configId == "netboot.linux-bootimage.cmdline.vga"
	assert new_states[8].values == ["normal"]
