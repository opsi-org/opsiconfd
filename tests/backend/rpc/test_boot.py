# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
test opsiconfd.backend.rpc.depot
"""

from pathlib import Path
from unittest.mock import patch

from opsicommon.objects import NetbootProduct, OpsiClient, ProductOnClient, ProductOnDepot, UnicodeConfig

from opsiconfd.config import get_depotserver_id
from tests.utils import UnprotectedBackend, backend, clean_mysql  # noqa: F401

TESTDIR = Path("tests/data/workbench/test_dir")
TESTFILE = TESTDIR / "testfile"
TESTPACKAGE_NAME = "localboot_legacy"
TESTPACKAGE = Path(f"tests/data/workbench/{TESTPACKAGE_NAME}_42.0-1337.opsi")
CONTROLFILE = Path("tests/data/workbench/control")


def test_boot_getConfig(
	backend: UnprotectedBackend,  # noqa: F811
	tmp_path: Path,
) -> None:
	product_id = "test-boot-product1"
	client_id = "test-boot-client1.opsi.test"
	depot_id = get_depotserver_id()

	depot_dir = tmp_path / "depot"
	product_dir = depot_dir / product_id
	product_dir.mkdir(parents=True)
	bootimage_dir = tmp_path / "opsi-linux-bootimage"
	default_template = bootimage_dir / "cfg/install-grub-x64"
	default_template.parent.mkdir(parents=True)
	default_template.write_text("# grub config\n", encoding="utf-8")

	backend.config_createObjects(
		[
			UnicodeConfig(
				id="clientconfig.configserver.url",
				description="URL(s) of opsi config service(s) to use",
				possibleValues=["https://opsiservice.opsi.test:4447/rpc"],
				defaultValues=["https://opsiservice.opsi.test:4447/rpc"],
				editable=True,
				multiValue=True,
			)
		]
	)

	client = OpsiClient(
		id=client_id,
		opsiHostKey="fe5e2020410d947c58508cdcd29d9ec0",
		hardwareAddress="01:02:03:04:05:06",
		systemUUID="6a6fa111-a6a6-42da-bb96-f1401ab95a06",
	)
	product = NetbootProduct(id=product_id, productVersion="1", packageVersion="1")
	product_on_depot = ProductOnDepot(
		productId=product.id,
		productType=product.getType(),
		productVersion=product.productVersion,
		packageVersion=product.packageVersion,
		depotId=depot_id,
	)
	product_on_client = ProductOnClient(productId=product.id, productType=product.getType(), clientId=client_id, actionRequest="setup")

	backend.host_createObjects([client])
	backend.product_createObjects([product])
	backend.productOnDepot_createObjects([product_on_depot])

	with (
		patch("opsiconfd.backend.rpc.boot.DEPOT_DIR", str(depot_dir)),
		patch("opsiconfd.backend.rpc.boot.BOOTIMAGE_PATH", bootimage_dir),
	):
		boot_config = backend.boot_getConfig(client_id=client_id)
		assert boot_config.linux_bootimage_kernel_params is None

		backend.productOnClient_createObjects([product_on_client])
		for bios_type in ["UEFI", "BIOS"]:
			for kwargs in (
				{"client_id": client_id},
				{"system_uuid": client.systemUUID},
				{"hardware_address": client.hardwareAddress},
			):
				kwargs["bios_type"] = bios_type
				kwargs["architecture"] = "x64" if bios_type == "UEFI" else "x86"

				boot_config = backend.boot_getConfig(**kwargs)

				if bios_type == "UEFI":
					assert boot_config.pxe_boot_filename == str(bootimage_dir / "loader/shimx64.efi.signed")
				else:
					assert boot_config.pxe_boot_filename == str(bootimage_dir / "loader/opsi-netboot.pxe")

				assert boot_config.grub_config == "# grub config\n"

				assert boot_config.linux_bootimage_kernel_params["hn"] == client_id.split(".")[0]
				assert boot_config.linux_bootimage_kernel_params["dn"] == ".".join(client_id.split(".")[1:])
				assert boot_config.linux_bootimage_kernel_params["pckey"] == client.opsiHostKey
				assert boot_config.linux_bootimage_kernel_params["macaddress"] == client.hardwareAddress
				assert boot_config.linux_bootimage_kernel_params["service"] == "https://opsiservice.opsi.test:4447/rpc"
				assert boot_config.linux_bootimage_kernel_params["product"] == product_on_client.productId
