# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2025 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
test opsiconfd.backend.rpc.depot
"""

import re
from pathlib import Path
from textwrap import dedent
from typing import Any
from unittest import mock
from unittest.mock import patch

import pytest
from opsicommon.objects import BoolConfig, NetbootProduct, OpsiClient, OpsiDepotserver, ProductOnClient, ProductOnDepot, UnicodeConfig

from opsiconfd.backend.rpc.boot import (
	BootConfig,
	Template,
	# get_template_context,
	# render_grub_cfg,
	TemplateContext,
	TemplateContextConfigState,
	TemplateContextConfigStates,
)
from opsiconfd.config import get_depotserver_id
from tests.utils import UnprotectedBackend, backend, clean_mysql  # noqa: F401

TESTDIR = Path("tests/data/workbench/test_dir")
TESTFILE = TESTDIR / "testfile"
TESTPACKAGE_NAME = "localboot_legacy"
TESTPACKAGE = Path(f"tests/data/workbench/{TESTPACKAGE_NAME}_42.0-1337.opsi")
CONTROLFILE = Path("tests/data/workbench/control")


def test_TemplateContextConfigStates() -> None:
	states = TemplateContextConfigStates()
	states["netboot.host_identifiers"] = TemplateContextConfigState(id="netboot.host_identifiers", values=["mac", "uuid"])
	assert states["netboot.host_identifiers"]
	assert states["netboot.host_identifiers"].exists
	assert states["netboot.host_identifiers"].value == "mac,uuid"

	# Missing entries return a default TemplateContextConfigState
	assert not states["missing"]
	assert states["missing"].exists is False
	assert states["missing"].value is None
	assert states["missing"].password_hash() is None
	assert str(states["missing"]) == ""

	# But we can set values later
	states["missing"] = TemplateContextConfigState(id="missing", values=[True])
	assert states["missing"]
	assert states["missing"].exists
	assert states["missing"].value is True
	assert states["missing"].password_hash() is None
	assert str(states["missing"]) == "True"


def test_TemplateContextConfigState_password_hash() -> None:
	state = TemplateContextConfigState(id="netboot.grub.password", values=["secret"])

	pw_hash_sha512 = state.password_hash("Sha512", "Shadow")
	assert pw_hash_sha512
	assert pw_hash_sha512.startswith("$6$")  # SHA-512

	# Already hashed, keep as is
	state.values = [pw_hash_sha512]
	assert pw_hash_sha512 == state.password_hash("SHA512", "shadow")

	# Different method requested
	state.values = [pw_hash_sha512.replace("$6$", "$1$")]
	with pytest.raises(ValueError, match="Password is already hashed with method 1, but SHA512 is requested"):
		state.password_hash("sha512", "shadow")

	state.values = ["secret"]
	pw_hash_grub_pbkdf2_sha512 = state.password_hash("pbkdf2-sha512", "grub")
	assert pw_hash_grub_pbkdf2_sha512
	assert pw_hash_grub_pbkdf2_sha512.startswith("grub.pbkdf2.sha512.")

	# Already hashed, keep as is
	state.values = [pw_hash_grub_pbkdf2_sha512]
	assert pw_hash_grub_pbkdf2_sha512 == state.password_hash("pbkdf2-sha512", "grub")


def test_TemplateContext_linux_cmdline() -> None:
	context = TemplateContext(depot=OpsiDepotserver(id="depot1.opsi.test"), client=OpsiClient(id="client1.opsi.test"))
	context.config_states["clientconfig.configserver.url"] = TemplateContextConfigState(
		id="clientconfig.configserver.url", values=["http://opsi.test:4447/rpc"]
	)
	context.config_states["netboot.linux-bootimage.cmdline.option1"] = TemplateContextConfigState(
		id="netboot.linux-bootimage.cmdline.option1",
		values=["", None],  # type: ignore
	)
	context.config_states["netboot.linux-bootimage.cmdline.sub1.sub2.option2"] = TemplateContextConfigState(
		id="netboot.linux-bootimage.cmdline.sub1.sub2.option2",
		values=[],
	)
	context.config_states["netboot.linux-bootimage.cmdline.option3"] = TemplateContextConfigState(
		id="netboot.linux-bootimage.cmdline.option3", values=[True]
	)
	context.config_states["netboot.linux-bootimage.cmdline.option4"] = TemplateContextConfigState(
		id="netboot.linux-bootimage.cmdline.option4", values=[False]
	)
	context.config_states["netboot.linux-bootimage.cmdline.option5"] = TemplateContextConfigState(
		id="netboot.linux-bootimage.cmdline.option5", values=["value with spaces", "value,with,commas"]
	)
	context.config_states["netboot.linux-bootimage.cmdline.sub1.option6"] = TemplateContextConfigState(
		id="netboot.linux-bootimage.cmdline.sub1.option6", values=["1", "value2"]
	)
	context.config_states["netboot.linux-bootimage.cmdline.pwh"] = TemplateContextConfigState(
		id="netboot.linux-bootimage.cmdline.pwh", values=["secret"]
	)
	context.config_states["netboot.linux-bootimage.cmdline.splash"] = TemplateContextConfigState(
		id="netboot.linux-bootimage.cmdline.splash", values=[True]
	)
	context.config_states["netboot.linux-bootimage.cmdline.quiet"] = TemplateContextConfigState(
		id="netboot.linux-bootimage.cmdline.quiet", values=[True]
	)

	assert (
		context.opsi_linux_bootimage.cmdline(config_id_prefix=None)
		== "service=http://opsi.test:4447/rpc host_id=client1.opsi.test hn=client1 dn=opsi.test"
	)
	kernel_cmdline = context.opsi_linux_bootimage.cmdline()
	kernel_cmdline = re.sub(r'pwh="\\\$6\\\$\S+', 'pwh="..."', kernel_cmdline)
	assert kernel_cmdline == (
		"quiet splash service=http://opsi.test:4447/rpc host_id=client1.opsi.test hn=client1 dn=opsi.test "
		'option3 option5="value with spaces","value,with,commas" sub1.option6=1,value2 pwh="..."'
	)

	# opsi_linux_bootimage.additional_cmdline_params override config states
	context.opsi_linux_bootimage.additional_cmdline_params = {"option1": "value1", "sub1.option6": "overridden"}
	assert (
		context.opsi_linux_bootimage.cmdline(config_id_prefix=None)
		== "service=http://opsi.test:4447/rpc host_id=client1.opsi.test hn=client1 dn=opsi.test option1=value1 sub1.option6=overridden"
	)
	kernel_cmdline = context.opsi_linux_bootimage.cmdline(config_id_prefix="netboot.linux-bootimage.cmdline")
	kernel_cmdline = re.sub(r'pwh="\\\$6\\\$\S+', 'pwh="..."', kernel_cmdline)
	assert kernel_cmdline == (
		"quiet splash service=http://opsi.test:4447/rpc host_id=client1.opsi.test hn=client1 dn=opsi.test "
		'option1=value1 option3 option5="value with spaces","value,with,commas" sub1.option6=overridden pwh="..."'
	)

	# additional_params override opsi_linux_bootimage.additional_cmdline_params and config states
	context.opsi_linux_bootimage.additional_cmdline_params = {"option1": "value1", "sub1.option6": "overridden"}
	assert (
		context.opsi_linux_bootimage.cmdline(config_id_prefix=None)
		== "service=http://opsi.test:4447/rpc host_id=client1.opsi.test hn=client1 dn=opsi.test option1=value1 sub1.option6=overridden"
	)
	kernel_cmdline = context.opsi_linux_bootimage.cmdline(
		additional_params={"option1": False, "sub1.option6": ["overridden1", "overridden2"], "hn": "overridden-host"},
		config_id_prefix="netboot.linux-bootimage.cmdline",
	)
	kernel_cmdline = re.sub(r'pwh="\\\$6\\\$\S+', 'pwh="..."', kernel_cmdline)
	assert kernel_cmdline == (
		"quiet splash service=http://opsi.test:4447/rpc host_id=client1.opsi.test hn=overridden-host dn=opsi.test "
		'option3 option5="value with spaces","value,with,commas" sub1.option6=overridden1,overridden2 pwh="..."'
	)

	# Test other prefix
	context.config_states["some.prefix.option1"] = TemplateContextConfigState(id="some.prefix.option1", values=[False])
	context.config_states["some.prefix.sub1.option2"] = TemplateContextConfigState(id="some.prefix.sub1.option2", values=["r", "f"])
	kernel_cmdline = context.opsi_linux_bootimage.cmdline(config_id_prefix="")
	assert (
		kernel_cmdline
		== "service=http://opsi.test:4447/rpc host_id=client1.opsi.test hn=client1 dn=opsi.test option1=value1 sub1.option6=overridden"
	)
	kernel_cmdline = context.opsi_linux_bootimage.cmdline(config_id_prefix="some.prefix")
	assert (
		kernel_cmdline
		== "service=http://opsi.test:4447/rpc host_id=client1.opsi.test hn=client1 dn=opsi.test option1=value1 sub1.option2=r,f sub1.option6=overridden"
	)

	# Test remove loglevel if splash is set
	context.opsi_linux_bootimage.additional_cmdline_params = {"splash": True, "loglevel": "3"}
	kernel_cmdline = context.opsi_linux_bootimage.cmdline(config_id_prefix="not.found")
	assert "splash" in kernel_cmdline
	assert "loglevel=3" not in kernel_cmdline


def test_TemplateContext_grub_menu_entries() -> None:
	context = TemplateContext(depot=OpsiDepotserver(id="depot1.opsi.test"), client=OpsiClient(id="client1.opsi.test"))
	context.config_states["netboot.grub.additional_menu_entries"] = TemplateContextConfigState(
		id="netboot.grub.additional_menu_entries",
		values=["menuentry 'Entry 1' { echo '{{client.id}}'; }", "menuentry 'Entry 2' { echo 'Entry 2'; }"],
	)
	context.grub.primary_menu_entries = [
		"menuentry 'Primary Entry' { echo '{{client.id}}'; }",
		"menuentry 'Secondary Entry' { echo 'Secondary Entry'; }",
	]
	entries = context.grub.menu_entries()
	assert len(entries) == 2
	assert entries[0] == "menuentry 'Primary Entry' { echo 'client1.opsi.test'; }"
	assert entries[1] == "menuentry 'Secondary Entry' { echo 'Secondary Entry'; }"

	entries = context.grub.menu_entries("netboot.grub.additional_menu_entries")
	assert len(entries) == 4
	assert entries[0] == "menuentry 'Primary Entry' { echo 'client1.opsi.test'; }"
	assert entries[1] == "menuentry 'Secondary Entry' { echo 'Secondary Entry'; }"
	assert entries[2] == "menuentry 'Entry 1' { echo 'client1.opsi.test'; }"
	assert entries[3] == "menuentry 'Entry 2' { echo 'Entry 2'; }"


def test_render_grub_cfg(tmp_path: Path) -> None:
	grub_cfg_template = Path("tests/data/boot/grub.cfg")
	default_product_grub_cfg_template = Path(tmp_path) / "product_grub.cfg"
	default_product_grub_cfg_template.write_text("DEFAULT_PRODUCT_GRUB_CFG_TEMPLATE", encoding="utf-8")

	pxe_config_template = dedent("""
		menuentry 'Start netboot for {{ product.name }}' {
			linux (pxe)/opsi/opsi-linux-bootimage/kernel.x64 {{ opsi_linux_bootimage.cmdline() }}
		}
	""")
	context = TemplateContext(
		depot=OpsiDepotserver(id="depot1.opsi.test"),
		client=OpsiClient(id="client1.opsi.test"),
		product=NetbootProduct(id="test_product", productVersion="1.0", packageVersion="1", name="Test Product"),
	)
	context.client = OpsiClient(id="client1.opsi.test")
	context.config_states["netboot.grub.graphicsmode"] = TemplateContextConfigState(id="netboot.grub.graphicsmode", values=[True])
	context.config_states["netboot.grub.password"] = TemplateContextConfigState(id="netboot.grub.password", values=["secret"])
	context.config_states["netboot.grub.timeout"] = TemplateContextConfigState(id="netboot.grub.timeout", values=["9"])
	context.config_states["netboot.linux-bootimage.cmdline.option1"] = TemplateContextConfigState(
		id="netboot.linux-bootimage.cmdline.option1", values=[True]
	)
	context.config_states["netboot.grub.additional_menu_entries"] = TemplateContextConfigState(
		id="netboot.grub.additional_menu_entries",
		values=[
			"menuentry 'Entry 1' { echo '{{client.id}}'; }",
			'if [ "$grub_platform" = "efi" ]; then menuentry \'efi\' { echo "efi" }; fi',
		],
	)
	context.grub.primary_menu_entries = ["menuentry 'Primary Entry' { echo '{{client.id}}'; }"]
	context.opsi_linux_bootimage.additional_cmdline_params = {"hn": "client1", "dn": "opsi.test"}

	with patch("opsiconfd.backend.rpc.boot.DEFAULT_PRODUCT_GRUB_CFG_TEMPLATE", str(default_product_grub_cfg_template)):
		recursion_pxe_config_template = "{{ product.grub_cfg() }}"
		for use_pxe_config_template in (pxe_config_template, None, "", "install3264", "install-x64", recursion_pxe_config_template):
			assert context.product
			context.product.product.pxeConfigTemplate = use_pxe_config_template

			if use_pxe_config_template == recursion_pxe_config_template:
				with pytest.raises(RuntimeError, match="Recursion detected in product specific GRUB config template"):
					Template(grub_cfg_template.read_text()).render(context.context_args())
				continue

			data = Template(grub_cfg_template.read_text()).render(context.context_args())

			assert 'echo "grub.cfg"' in data
			assert 'echo "gfxmode"' in data
			assert 'echo "password: grub.pbkdf2.sha512.10000.' in data

			if use_pxe_config_template == pxe_config_template:
				assert (
					dedent("""
					menuentry 'Start netboot for Test Product' {
						linux (pxe)/opsi/opsi-linux-bootimage/kernel.x64 host_id=client1.opsi.test hn=client1 dn=opsi.test product=test_product option1
					}
					""")
					in data
				)
				assert "DEFAULT_PRODUCT_GRUB_CFG_TEMPLATE" not in data
			else:
				assert "DEFAULT_PRODUCT_GRUB_CFG_TEMPLATE" in data

		context.config_states["netboot.grub.graphicsmode"].values = [False]
		context.product = None
		data = Template(grub_cfg_template.read_text()).render(context.context_args())
		assert 'echo "gfxmode"' not in data
		assert "set timeout=9" in data
		assert (
			dedent("""
			menuentry 'Local Disk' {
				echo "Local Disk"
			}
			""")
			in data
		)
		assert 'if [ "$grub_platform" = "efi" ]; then menuentry \'efi\' { echo "efi" }; fi' in data
		assert "menuentry 'Primary Entry' { echo 'client1.opsi.test'; }" in data
		assert "menuentry 'Entry 1' { echo 'client1.opsi.test'; }" in data
		assert "DEFAULT_PRODUCT_GRUB_CFG_TEMPLATE" not in data


def test_TemplateContext_product_property_state_cmdline(
	backend: UnprotectedBackend,  # noqa: F811
) -> None:
	client_id = "client1.opsi.test"
	product_id = "memtest86"

	def mock_productPropertyState_getValues(
		product_ids: list[str] | str | None = None,
		property_ids: list[str] | str | None = None,
		object_ids: list[str] | str | None = None,
		with_defaults: bool = True,
	) -> dict[str, dict[str, dict[str, list[Any]]]]:
		return {
			client_id: {
				product_id: {
					"nosmp": [True],
					"nobench": [False],
					"nobigstatus": [True],
					"screen.mode": ["1024 x 768"],
					"screen.rhs-up": [True],
					"screen.vhs-up": [False],
					"usbinit": [""],
					"console": [],
					"keyboard": ["legacy", "usb"],
				}
			}
		}

	with patch.object(backend, "productPropertyState_getValues", mock_productPropertyState_getValues):
		context = backend._get_boot_config_template_context(  # type: ignore[misc,call-arg]
			depot=OpsiDepotserver(id="depot1.opsi.test"),
			client=OpsiClient(id=client_id),
			product=NetbootProduct(id=product_id, productVersion="7.20", packageVersion="1", name="Memtest86+"),
		)

		assert context.product_property_states
		assert context.product_property_states.cmdline() == 'nosmp nobigstatus screen.mode="1024 x 768" screen.rhs-up keyboard=legacy,usb'
		assert context.product_property_states.cmdline(["nosmp", "nobench", "screen.mode"]) == 'nosmp screen.mode="1024 x 768"'
		assert context.product_property_states.cmdline(["*smp", "nobench", "screen.*"]) == 'nosmp screen.mode="1024 x 768" screen.rhs-up'
		assert context.product_property_states.cmdline("screen.*") == 'screen.mode="1024 x 768" screen.rhs-up'
		assert context.product_property_states.cmdline("screen.*", "screen.") == 'mode="1024 x 768" rhs-up'


def test_boot_getConfig(
	backend: UnprotectedBackend,  # noqa: F811
	tmp_path: Path,
) -> None:
	product_id = "test-boot-product1"
	client_id = "test-boot-client1.opsi.test"
	depot_id = get_depotserver_id()

	grub_cfg = tmp_path / "grub.cfg"
	Path("tests/data/boot/grub.cfg").copy(grub_cfg)

	backend.config_createObjects(
		[
			UnicodeConfig(
				id="clientconfig.configserver.url",
				description="URL(s) of OPSI config service(s) to use",
				possibleValues=["https://opsiservice.opsi.test:4447/rpc"],
				defaultValues=["https://opsiservice.opsi.test:4447/rpc"],
				editable=True,
				multiValue=True,
			),
			BoolConfig(
				id="netboot.use_host_onetime_password",
				description="Use a one-time password for host authentication?",
				defaultValues=[False],
			),
		]
	)

	client = OpsiClient(
		id=client_id,
		opsiHostKey="fe5e2020410d947c58508cdcd29d9ec0",
		hardwareAddress="01:02:03:04:05:06",
		systemUUID="6a6fa111-a6a6-42da-bb96-f1401ab95a06",
	)
	product = NetbootProduct(
		id=product_id,
		productVersion="1",
		packageVersion="1",
		pxeConfigTemplate=(
			"menuentry 'Start netboot installation' --class netboot --unrestricted {\n"
			"	linux opsi-linux-bootimage/kernel.x64 {{ opsi_linux_bootimage.cmdline() }}\n"
			"	initrd opsi-linux-bootimage/initramfs.x64\n"
			"}\n"
		),
	)
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
	backend.configState_create(configId="clientconfig.depot.id", objectId=client_id, values=[depot_id])
	backend.configState_create(configId="clientconfig.depot.id", objectId=client_id, values=[depot_id])

	boot_server_address = "10.10.1.1"
	for use_product_on_client in (False, True):
		if use_product_on_client:
			backend.productOnClient_createObjects([product_on_client])
		else:
			backend.productOnClient_deleteObjects([product_on_client])
		for host_identifiers in (["system_uuid", "mac_address"], ["mac_address"], ["system_uuid"], []):
			backend.config_createObjects(
				[
					UnicodeConfig(
						id="netboot.host_identifiers",
						description="Defines the identifiers used for host recognition on the boot server.",
						possibleValues=["system_uuid", "mac_address"],
						defaultValues=host_identifiers,
						editable=False,
						multiValue=True,
					)
				]
			)
			for use_host_onetime_password in (False, True):
				backend.configState_create(
					configId="netboot.use_host_onetime_password", objectId=client_id, values=[use_host_onetime_password]
				)
				for client_args in (
					{"client_id": client_id},
					{"system_uuid": client.systemUUID},
					{"hardware_address": client.hardwareAddress},
				):
					for architecture in ("x86", "x64", "arm64"):
						for firmware_type in ("UEFI", "BIOS"):
							for protocol in ("TFTP", "HTTP"):
								print(
									f"use_product_on_client={use_product_on_client}, host_identifiers={host_identifiers}, client_args={client_args}, "
									f"architecture={architecture}, firmware_type={firmware_type}, protocol={protocol}"
								)
								with mock.patch("opsiconfd.backend.rpc.boot.GRUB_CFG_TEMPLATE", str(grub_cfg)):
									boot_config: BootConfig = backend.boot_getConfig(
										ip_version=4,
										architecture=architecture,
										firmware_type=firmware_type,
										protocol=protocol,
										boot_server_address=boot_server_address,
										**client_args,
									)

								# print(boot_config.pxe_boot_server)
								# print(boot_config.pxe_boot_filename)
								# print(boot_config.grub_config)

								assert boot_config.depot_id == depot_id
								assert boot_config.pxe_boot_server == boot_server_address
								assert boot_config.pxe_boot_filename
								assert boot_config.grub_config

								if firmware_type == "UEFI":
									assert boot_config.pxe_boot_filename.endswith(f"/grub-shim.{architecture}.efi")
								else:
									assert boot_config.pxe_boot_filename.endswith(f"/grub.{architecture}.bios")
								if protocol == "TFTP":
									boot_config.pxe_boot_filename.startswith("/opsi/")
								else:
									boot_config.pxe_boot_filename.startswith(f"http://{boot_server_address}:4442/boot/opsi/")

								assert f"depot_id: {depot_id}" in boot_config.grub_config
								if (
									"client_id" in client_args
									or ("hardware_address" in client_args and ("mac_address" in host_identifiers or not host_identifiers))
									or ("system_uuid" in client_args and ("system_uuid" in host_identifiers or not host_identifiers))
								):
									assert boot_config.client_id == client_id
									assert f"client_id: {client_id}" in boot_config.grub_config

									match = re.search(r"linux opsi-linux-bootimage/kernel.x64 (.+)", boot_config.grub_config)
									if use_product_on_client:
										assert match
										cmdline = {
											p.split("=")[0].lower(): p.split("=")[1] if "=" in p else None for p in match.group(1).split()
										}
										assert cmdline.get("hn") == client_id.split(".")[0]
										assert cmdline.get("dn") == ".".join(client_id.split(".")[1:])
										assert cmdline.get("product") == product_id
										if use_host_onetime_password:
											assert len(str(cmdline["otp"])) == 32
											assert "pckey" not in cmdline
										else:
											assert "otp" not in cmdline
											assert cmdline.get("pckey") == client.opsiHostKey
									else:
										assert match is None
								else:
									assert boot_config.client_id is None
									assert client_id not in boot_config.grub_config
