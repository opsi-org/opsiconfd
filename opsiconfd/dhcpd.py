# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
dhcpd
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from subprocess import CalledProcessError, run
from time import sleep, time
from typing import Generator, Literal

from opsicommon.types import (
	forceBool,
	forceDict,
	forceHardwareAddress,
	forceHostname,
	forceIPAddress,
	forceStringLower,
)
from opsicommon.utils import ip_address_in_network

from opsiconfd.backend.rpc import read_backend_config_file
from opsiconfd.config import OPSICONFD_DIR, config, opsi_config
from opsiconfd.logging import logger
from opsiconfd.utils import get_ip_addresses, lock_file


@contextmanager
def dhcpd_lock(lock_type: str = "") -> Generator[None, None, None]:
	dhcpd_lock_file = Path(OPSICONFD_DIR) / ".opsi-dhcpd-lock"
	with open(dhcpd_lock_file, "a+", encoding="utf8") as lock_fh:
		try:
			os.chmod(dhcpd_lock_file, 0o666)
		except PermissionError:
			pass
		with lock_file(lock_fh, timeout=10.0):
			lock_fh.seek(0)
			lines = lock_fh.readlines()
			if len(lines) >= 100:
				lines = lines[-100:]
			lines.append(f"{time()};{os.getpid()};{lock_type}\n")
			lock_fh.seek(0)
			lock_fh.truncate()
			lock_fh.writelines(lines)
			lock_fh.flush()
			yield None
			if lock_type == "config_reload":
				sleep(4.0)
	# os.remove(dhcpd_lock_file)


class DHCPDConfComponent:
	def __init__(self, start_line: int, parent_block: DHCPDConfBlock | None) -> None:
		self.start_line = start_line
		self.end_line = start_line
		self.parent_block = parent_block

	def get_shifting(self) -> str:
		shifting = ""
		if not self.parent_block:
			return shifting
		parent_block = self.parent_block.parent_block
		while parent_block:
			shifting += "\t"
			parent_block = parent_block.parent_block
		return shifting

	def as_text(self) -> str:
		return self.get_shifting()

	def __str__(self) -> str:
		return f"<{self.__class__.__name__}({self.start_line}, {self.end_line})>"

	__repr__ = __str__


class DHCPDConfParameter(DHCPDConfComponent):
	def __init__(self, start_line: int, parent_block: DHCPDConfBlock | None, key: str, value: str | bool) -> None:
		super().__init__(start_line, parent_block)
		self.key = key
		self.value = value
		if isinstance(self.value, str):
			if self.value.lower() in ("yes", "true", "on"):
				self.value = True
			elif self.value.lower() in ("no", "false", "off"):
				self.value = False

	def as_text(self) -> str:
		value = self.value
		if isinstance(value, bool):
			value = "on" if value else "off"
		elif (
			self.key in ("filename", "file_path", "ddns-domainname")
			or re.match(r".*['/\\].*", value)
			or re.match(r"^\w+\.\w+$", value)
			or self.key.endswith("-name")
		):
			value = f'"{value}"'
		return f"{self.get_shifting()}{self.key} {value};"

	def as_hash(self) -> dict[str, str | bool]:
		return {self.key: self.value}


class DHCPDConfOption(DHCPDConfComponent):
	quoted_options = (
		"-name",
		"-domain",
		"-identifier",
		"-search",
		"merit-dump",
		"nds-context",
		"netbios-scope",
		"nwip-domain",
		"nwip-suboptions",
		"nis-domain",
		"nisplus-domain",
		"root-path",
		"uap-servers",
		"user-class",
		"vendor-encapsulated-options",
		"circuit-id",
		"remote-id",
		"fqdn.fqdn",
		"ddns-rev-domainname",
	)

	def __init__(self, start_line: int, parent_block: DHCPDConfBlock | None, key: str, value: list[str] | str) -> None:
		super().__init__(start_line, parent_block)
		self.key = key
		if not isinstance(value, list):
			value = [value]
		self.value = value

	def as_text(self) -> str:
		text = []
		for value in self.value:
			if re.match(r".*['/\\].*", value) or re.match(r"^\w+\.\w+$", value) or self.key.endswith(self.quoted_options):
				text.append(f'"{value}"')
			else:
				text.append(value)
		return f"{self.get_shifting()}option {self.key} {', '.join(text)};"

	def as_hash(self) -> dict[str, list[str]]:
		return {self.key: self.value}


class DHCPDConfComment(DHCPDConfComponent):
	def __init__(self, start_line: int, parent_block: DHCPDConfBlock | None, data: str) -> None:
		super().__init__(start_line, parent_block)
		self._data = data

	def as_text(self) -> str:
		return f"{self.get_shifting()}#{self._data}"


class DHCPDConfEmptyLine(DHCPDConfComponent):
	pass


class DHCPDConfBlock(DHCPDConfComponent):
	def __init__(
		self,
		start_line: int,
		parent_block: DHCPDConfBlock | None,
		type: str,  # pylint: disable=redefined-builtin
		settings: list[str] | None = None,
	):
		super().__init__(start_line, parent_block)
		self.type = type
		self.settings = settings or []
		self.line_refs: dict[int, list[DHCPDConfComponent]] = {}
		self.components: list[DHCPDConfComponent] = []

	def get_components(self) -> list[DHCPDConfComponent]:
		return self.components

	def remove_components(self) -> None:
		logger.debug("Removing components: %s", self.components)
		for comp in self.components:
			self.remove_component(comp)

	def add_component(self, component: DHCPDConfComponent) -> None:
		self.components.append(component)
		if component.start_line not in self.line_refs:
			self.line_refs[component.start_line] = []
		self.line_refs[component.start_line].append(component)

	def remove_component(self, component: DHCPDConfComponent) -> None:
		self.components.remove(component)

		if component.start_line in self.line_refs:
			try:
				self.line_refs[component.start_line].remove(component)
			except ValueError:
				pass

	def get_options_hash(self, inherit: str | None = None) -> dict[str, str | list[str]]:
		options: dict[str, str | list[str]] = {}
		for component in self.components:
			if not isinstance(component, DHCPDConfOption):
				continue
			options[component.key] = component.value

		if inherit and self.type != inherit and self.parent_block:
			for key, value in self.parent_block.get_options_hash(inherit).items():
				if key not in options:
					options[key] = value

		return options

	def get_options(self, inherit: str | None = None) -> list[DHCPDConfOption]:
		options = []
		for component in self.components:
			if not isinstance(component, DHCPDConfOption):
				continue
			options.append(component)

		if inherit and self.type != inherit and self.parent_block:
			options.extend(self.parent_block.get_options(inherit))

		return options

	def get_parameters_hash(self, inherit: str | None = None) -> dict[str, str | bool]:
		parameters = {}
		for component in self.components:
			if not isinstance(component, DHCPDConfParameter):
				continue
			parameters[component.key] = component.value

		if inherit and self.type != inherit and self.parent_block:
			for (key, value) in self.parent_block.get_parameters_hash(inherit).items():
				if key not in parameters:
					parameters[key] = value
		return parameters

	def get_parameters(self, inherit: str | None = None) -> list[str]:
		parameters = []

		if inherit and self.type != inherit and self.parent_block:
			parameters.extend(self.parent_block.get_parameters(inherit))

		return parameters

	def get_blocks(self, type: str | None = None, recursive: bool = False) -> list[DHCPDConfBlock]:  # pylint: disable=redefined-builtin
		blocks = []
		for component in self.components:
			if not isinstance(component, DHCPDConfBlock):
				continue
			if not type or component.type == type:
				blocks.append(component)
			if recursive:
				blocks.extend(component.get_blocks(type, recursive))
		return blocks

	def as_text(self) -> str:
		text = ""
		shifting = self.get_shifting()
		if not isinstance(self, DHCPDConfGlobalBlock):
			text = f"{shifting}{' '.join(self.settings)} {{\n"

		not_written = self.components
		line_number = max(self.start_line, 1)

		while line_number <= self.end_line:
			if line_number not in self.line_refs or not self.line_refs[line_number]:
				line_number += 1
				continue

			for idx, line_ref in enumerate(self.line_refs[line_number]):
				comp_text = line_ref.as_text()
				if idx > 0 and isinstance(line_ref, DHCPDConfComment):
					comp_text = f" {comp_text.lstrip()}"
				text += comp_text
				# Mark component as written
				if line_ref in not_written:
					not_written.remove(line_ref)
			text += "\n"
			line_number += 1

		for component in not_written:
			text += component.as_text() + "\n"

		if not isinstance(self, DHCPDConfGlobalBlock):
			# Write '}' to close block
			text += shifting + "}"

		return text

	def __str__(self) -> str:
		return f"<{self.__class__.__name__}({self.type}, {self.start_line}, {self.end_line})>"


class DHCPDConfGlobalBlock(DHCPDConfBlock):
	def __init__(self) -> None:
		super().__init__(1, None, "global")


class DHCPDConfFile:  # pylint: disable=too-many-instance-attributes
	def __init__(self, file_path: str | Path, lock_timeout: float = 2.0) -> None:
		self.file_path = Path(file_path)
		self._lock_timeout = lock_timeout
		self._lines: list[str] = []
		self._current_line = 0
		self._current_token: str | None = None
		self._current_index = -1
		self._data = ""
		self._global_block: DHCPDConfBlock = DHCPDConfGlobalBlock()
		self._current_block: DHCPDConfBlock = self._global_block
		self._parsed = False

		logger.debug("Parsing dhcpd conf file '%s'", self.file_path)

	def get_global_block(self) -> DHCPDConfBlock:
		return self._global_block

	def parse(self) -> None:  # pylint: disable=too-many-branches
		self._current_line = 0
		self._current_token = None
		self._current_index = -1
		self._data = ""
		self._parsed = False

		with open(self.file_path, "r", encoding="utf-8") as file:
			with lock_file(file, timeout=self._lock_timeout):
				self._lines = file.readlines()

		self._current_block = self._global_block = DHCPDConfGlobalBlock()
		self._global_block.end_line = len(self._lines)

		min_index = 0
		while True:
			self._current_token = None
			self._current_index = -1
			if not self._data.strip():
				if not self._get_new_data():
					break
				if not self._data.strip():
					self._parse_emptyline()
				continue

			for token in ("#", ";", "}", "{"):
				index = self._data.find(token)
				if (index != -1) and (index >= min_index) and ((self._current_index == -1) or (index < self._current_index)):
					if (self._data[:index].count('"') % 2 == 1) or (self._data[:index].count("'") % 2 == 1):
						continue
					self._current_token = token
					self._current_index = index
					break

			if not self._current_token:
				min_index = len(self._data)
				if not self._get_new_data():
					break
				continue

			min_index = 0
			if self._current_token == "#":
				self._parse_comment()
			elif self._current_token == ";":
				self._parse_semicolon()
			elif self._current_token == "}":
				self._parse_rbracket()
			elif self._current_token == "{":
				self._parse_lbracket()

		self._parsed = True

	def _assert_parsed(self) -> None:
		if self._parsed:
			return
		self.parse()

	def generate(self) -> None:
		with open(self.file_path, "r+", encoding="utf-8") as file:
			with lock_file(file, timeout=self._lock_timeout):
				file.seek(0)
				file.truncate()
				file.write(self._global_block.as_text())

	def add_host(  # pylint: disable=too-many-branches,too-many-locals,too-many-arguments
		self, hostname: str, hardware_address: str, ip_address: str, fixed_address: str, parameters: dict[str, str | bool] | None = None
	) -> None:
		self._assert_parsed()
		hostname = forceHostname(hostname)
		hardware_address = forceHardwareAddress(hardware_address)
		ip_address = forceIPAddress(ip_address)
		fixed_address = forceStringLower(fixed_address)
		parameters = forceDict(parameters or {})

		existing_host = None
		for block in self._global_block.get_blocks("host", recursive=True):
			if block.settings[1].lower() == hostname:
				existing_host = block
			else:
				for (key, value) in block.get_parameters_hash().items():
					if key == "fixed-address" and str(value).lower() == fixed_address:
						raise ValueError(f"Host '{block.settings[1]}' uses the same fixed address")
					if key == "hardware" and str(value).lower() == f"ethernet {hardware_address}":
						raise ValueError(f"Host '{block.settings[1]}' uses the same hardware ethernet address")

		if existing_host:
			logger.info("Host '%s' already exists in config file '%s', deleting first", hostname, self.file_path)
			self.delete_host(hostname)

		logger.notice(
			"Creating host '%s', hardware_address '%s', ip_address '%s', fixed_address '%s', parameters '%s' in dhcpd config file '%s'",
			hostname,
			hardware_address,
			ip_address,
			fixed_address,
			parameters,
			self.file_path,
		)

		for (key, value) in parameters.items():
			parameters[key] = DHCPDConfParameter(-1, None, key, value).as_hash()[key]

		# Default parent block is global
		parent_block: DHCPDConfBlock = self._global_block

		# Search the right subnet block
		for block in self._global_block.get_blocks("subnet", recursive=True):
			if ip_address_in_network(ip_address, f"{block.settings[1]}/{block.settings[3]}"):
				logger.debug("Choosing subnet %s/%s for host %s", block.settings[1], block.settings[3], hostname)
				parent_block = block

		# Search the right group for the host
		best_group = None
		best_match_count = 0
		for block in parent_block.get_blocks("group"):
			match_count = 0
			block_parameters = block.get_parameters_hash(inherit="global")
			if block_parameters:
				# Block has parameters set, check if they match the hosts parameters
				for (key, value) in block_parameters.items():
					if key not in parameters:
						continue

					if parameters[key] == value:
						match_count += 1
					else:
						match_count -= 1

			if match_count > best_match_count or match_count >= 0 and not best_group:
				match_count = best_match_count
				best_group = block

		if best_group:
			parent_block = best_group

		# Remove parameters which are already defined in parents
		block_parameters = parent_block.get_parameters_hash(inherit="global")
		if block_parameters:
			for (key, value) in block_parameters.items():
				if key in parameters and parameters[key] == value:
					del parameters[key]

		host_block = DHCPDConfBlock(start_line=-1, parent_block=parent_block, type="host", settings=["host", hostname])
		host_block.add_component(DHCPDConfParameter(start_line=-1, parent_block=host_block, key="fixed-address", value=fixed_address))
		host_block.add_component(
			DHCPDConfParameter(start_line=-1, parent_block=host_block, key="hardware", value=f"ethernet {hardware_address}")
		)
		for key, value in parameters.items():
			host_block.add_component(DHCPDConfParameter(start_line=-1, parent_block=host_block, key=key, value=value))

		parent_block.add_component(host_block)

	def get_host(self, hostname: str) -> dict[str, str | bool] | None:
		self._assert_parsed()
		hostname = forceHostname(hostname)

		for block in self._global_block.get_blocks("host", recursive=True):
			if block.settings[1] == hostname:
				return block.get_parameters_hash()
		return None

	def delete_host(self, hostname: str) -> None:
		self._assert_parsed()
		hostname = forceHostname(hostname)

		logger.notice("Deleting host '%s' from dhcpd config file '%s'", hostname, self.file_path)
		host_blocks = []
		for block in self._global_block.get_blocks("host", recursive=True):
			if block.settings[1] == hostname:
				host_blocks.append(block)
			else:
				for (key, value) in block.get_parameters_hash().items():
					if key == "fixed-address" and value == hostname:
						host_blocks.append(block)

		if not host_blocks:
			logger.warning("Failed to remove host '%s': not found", hostname)
			return

		for block in host_blocks:
			if block.parent_block:
				block.parent_block.remove_component(block)

	def modify_host(self, hostname: str, parameters: dict[str, str | bool]) -> None:
		self._assert_parsed()
		hostname = forceHostname(hostname)
		parameters = forceDict(parameters)

		logger.notice("Modifying host '%s' in dhcpd config file '%s'", hostname, self.file_path)

		host_blocks: list[DHCPDConfBlock] = []
		for block in self._global_block.get_blocks("host", recursive=True):
			if block.settings[1] == hostname:
				host_blocks.append(block)
			else:
				for (key, value) in block.get_parameters_hash().items():
					if key == "fixed-address" and value == hostname:
						host_blocks.append(block)
					elif key == "hardware" and str(value).lower() == parameters.get("hardware"):
						raise ValueError(f"Host '{block.settings[1]}' uses the same hardware ethernet address")

		if len(host_blocks) != 1:
			raise ValueError(f"Host '{hostname}' found {len(host_blocks)} times")

		host_block = host_blocks[0]
		assert host_block.parent_block
		host_block.remove_components()

		for (key, value) in parameters.items():
			parameters[key] = DHCPDConfParameter(-1, None, key, value).as_hash()[key]

		for key, value in host_block.parent_block.get_parameters_hash(inherit="global").items():
			if key not in parameters:
				continue

			if parameters[key] == value:
				del parameters[key]

		for (key, value) in parameters.items():
			host_block.add_component(DHCPDConfParameter(start_line=-1, parent_block=host_block, key=key, value=value))

	def _get_new_data(self) -> bool:
		if self._current_line >= len(self._lines):
			return False
		self._data += self._lines[self._current_line]
		self._current_line += 1
		return True

	def _parse_emptyline(self) -> None:
		logger.trace("_parse_emptyline")
		self._current_block.add_component(DHCPDConfEmptyLine(start_line=self._current_line, parent_block=self._current_block))
		self._data = self._data[: self._current_index]

	def _parse_comment(self) -> None:
		logger.trace("_parse_comment")
		self._current_block.add_component(
			DHCPDConfComment(start_line=self._current_line, parent_block=self._current_block, data=self._data.strip()[1:])
		)
		self._data = self._data[: self._current_index]

	def _parse_semicolon(self) -> None:  # pylint: disable=too-many-branches
		logger.trace("_parse_semicolon")
		data = self._data[: self._current_index]
		self._data = self._data[self._current_index + 1 :]

		splitted_data = data.split()
		key = splitted_data[0]
		if key != "option":
			# Parameter
			value = " ".join(data.split()[1:]).strip()
			if len(value) > 1 and value.startswith('"') and value.endswith('"'):
				value = value[1:-1]

			self._current_block.add_component(
				DHCPDConfParameter(start_line=self._current_line, parent_block=self._current_block, key=key, value=value)
			)
			return

		# Option
		key = splitted_data[1]
		value = " ".join(splitted_data[2:]).strip()
		values = []
		quote = ""
		current = []
		for val in value:
			if val == '"':
				if quote == '"':
					quote = ""
				elif quote == "'":
					current.append(val)
				else:
					quote = '"'
			elif val == "'":
				if quote == "'":
					quote = ""
				elif quote == '"':
					current.append(val)
				else:
					quote = "'"
			elif re.search(r"\s", val):
				current.append(val)
			elif val == ",":
				if quote:
					current.append(val)
				else:
					values.append("".join(current).strip())
					current = []
			else:
				current.append(val)

		if current:
			values.append("".join(current).strip())

		self._current_block.add_component(
			DHCPDConfOption(start_line=self._current_line, parent_block=self._current_block, key=key, value=values)
		)

	def _parse_lbracket(self) -> None:
		logger.trace("_parse_lbracket")
		# Start of a block
		data = self._data[: self._current_index]
		self._data = self._data[self._current_index + 1 :]
		# Split the block definition at whitespace
		# The first value is the block type
		# Example: subnet 194.31.185.0 netmask 255.255.255.0 => type is subnet
		splitted_data = data.split()
		block = DHCPDConfBlock(
			start_line=self._current_line, parent_block=self._current_block, type=splitted_data[0].strip(), settings=splitted_data
		)
		self._current_block.add_component(block)
		self._current_block = block

	def _parse_rbracket(self) -> None:
		logger.trace("_parse_rbracket")
		# End of a block
		self._data = self._data[self._current_index + 1 :]
		self._current_block.end_line = self._current_line
		assert self._current_block.parent_block
		self._current_block = self._current_block.parent_block


def get_dhcpd_conf_location() -> Path:
	for filename in (
		"/etc/dhcpd.conf",  # suse / redhat / centos
		"/etc/dhcp/dhcpd.conf",  # newer debian / ubuntu
		"/etc/dhcp3/dhcpd.conf",  # older debian / ubuntu
	):
		file_path = Path(filename)
		if file_path.exists():
			return file_path
	return Path("/etc/dhcp/dhcpd.conf")


@lru_cache
def get_dhcpd_service_name() -> str:
	try:
		possible_names = ("dhcpd", "isc-dhcp-server", "dhcp3-server", "univention-dhcp")
		pattern = re.compile(r"^\s*([a-z\-]+)\@?\.service\s+(\S+)\s+")
		for line in run(
			["systemctl", "list-unit-files"], shell=False, text=True, encoding="utf-8", check=True, capture_output=True
		).stdout.split("\n"):
			match = pattern.match(line)
			if match and match.group(1) in possible_names and match.group(2) not in ("masked", "disabled"):
				return match.group(1)
	except (FileNotFoundError, PermissionError, CalledProcessError) as err:
		logger.info("Failed to get dhcpd service name: %s", err)

	return "dhcpd"


def get_dhcpd_restart_command() -> list[str]:
	return ["sudo", "systemctl", "restart", get_dhcpd_service_name()]


def setup_dhcpd() -> None:  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
	logger.info("Setup DHCPD")
	dhcpd_control_config = get_dhcpd_control_config()
	if not dhcpd_control_config.enabled:
		return

	local_addr = None
	for addr in get_ip_addresses():
		if addr["family"] == "ipv4" and addr["interface"] != "lo":
			local_addr = addr

	if not local_addr:
		raise RuntimeError("Failed to get local ip address")

	dhcpd_control_config.dhcpd_config_file.parse()
	global_block = dhcpd_control_config.dhcpd_config_file.get_global_block()

	conf_changed = False
	if not global_block.get_parameters_hash().get("use-host-decl-names", False):
		logger.notice("Enabling use-host-decl-names")
		global_block.add_component(DHCPDConfParameter(start_line=-1, parent_block=global_block, key="use-host-decl-names", value=True))
		conf_changed = True

	subnets = global_block.get_blocks("subnet", recursive=True)
	if not subnets:
		logger.notice("No subnets found, adding subnet")
		global_block.add_component(
			DHCPDConfBlock(
				start_line=-1,
				parent_block=global_block,
				type="subnet",
				settings=["subnet", local_addr["network"].split("/")[0], "netmask", local_addr["netmask"]],
			)
		)
		conf_changed = True

	for subnet in global_block.get_blocks("subnet", recursive=True):  # pylint: disable=too-many-nested-blocks
		logger.info("Found subnet %s/%s", subnet.settings[1], subnet.settings[3])
		groups = subnet.get_blocks("group")
		if not groups:
			logger.notice("No groups found, adding group")
			subnet.add_component(DHCPDConfBlock(start_line=-1, parent_block=subnet, type="group", settings=["group"]))
			conf_changed = True

		for group in subnet.get_blocks("group"):
			logger.info("Configuring group")
			params = group.get_parameters_hash(inherit="global")

			if not params.get("next-server"):
				group.add_component(DHCPDConfParameter(start_line=-1, parent_block=group, key="next-server", value=local_addr["address"]))
				logger.info("next-server set to %s", local_addr["address"])
				conf_changed = True

			if_found = False
			for comp in group.get_components():
				if isinstance(comp, DHCPDConfBlock):
					settings_str = ("".join(comp.settings)).lower()
					if comp.type == "if":
						if_found = True

					filename = ""
					if settings_str.endswith('ifsubstring(optionvendor-class-identifier,19,1)="0"'):
						filename = dhcpd_control_config.boot_filename_bios
					elif settings_str.endswith('ifsubstring(optionvendor-class-identifier,19,1)="7"'):
						filename = dhcpd_control_config.boot_filename_uefi
					if not filename:
						continue
					for sub_comp in comp.get_components():
						if isinstance(sub_comp, DHCPDConfParameter) and sub_comp.key == "filename" and sub_comp.value != filename:
							sub_comp.value = filename
							conf_changed = True

			if not if_found:
				conf_changed = True
				blk = DHCPDConfBlock(
					start_line=-1,
					parent_block=group,
					type="if",
					settings=["if", "substring", "(option", "vendor-class-identifier,", "19,", "1)", "=", '"0"'],
				)
				blk.add_component(
					DHCPDConfParameter(start_line=-1, parent_block=blk, key="filename", value=dhcpd_control_config.boot_filename_bios)
				)
				group.add_component(blk)

				blk = DHCPDConfBlock(
					start_line=-1,
					parent_block=group,
					type="else",
					settings=["else", "if", "substring", "(option", "vendor-class-identifier,", "19,", "1)", "=", '"7"'],
				)
				blk.add_component(
					DHCPDConfParameter(start_line=-1, parent_block=blk, key="filename", value=dhcpd_control_config.boot_filename_uefi)
				)
				group.add_component(blk)

	if conf_changed:
		logger.info("Writing new %s", dhcpd_control_config.dhcpd_config_file)
		dhcpd_control_config.dhcpd_config_file.generate()

	shutil.chown(dhcpd_control_config.dhcpd_config_file.file_path, group=opsi_config.get("groups", "admingroup"))
	os.chmod(dhcpd_control_config.dhcpd_config_file.file_path, 0o664)

	if conf_changed:
		if dhcpd_control_config.reload_config_command:
			logger.info("Restarting DHCPD")
			try:
				run(dhcpd_control_config.reload_config_command, shell=False, check=True)
			except (FileNotFoundError, CalledProcessError) as err:
				logger.warning(err)
		else:
			logger.info("DHCPD config changed, but no reload command configured")


@dataclass(slots=True, kw_only=True)
class DHCPDControlConfig:  # pylint: disable=too-many-instance-attributes
	enabled: bool
	dhcpd_on_depot: bool
	dhcpd_config_file: DHCPDConfFile
	reload_config_command: list[str]
	fixed_address_format: Literal["IP", "FQDN"]
	default_client_parameters: dict[str, str]
	boot_filename_uefi: str
	boot_filename_bios: str


@lru_cache
def get_dhcpd_control_config() -> DHCPDControlConfig:
	local_addr = None
	for addr in get_ip_addresses():
		if addr["family"] == "ipv4" and addr["interface"] != "lo":
			local_addr = addr
	next_server = local_addr["address"] if local_addr else "127.0.0.1"

	db_config = DHCPDControlConfig(
		enabled=False,
		dhcpd_on_depot=False,
		dhcpd_config_file=DHCPDConfFile(get_dhcpd_conf_location()),
		reload_config_command=get_dhcpd_restart_command(),
		fixed_address_format="IP",
		default_client_parameters={"next-server": next_server},
		boot_filename_uefi="opsi/opsi-linux-bootimage/loader/opsi-netboot.efi",
		boot_filename_bios="opsi/opsi-linux-bootimage/loader/opsi-netboot.bios",
	)

	dhcpd_control_conf = Path(config.backend_config_dir) / "dhcpd.conf"
	if not dhcpd_control_conf.exists():
		logger.error("Config file '%s' not found, DHCPD control disabled", dhcpd_control_conf)
		return db_config

	for key, val in read_backend_config_file(dhcpd_control_conf).items():
		attr = "".join([f"_{c.lower()}" if c.isupper() else c for c in key])
		if not hasattr(db_config, attr):
			logger.error("Invalid config key %s in %s", attr, dhcpd_control_conf)
			continue

		if attr == "fixed_address_format":
			if val not in ("IP", "FQDN"):
				logger.error("Bad value %r for fixedAddressFormat, possible values are IP and FQDN", val)
				continue
		elif attr in ("dhcpd_on_depot", "enabled"):
			val = forceBool(val)
		elif attr == "dhcpd_config_file":
			val = DHCPDConfFile(val)
		elif attr == "reload_config_command":
			if not isinstance(val, list):
				val = shlex.split(val)

		setattr(db_config, attr, val)

	if db_config.enabled and not db_config.dhcpd_config_file.file_path.exists():
		logger.error(
			"DHCPD config file '%s' not found, DHCPD control disabled. "
			"DHCPD control can be disabled permanently by setting 'enabled' to False in '%s'",
			db_config.dhcpd_config_file.file_path,
			dhcpd_control_conf,
		)
		db_config.enabled = False

	logger.info("DHCPD control config: %s", db_config)
	return db_config
