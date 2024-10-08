# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
auth
"""

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

from opsiconfd.config import opsi_config
from opsiconfd.logging import logger


@dataclass(frozen=True, kw_only=True)
class RPCACE:
	"""RPC Access Control Entry"""

	method_re: re.Pattern
	type: Literal["all", "self", "opsi_depotserver", "opsi_client", "sys_group", "sys_user"]
	id: Optional[str] = None
	allowed_attributes: set[str] = field(default_factory=set)
	denied_attributes: set[str] = field(default_factory=set)


RPCACE_ALLOW_ALL = RPCACE(method_re=re.compile(".*"), type="all")


def read_acl_file(acl_file: Path | str) -> list[RPCACE]:
	acl = []
	# acl example:
	#    <method>: <aclType>[(aclTypeParam[(aclTypeParamValue,...)];...)]
	#    xyz_.*:   opsi_depotserver(attributes(id,name))
	#    abc:      self(attributes(!opsiHostKey));sys_group(admin, group 2, attributes(!opsiHostKey))
	acl_entry_regex = re.compile(r"^([^:]+)+\s*:\s*(\S.*)$")
	if not isinstance(acl_file, Path):
		acl_file = Path(acl_file)

	for idx, line in enumerate(acl_file.read_text(encoding="utf-8").split("\n")):
		position_text = f"at line {idx + 1} in acl file '{acl_file}'"
		line = line.strip()
		if not line or line.startswith("#"):
			continue
		match = acl_entry_regex.search(line)
		if not match:
			raise ValueError(f"Bad formatted line '{line}' {position_text}")
		method_re = re.compile(match.group(1).strip())
		for entry in match.group(2).split(";"):
			entry = str(entry).strip()
			ace_type = entry
			ace_type_params = ""
			if entry.find("(") != -1:
				(ace_type, ace_type_params) = entry.split("(", 1)
				if ace_type_params[-1] != ")":
					raise ValueError(f"Bad formatted acl entry '{entry}': trailing ')' missing {position_text}")
				ace_type = ace_type.strip()
				ace_type_params = ace_type_params[:-1]

			if not ace_type:
				# Ignore empty string
				continue
			if ace_type not in ("all", "self", "opsi_depotserver", "opsi_client", "sys_group", "sys_user"):
				raise ValueError(f"Unhandled acl type: '{ace_type}' {position_text}")

			ace = RPCACE(method_re=method_re, type=ace_type)  # type: ignore[arg-type]
			if not ace_type_params:
				if ace_type in ("sys_group", "sys_user"):
					raise ValueError(f"Bad formatted acl type '{ace_type}': no params given {position_text}")
				acl.append(ace)
				continue

			ace_type_param = ""
			ace_type_param_values = [""]
			in_ace_type_param_values = False
			ids = []
			for idx, char in enumerate(ace_type_params):
				if char == "(":
					if in_ace_type_param_values:
						raise ValueError(f"Bad formatted acl type params '{ace_type_params}' {position_text}")
					in_ace_type_param_values = True
				elif char == ")":
					if not in_ace_type_param_values or not ace_type_param:
						raise ValueError(f"Bad formatted acl type params '{ace_type_params}' {position_text}")
					in_ace_type_param_values = False
				elif char != "," or idx == len(ace_type_params) - 1:
					if in_ace_type_param_values:
						ace_type_param_values[-1] += char
					else:
						ace_type_param += char

				if char == "," or idx == len(ace_type_params) - 1:
					if in_ace_type_param_values:
						if idx == len(ace_type_params) - 1:
							raise ValueError(f"Bad formatted acl type params '{ace_type_params}' {position_text}")
						ace_type_param_values.append("")
					else:
						ace_type_param = ace_type_param.strip()
						ace_type_param_values = [t.strip() for t in ace_type_param_values if t.strip()]
						if ace_type_param == "attributes":
							for val in ace_type_param_values:
								if not val:
									continue
								if val.startswith("!"):
									ace.denied_attributes.add(val[1:].strip())
								else:
									ace.allowed_attributes.add(val.strip())
						elif ace_type in ("sys_group", "sys_user", "opsi_depotserver", "opsi_client"):
							val = ace_type_param.strip()
							if ace_type == "sys_group":
								val = val.replace("{admingroup}", opsi_config.get("groups", "admingroup"))
								val = val.replace("{fileadmingroup}", opsi_config.get("groups", "fileadmingroup"))
							ids.append(val)
						else:
							raise ValueError(f"Unhandled acl type param '{ace_type_param}' for acl type '{ace_type}' {position_text}")
						ace_type_param = ""
						ace_type_param_values = [""]
			if ids:
				for _id in ids:
					kwargs = ace.__dict__
					kwargs["id"] = _id
					acl.append(RPCACE(**kwargs))
			else:
				acl.append(ace)
	return acl


def write_default_acl_conf(path: Path) -> None:
	source = Path("/usr/lib/opsiconfd/opsiconfd_data/etc/backendManager/acl.conf")
	if not source.exists():
		source = Path("opsiconfd_data/etc/backendManager/acl.conf")  # Test scenario
		if not source.exists():
			logger.error("Failed to write default acl.conf. File not found")
			return
	logger.notice("Copying default acl.conf to '%s'", path)
	shutil.copy2(source, path)
