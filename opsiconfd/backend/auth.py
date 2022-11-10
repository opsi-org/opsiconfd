# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
auth
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Literal, Optional, Set, Tuple

from OPSI.Config import FILE_ADMIN_GROUP, OPSI_ADMIN_GROUP  # type: ignore[import]
from sqlalchemy.orm.query import Query

from opsiconfd.config import config
from opsiconfd.logging import logger
from opsiconfd.utils import Singleton


@dataclass(frozen=True, kw_only=True)
class RPCACE:
	"""RPC Access Control Entry"""
	# __slots__ = ('method_re', 'type', 'id', 'allowed_attributes', 'denied_attributes')
	method_re: re.Pattern
	type: Literal['all', 'self', 'opsi_depotserver', 'opsi_client', 'sys_group', 'sys_user']
	id: Optional[str] = None  # pylint: disable=invalid-name
	allowed_attributes: Set[str] = field(default_factory=set)
	denied_attributes: Set[str] = field(default_factory=set)


def read_acl_file(acl_file: Path | str) -> List[RPCACE]:  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
	acl = []
	# acl example:
	#    <method>: <aclType>[(aclTypeParam[(aclTypeParamValue,...)];...)]
	#    xyz_.*:   opsi_depotserver(attributes(id,name))
	#    abc:      self(attributes(!opsiHostKey));sys_group(admin, group 2, attributes(!opsiHostKey))
	acl_entry_regex = re.compile(r'^([^:]+)+\s*:\s*(\S.*)$')
	if not isinstance(acl_file, Path):
		acl_file = Path(acl_file)

	for line in acl_file.read_text(encoding="utf-8").split("\n"):  # pylint: disable=too-many-nested-blocks
		line = line.strip()
		if not line or line.startswith("#"):
			continue
		match = acl_entry_regex.search(line)
		if not match:
			raise ValueError(f"Bad formatted line '{line}' in acl file '{config.acl_file}'")
		method_re = re.compile(match.group(1).strip())  # pylint: disable=dotted-import-in-loop
		for entry in match.group(2).split(';'):
			entry = str(entry).strip()
			ace_type = entry
			ace_type_params = ''
			if entry.find('(') != -1:
				(ace_type, ace_type_params) = entry.split('(', 1)
				if ace_type_params[-1] != ')':
					raise ValueError(f"Bad formatted acl entry '{entry}': trailing ')' missing")
				ace_type = ace_type.strip()
				ace_type_params = ace_type_params[:-1]

			if ace_type not in ('all', 'self', 'opsi_depotserver', 'opsi_client', 'sys_group', 'sys_user'):
				raise ValueError(f"Unhandled acl type: '{ace_type}'")

			ace = RPCACE(method_re=method_re, type=ace_type)  # type: ignore[arg-type]
			if not ace_type_params:
				if ace_type in ('sys_group', 'sys_user'):
					raise ValueError(f"Bad formatted acl type '{ace_type}': no params given")
				acl.append(ace)
				continue

			ace_type_param = ''
			ace_type_param_values = ['']
			in_ace_type_param_values = False
			ids = []
			for idx, char in enumerate(ace_type_params):
				if char == '(':
					if in_ace_type_param_values:
						raise ValueError(f"Bad formatted acl type params '{ace_type_params}'")  # pylint: disable=loop-invariant-statement
					in_ace_type_param_values = True
				elif char == ')':
					if not in_ace_type_param_values or not ace_type_param:
						raise ValueError(f"Bad formatted acl type params '{ace_type_params}'")  # pylint: disable=loop-invariant-statement
					in_ace_type_param_values = False
				elif char != ',' or idx == len(ace_type_params) - 1:  # pylint: disable=loop-invariant-statement
					if in_ace_type_param_values:
						ace_type_param_values[-1] += char
					else:
						ace_type_param += char

				if char == ',' or idx == len(ace_type_params) - 1:  # pylint: disable=loop-invariant-statement
					if in_ace_type_param_values:
						if idx == len(ace_type_params) - 1:  # pylint: disable=loop-invariant-statement
							raise ValueError(f"Bad formatted acl type params '{ace_type_params}'")  # pylint: disable=loop-invariant-statement
						ace_type_param_values.append('')
					else:
						ace_type_param = ace_type_param.strip()
						ace_type_param_values = [t.strip() for t in ace_type_param_values if t.strip()]
						if ace_type_param == 'attributes':
							for val in ace_type_param_values:
								if not val:
									continue
								if val.startswith('!'):
									ace.denied_attributes.add(val[1:].strip())
								else:
									ace.allowed_attributes.add(val.strip())
						elif ace_type in ('sys_group', 'sys_user', 'opsi_depotserver', 'opsi_client'):  # pylint: disable=loop-invariant-statement
							val = ace_type_param.strip()
							if ace_type == 'sys_group':  # pylint: disable=loop-invariant-statement
								val = val.replace("{admingroup}", OPSI_ADMIN_GROUP)
								val = val.replace("{fileadmingroup}", FILE_ADMIN_GROUP)
							ids.append(val)
						else:
							raise ValueError(f"Unhandled acl type param '{ace_type_param}' for acl type '{ace_type}'")
						ace_type_param = ''
						ace_type_param_values = ['']  # pylint: disable=use-tuple-over-list
			if ids:
				for _id in ids:
					kwargs = ace.__dict__
					kwargs["id"] = _id
					acl.append(RPCACE(**kwargs))
			else:
				acl.append(ace)
	return acl

'''
@dataclass(frozen=True, kw_only=True)
class RPCPermissions:
	"""
	RPC permissions
	allowed_* = None  means no restricitions
	allowed_* = {}    means no permssions
	"""
	__slots__ = ('allowed_user_ids', 'allowed_client_ids', 'allowed_depot_ids', 'allowed_attributes', 'denied_attributes')

	allowed_user_ids: Set[str] = set()
	allowed_client_ids: Set[str] = set()
	allowed_depot_ids: Set[str] = set()
	allowed_attributes: Set[str] = set()
	denied_attributes: Set[str] = set()


class RPCAccessControl(metaclass=Singleton):
	def __init__(self) -> None:
		self._acl = []

	def read_acl_file(self) -> None:
		self._acl = []
		# acl example:
		#    <method>: <aclType>[(aclTypeParam[(aclTypeParamValue,...)];...)]
		#    xyz_.*:   opsi_depotserver(attributes(id,name))
		#    abc:      self(attributes(!opsiHostKey));sys_group(admin, group 2, attributes(!opsiHostKey))
		acl_entry_regex = re.compile(r'^([^:]+)+\s*:\s*(\S.*)$')

		acls = {}
		with open(config.acl_file, encoding="utf-8") as file:
			for line in file.readlines():
				line = line.strip()
				if not line or line.startswith("#"):
					continue
				match = acl_entry_regex.search(line)
				if not match:
					raise ValueError(f"Bad formatted line '{line}' in acl file '{config.acl_file}'")

	def get_rpc_permissions(user_type: Literal["user", "client", "depot"], user: str, groups: Set[str]):
		return RPCPermissions(
			allowed_user_ids=set(),
			allowed_client_ids=set(),
			allowed_depot_ids=set(),
			allowed_attributes={},
			denied_attributes={}
		)

	#def get_ace(user_type) -> RPCACE:

	#def adjust_query(query: Query) -> Query:
	#	return query
'''
