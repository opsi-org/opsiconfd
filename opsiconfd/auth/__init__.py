# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
auth
"""

import re
from dataclasses import dataclass
from typing import Literal, Tuple

from config import config
from OPSI.Config import (  # pylint: disable=import-outside-toplevel
	FILE_ADMIN_GROUP,
	OPSI_ADMIN_GROUP,
)
from sqlalchemy.orm.query import Query

from opsiconfd.logging import logger
from opsiconfd.utils import Singleton

	def parse(self, lines=None):  # pylint: disable=too-many-branches,too-many-statements,too-many-locals

		if lines:
			self._lines = forceUnicodeList(lines)
		else:
			self.readlines()
		self._parsed = False
		# acl example:
		#    <method>: <aclType>[(aclTypeParam[(aclTypeParamValue,...)];...)]
		#    xyz_.*:   opsi_depotserver(attributes(id,name))
		#    abc:      self(attributes(!opsiHostKey));sys_group(admin, group 2, attributes(!opsiHostKey))

		acl = []
		for line in ConfigFile.parse(self):  # pylint: disable=too-many-nested-blocks
			match = re.search(self.aclEntryRegex, line)
			if not match:
				raise ValueError(f"Found bad formatted line '{line}' in acl file '{self._filename}'")
			method = match.group(1).strip()
			acl.append([method, []])
			for entry in match.group(2).split(';'):
				entry = entry.strip()
				aclType = entry
				aclTypeParams = ''
				if entry.find('(') != -1:
					(aclType, aclTypeParams) = entry.split('(', 1)
					if aclTypeParams[-1] != ')':
						raise ValueError(f"Bad formatted acl entry '{entry}': trailing ')' missing")
					aclType = aclType.strip()
					aclTypeParams = aclTypeParams[:-1]

				if aclType not in ('all', 'self', 'opsi_depotserver', 'opsi_client', 'sys_group', 'sys_user'):
					raise ValueError(f"Unhandled acl type: '{aclType}'")
				entry = {'type': aclType, 'allowAttributes': [], 'denyAttributes': [], 'ids': []}
				if not aclTypeParams:
					if aclType in ('sys_group', 'sys_user'):
						raise ValueError(f"Bad formatted acl type '{aclType}': no params given")
				else:
					aclTypeParam = ''
					aclTypeParamValues = ['']
					inAclTypeParamValues = False
					for idx, char in enumerate(aclTypeParams):
						if char == '(':
							if inAclTypeParamValues:
								raise ValueError(f"Bad formatted acl type params '{aclTypeParams}'")
							inAclTypeParamValues = True
						elif char == ')':
							if not inAclTypeParamValues or not aclTypeParam:
								raise ValueError(f"Bad formatted acl type params '{aclTypeParams}'")
							inAclTypeParamValues = False
						elif char != ',' or idx == len(aclTypeParams) - 1:
							if inAclTypeParamValues:
								aclTypeParamValues[-1] += char
							else:
								aclTypeParam += char

						if char == ',' or idx == len(aclTypeParams) - 1:
							if inAclTypeParamValues:
								if idx == len(aclTypeParams) - 1:
									raise ValueError(f"Bad formatted acl type params '{aclTypeParams}'")
								aclTypeParamValues.append('')
							else:
								aclTypeParam = aclTypeParam.strip()
								aclTypeParamValues = [t.strip() for t in aclTypeParamValues if t.strip()]
								if aclTypeParam == 'attributes':
									for val in aclTypeParamValues:
										if not val:
											continue
										if val.startswith('!'):
											entry['denyAttributes'].append(val[1:].strip())
										else:
											entry['allowAttributes'].append(val)
								elif aclType in ('sys_group', 'sys_user', 'opsi_depotserver', 'opsi_client'):
									val = aclTypeParam.strip()
									if aclType == 'sys_group':
										val = val.replace("{admingroup}", OPSI_ADMIN_GROUP)
										val = val.replace("{fileadmingroup}", FILE_ADMIN_GROUP)
									entry['ids'].append(val)
								else:
									raise ValueError(f"Unhandled acl type param '{aclTypeParam}' for acl type '{aclType}'")
								aclTypeParam = ''
								aclTypeParamValues = ['']

				acl[-1][1].append(entry)
		self._parsed = True
		return acl


@dataclass
class RPCACE:
	"""RPC Access Control Entry"""
	__slots__ = ('method_re', 'type', 'attributes_allowed', 'attributes_denied', 'ids')
	method_re: re.Pattern
	type: Literal['all', 'self', 'opsi_depotserver', 'opsi_client', 'sys_group', 'sys_user']
	attributes_allowed: Tuple[str]
	attributes_denied: Tuple[str]
	ids: Tuple[str]


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

	def get_ace(user_type) -> RPCACE:

	def adjust_query(query: Query) -> Query:
		return query
