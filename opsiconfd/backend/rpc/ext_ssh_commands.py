# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
rpc methods ssh commands
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Protocol

from opsicommon.types import forceList  # type: ignore[import]
from pydantic import (  # pylint: disable=no-name-in-module
	BaseModel,
	root_validator,
	validator,
)

from opsiconfd.config import SSH_COMMANDS_CUSTOM_FILE, SSH_COMMANDS_DEFAULT_FILE
from opsiconfd.logging import logger

from . import rpc_method

if TYPE_CHECKING:
	from .protocol import BackendProtocol


class SSHCommand(BaseModel):
	menuText: str
	commands: List[str]
	id: str | None = None
	position: int | None = None
	needSudo: bool = False
	tooltipText: str | None = None
	parentMenuText: str | None = None
	buildIn: bool = False

	@validator("menuText", always=True)
	def validate_menu_text(cls, value: str) -> str:
		if not value:
			raise ValueError("menuText must not be empty")
		return value

	@validator("commands", always=True)
	def validate_commands(cls, value: List[str]) -> List[str]:
		if not value:
			raise ValueError("'commands' has to be a non empty list")
		return value

	@root_validator
	def validate_id(cls, values: Dict[str, Any]) -> Dict[str, Any]:
		values["id"] = values["menuText"].strip().lower().replace(" ", "_")
		return values

	def conf_dict(self) -> Dict[str, Any]:
		ret = self.dict()
		del ret["buildIn"]
		return ret

	def update(  # pylint: disable=invalid-name,too-many-arguments
		self,
		commands: List[str] | None = None,
		position: int | None = None,
		needSudo: bool | None = None,
		tooltipText: str | None = None,
		parentMenuText: str | None = None,
	) -> None:
		if commands is not None:
			self.commands = commands
		if position is not None:
			self.position = position
		if needSudo is not None:
			self.needSudo = needSudo
		if tooltipText is not None:
			self.tooltipText = tooltipText
		if parentMenuText is not None:
			self.parentMenuText = parentMenuText


class RPCExtSSHCommandsMixin(Protocol):
	ssh_commands_default_file: str = SSH_COMMANDS_DEFAULT_FILE
	ssh_commands_custom_file: str = SSH_COMMANDS_CUSTOM_FILE

	def _read_ssh_commands_file(self: BackendProtocol, filename: str) -> List[SSHCommand]:
		logger.debug("Reading SSH commands file '%s'", filename)
		commands: List[SSHCommand] = []
		file_path = Path(filename)
		if not file_path.exists():
			logger.notice("SSH commands file '%s' not found", file_path)
			return commands

		build_in = filename == self.ssh_commands_default_file
		try:
			for line_idx, line in enumerate(file_path.read_text(encoding="utf-8").splitlines()):
				line = line.strip()
				if not line:
					continue
				try:  # pylint: disable=loop-try-except-usage
					entry = json.loads(line)  # pylint: disable=dotted-import-in-loop
					ssh_command = SSHCommand.parse_obj(entry)
					ssh_command.buildIn = build_in  # pylint: disable=invalid-name
					logger.trace("Read ssh command from '%s': %s", file_path, entry)
					commands.append(ssh_command)
				except Exception as err:  # pylint: disable=broad-except
					logger.error(
						"Failed to read entry on line number %d in SSH commands file '%s': %s", line_idx + 1, file_path, err, exc_info=True
					)
					continue

		except Exception as err:  # pylint: disable=broad-except
			logger.error("Failed to read SSH commands file '%s': %s", file_path, err)
		return commands

	def _read_ssh_commands_files(self: BackendProtocol) -> Dict[str, SSHCommand]:
		commands: Dict[str, SSHCommand] = {}
		for filename in (self.ssh_commands_default_file, self.ssh_commands_custom_file):
			# Custom file overrides commands with the same id
			for cmd in self._read_ssh_commands_file(filename):  # pylint: disable=use-dict-comprehension
				commands[cmd.menuText] = cmd
		return commands

	def _write_custom_ssh_command_file(self, commands: List[SSHCommand]) -> None:
		Path(self.ssh_commands_custom_file).write_text(
			"".join([json.dumps(c.conf_dict()) + "\n" for c in commands if not c.buildIn]), encoding="utf-8"
		)

	@rpc_method
	def SSHCommand_getObject(self: BackendProtocol, menuText: str) -> Optional[Dict[str, Any]]:  # pylint: disable=invalid-name
		for command in self._read_ssh_commands_files().values():
			if command.menuText == menuText:
				return command.dict()
		return None

	@rpc_method
	def SSHCommand_getObjects(self: BackendProtocol) -> List[Dict[str, Any]]:  # pylint: disable=invalid-name
		return [c.dict() for c in self._read_ssh_commands_files().values()]

	@rpc_method
	def SSHCommand_createObjects(self: BackendProtocol, commandList: List[Dict[str, Any]]) -> None:  # pylint: disable=invalid-name
		commands = self._read_ssh_commands_files()
		for cmd_dict in forceList(commandList):
			cmd = SSHCommand.parse_obj(cmd_dict)
			commands[cmd.menuText] = cmd
		self._write_custom_ssh_command_file(list(commands.values()))

	@rpc_method
	def SSHCommand_createObject(  # pylint: disable=invalid-name, too-many-arguments
		self: BackendProtocol,
		menuText: str,
		commands: List[str],
		position: int = 0,
		needSudo: bool = False,
		tooltipText: str = "",
		parentMenuText: str | None = None,
	) -> None:
		ssh_commands = self._read_ssh_commands_files()
		cmd = SSHCommand(
			menuText=menuText,
			commands=commands,
			position=position,
			needSudo=needSudo,
			tooltipText=tooltipText,
			parentMenuText=parentMenuText,
		)
		if not cmd.id:
			raise ValueError(f"Missing 'id' in command {cmd}")
		logger.notice("Creating SSH command: %s", cmd)
		ssh_commands[cmd.menuText] = cmd
		self._write_custom_ssh_command_file(list(ssh_commands.values()))

	@rpc_method
	def SSHCommand_updateObject(  # pylint: disable=invalid-name, too-many-arguments
		self: BackendProtocol,
		menuText: str,
		commands: List[str],
		position: int = 0,
		needSudo: bool = False,
		tooltipText: str = "",
		parentMenuText: str | None = None,
	) -> None:
		ssh_commands = self._read_ssh_commands_files()
		if menuText in ssh_commands:
			ssh_commands[menuText].update(
				commands=commands, position=position, needSudo=needSudo, tooltipText=tooltipText, parentMenuText=parentMenuText
			)
			ssh_commands[menuText].buildIn = False
			self._write_custom_ssh_command_file(list(ssh_commands.values()))

	@rpc_method
	def SSHCommand_updateObjects(  # pylint: disable=invalid-name, too-many-arguments
		self: BackendProtocol, commandList: List[Dict[str, Any]]
	) -> None:
		ssh_commands = self._read_ssh_commands_files()
		modified = False
		for cmd_dict in forceList(commandList):
			if "menuText" not in cmd_dict:
				raise ValueError("Key 'menuText' missing")  # pylint: disable=loop-invariant-statement
			menu_text = cmd_dict["menuText"]
			if menu_text in ssh_commands:
				ssh_commands[menu_text].update(
					commands=cmd_dict.get("commands"),
					position=cmd_dict.get("position"),
					needSudo=cmd_dict.get("needSudo"),
					tooltipText=cmd_dict.get("tooltipText"),
					parentMenuText=cmd_dict.get("parentMenuText"),
				)
				ssh_commands[menu_text].buildIn = False
				modified = True
		if modified:
			self._write_custom_ssh_command_file(list(ssh_commands.values()))

	@rpc_method
	def SSHCommand_deleteObjects(self: BackendProtocol, menuTextList: List[str]) -> None:  # pylint: disable=invalid-name
		ssh_commands = self._read_ssh_commands_files()
		for menu_text in forceList(menuTextList):
			if menu_text in ssh_commands:
				del ssh_commands[menu_text]
		self._write_custom_ssh_command_file(list(ssh_commands.values()))

	@rpc_method
	def SSHCommand_deleteObject(self: BackendProtocol, menuText: str) -> None:  # pylint: disable=invalid-name
		logger.notice("Deleting SSH command %s", menuText)
		ssh_commands = self._read_ssh_commands_files()
		if menuText not in ssh_commands:
			raise ValueError(f"Command menuText={menuText} does not exist")
		del ssh_commands[menuText]
		self._write_custom_ssh_command_file(list(ssh_commands.values()))