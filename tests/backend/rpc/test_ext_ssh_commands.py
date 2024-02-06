# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.ext_ssh_commands
"""

from pathlib import Path
from unittest.mock import patch

from opsiconfd.backend.rpc.ext_ssh_commands import RPCExtSSHCommandsMixin, SSHCommand


class Backend(RPCExtSSHCommandsMixin):
	pass


def test_ssh_commands_file(tmp_path: Path) -> None:
	ssh_commands_default_file = tmp_path / "server_commands_default.conf"
	ssh_commands_custom_file = tmp_path / "server_commands_custom.conf"
	ssh_commands_default_file.write_text(
		"\n"
		'{"position": 0, "needSudo": false, "parentMenuText": "list directories",'
		' "commands": ["ls -l /var/lib/opsi/workbench"], "menuText": "ls workbench", "id": "ls_workbench"}\n'
		"\n"
		'{"position": 1, "needSudo": true, "parentMenuText": null, "tooltipText": "tooltip1",'
		' "commands": ["whoami"], "menuText": "whoami", "id": "whoami"}\n'
		"\n"
	)
	ssh_commands_custom_file.write_text(
		"\n"
		'{"position": 3, "parentMenuText": "list directories",'
		' "commands": ["ls -l /var/lib/opsi/custom"], "menuText": "ls workbench", "id": "ls_workbench"}\n'
		"\n"
		' {"parse error}\n'
		"\n"
		'{"position": 4, "needSudo": true, "parentMenuText": null, "tooltipText": "tooltip4",'
		' "commands": ["whoami"], "menuText": "whoami custom", "id": "whoami_custom"}\n'
		"\n"
	)
	with patch(
		"opsiconfd.backend.rpc.ext_ssh_commands.RPCExtSSHCommandsMixin.ssh_commands_default_file", str(ssh_commands_default_file)
	), patch("opsiconfd.backend.rpc.ext_ssh_commands.RPCExtSSHCommandsMixin.ssh_commands_custom_file", str(ssh_commands_custom_file)):
		backend = Backend()
		cmd_list = backend._read_ssh_commands_file(str(ssh_commands_default_file))  # type: ignore[misc]
		assert len(cmd_list) == 2

		assert cmd_list[0].position == 0
		assert cmd_list[0].needSudo is False
		assert cmd_list[0].parentMenuText == "list directories"
		assert cmd_list[0].tooltipText is None
		assert cmd_list[0].commands == ["ls -l /var/lib/opsi/workbench"]
		assert cmd_list[0].menuText == "ls workbench"
		assert cmd_list[0].id == "ls_workbench"
		assert cmd_list[0].buildIn is True

		assert cmd_list[1].position == 1
		assert cmd_list[1].needSudo is True
		assert cmd_list[1].parentMenuText is None
		assert cmd_list[1].tooltipText == "tooltip1"
		assert cmd_list[1].commands == ["whoami"]
		assert cmd_list[1].menuText == "whoami"
		assert cmd_list[1].id == "whoami"
		assert cmd_list[1].buildIn is True

		cmd_list = backend._read_ssh_commands_file(str(ssh_commands_custom_file))  # type: ignore[misc]
		assert len(cmd_list) == 2

		assert cmd_list[0].position == 3
		assert cmd_list[0].needSudo is False
		assert cmd_list[0].parentMenuText == "list directories"
		assert cmd_list[0].tooltipText is None
		assert cmd_list[0].commands == ["ls -l /var/lib/opsi/custom"]
		assert cmd_list[0].menuText == "ls workbench"
		assert cmd_list[0].id == "ls_workbench"
		assert cmd_list[0].buildIn is False

		assert cmd_list[1].position == 4
		assert cmd_list[1].needSudo is True
		assert cmd_list[1].parentMenuText is None
		assert cmd_list[1].tooltipText == "tooltip4"
		assert cmd_list[1].commands == ["whoami"]
		assert cmd_list[1].menuText == "whoami custom"
		assert cmd_list[1].id == "whoami_custom"
		assert cmd_list[1].buildIn is False

		cmd_dict = backend._read_ssh_commands_files()  # type: ignore[misc]
		assert len(cmd_dict) == 3

		assert cmd_dict["ls workbench"].commands == ["ls -l /var/lib/opsi/custom"]
		assert cmd_dict["whoami"].commands == ["whoami"]
		assert cmd_dict["whoami custom"].commands == ["whoami"]

		new_cmd = SSHCommand(menuText="new 1", commands=["1", "2"])
		assert new_cmd.id == "new_1"
		cmd_dict[new_cmd.menuText] = new_cmd

		backend._write_custom_ssh_command_file(list(cmd_dict.values()))
		cmd_list = backend._read_ssh_commands_file(str(ssh_commands_custom_file))  # type: ignore[misc]
		assert len(cmd_list) == 3
		_new_cmd = None
		for cmd in cmd_list:
			assert cmd.buildIn is False
			if cmd.id == new_cmd.id:
				_new_cmd = new_cmd

		assert _new_cmd == new_cmd
