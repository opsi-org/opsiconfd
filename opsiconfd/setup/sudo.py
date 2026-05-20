# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.setup.sudo
"""

import shlex
import shutil
from pathlib import Path

from opsiconfd.config import SUDOERS_CONF, config, opsi_config
from opsiconfd.dhcpd import get_dhcpd_control_config
from opsiconfd.logging import logger

START_COMMENT = "# Auto added by opsiconfd setup"


def format_command(cmd: list[str] | str) -> str:
	if not isinstance(cmd, list):
		cmd = shlex.split(cmd)
	if cmd[0].rsplit("/", 1)[-1] == "sudo":
		cmd = cmd[1:]
	if not cmd[0].startswith("/"):
		cmd[0] = shutil.which(cmd[0]) or f"/usr/bin/{cmd[0]}"
	return shlex.join(cmd)


def setup_sudoers() -> None:
	logger.info("Setup sudoers")
	user = config.run_as_user
	setup_sudo_entries = config.setup_sudo_entries
	if user == "root":
		# No need to setup sudoers for opsiconfd if it runs as root
		setup_sudo_entries = [x for x in setup_sudo_entries if "opsiconfd" not in x]

	sudoers_conf = Path(SUDOERS_CONF)
	if not sudoers_conf.exists():
		return
	admin_group = opsi_config.get("groups", "admingroup")
	if not admin_group or " " in admin_group:
		logger.error("Invalid admin group '%s'. Skip setup sudoers.", admin_group)
		return
	file_admin_group = opsi_config.get("groups", "fileadmingroup")
	if not file_admin_group or " " in file_admin_group:
		logger.error("Invalid file admin group '%s'. Skip setup sudoers.", file_admin_group)
		return

	add_lines = [
		START_COMMENT,
		f"Defaults:{user} !requiretty",
	]
	if "set_rights_opsiconfd" in setup_sudo_entries:
		add_lines.append(f"{user} ALL=NOPASSWD: /usr/bin/opsi-set-rights")
	if "set_rights_file_admin_group" in setup_sudo_entries:
		add_lines.append(f"%{file_admin_group} ALL=NOPASSWD: /usr/bin/opsi-set-rights")
	if "opsiconfd_setup_admin_group" in setup_sudo_entries:
		add_lines.append(f"%{admin_group} ALL=NOPASSWD: /usr/bin/opsiconfd setup *")
	if "opsiconfd_dhcpd_reload" in setup_sudo_entries:
		dhcpd_control_config = get_dhcpd_control_config()
		if dhcpd_control_config.enabled and dhcpd_control_config.reload_config_command:
			cmd = format_command(dhcpd_control_config.reload_config_command)
			add_lines.append(f"{user} ALL=NOPASSWD: {cmd}")

	lines = sudoers_conf.read_text(encoding="utf-8").splitlines()
	new_lines: list[str] = []
	insert_pos = -1
	idx = 0
	for line in lines:
		sline = line.strip().lower()
		if line == START_COMMENT:
			insert_pos = idx
		if line == START_COMMENT or sline.startswith(
			(f"{user} ", f"{user}\t", f"defaults:{user}", f"%{admin_group} ", f"%{file_admin_group} ")
		):
			continue
		new_lines.append(line)
		idx += 1

	if insert_pos == -1:
		insert_pos = len(new_lines)
		add_lines.append("")
	elif new_lines[insert_pos] != "":
		add_lines.append("")
	new_lines[insert_pos:insert_pos] = add_lines

	if lines != new_lines:
		logger.info("Patching '%s'", sudoers_conf)
		sudoers_conf.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
