# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

import os
import pytest

from opsiconfd.config import config

@pytest.mark.parametrize("arguments,config_name,expexted_value", [
    (["--backend-config-dir", "/test"], "backend_config_dir", "/test"),
	(["--dispatch-config-file", "/filename"], "dispatch_config_file", "/filename"),
	(["--extension-config-dir", "/test"], "extension_config_dir", "/test"),
	(["--admin-networks", "10.10.10.0/24", "10.10.20.0/24"], "admin_networks", ["10.10.10.0/24", "10.10.20.0/24"]),
	(["--symlink-logs"], "symlink_logs", True),
])
def test_cmdline(arguments, config_name, expexted_value):
	config._parse_args(arguments) # pylint: disable=protected-access
	assert getattr(config, config_name) == expexted_value

@pytest.mark.parametrize("varname,value,config_name,expexted_value", [
    ("OPSICONFD_BACKEND_CONFIG_DIR", "/test", "backend_config_dir", "/test"),
	("OPSICONFD_DISPATCH_CONFIG_FILE", "/filename", "dispatch_config_file", "/filename"),
	("OPSICONFD_EXTENSION_CONFIG_DIR", "/test", "extension_config_dir", "/test"),
	("OPSICONFD_ADMIN_NETWORKS", "[10.10.10.0/24,10.10.20.0/24]", "admin_networks", ["10.10.10.0/24", "10.10.20.0/24"]),
	("OPSICONFD_SYMLINK_LOGS", "yes", "symlink_logs", True),
])
def test_environment_vars(varname, value, config_name, expexted_value):
	os.environ[varname] = value
	config._parse_args([]) # pylint: disable=protected-access
	try:
		assert getattr(config, config_name) == expexted_value
	finally:
		del os.environ[varname]

@pytest.mark.parametrize("varname,value,config_name,expexted_value", [
    ("backend-config-dir", "/test", "backend_config_dir", "/test"),
	("dispatch-config-file", "/filename", "dispatch_config_file", "/filename"),
	("extension-config-dir", "/test", "extension_config_dir", "/test"),
	("admin-networks", "[10.10.10.0/24,10.10.20.0/24]", "admin_networks", ["10.10.10.0/24", "10.10.20.0/24"]),
	("symlink-logs", "1", "symlink_logs", True),
	("symlink-logs", "false", "symlink_logs", False),
	("symlink-logs", "no", "symlink_logs", False),
])
def test_config_file(tmp_path, varname, value, config_name, expexted_value):
	conf_file = tmp_path / "opsiconfd.conf"
	conf_file.write_text(f"{varname} = {value}")
	config._parse_args(["--config", str(conf_file)]) # pylint: disable=protected-access
	assert getattr(config, config_name) == expexted_value
