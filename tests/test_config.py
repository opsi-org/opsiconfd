# -*- coding: utf-8 -*-

# This file is part of opsiconfd.
# Copyright (C) 2019 uib GmbH <info@uib.de>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Test config parsing.

:copyright:uib GmbH <info@uib.de>
:author: Niko Wenselowski <n.wenselowski@uib.de>
:license: GNU Affero General Public License version 3
"""

import os

from opsiconfd.config import readConfigFile

import pytest


@pytest.fixture
def configfile():
    return os.path.join(os.path.dirname(__file__), '..',
                              'data', 'etc', 'opsi', 'opsiconfd.conf')


@pytest.mark.parametrize("key, expected", [
	('backendConfigDir', '/etc/opsi/backends'),
	('dispatchConfigFile', '/etc/opsi/backendManager/dispatch.conf'),
	('extensionConfigDir', '/etc/opsi/backendManager/extend.d'),
	('aclFile', '/etc/opsi/backendManager/acl.conf'),
	('adminNetworks', ['0.0.0.0/0']),
	('pidFile', '/var/run/opsiconfd/opsiconfd.pid'),
	('logFile', '/var/log/opsi/opsiconfd/%m.log'),
	('symlinkLogs', True),
	('logLevel', 5),
	('logFormat', '[%l] [%D] %M (%F|%N)'),
	('maxlogsize', 5242880),
	('maxExecutionStatisticValues', 250),
	('monitoringUser', 'monitoring'),
	('monitoringDebug', False),
	('interface', '0.0.0.0'),
	('httpPort', 0),
	('httpsPort', 4447),
	('sslServerCertFile', '/etc/opsi/opsiconfd.pem'),
	('sslServerKeyFile', '/etc/opsi/opsiconfd.pem'),
	('acceptedCiphers', ''),
	('sessionName', 'OPSISID'),
	('resolveVerifyIp', False),
	('updateIpAddress', True),
	('sessionMaxInactiveInterval', 120),
	('maxAuthenticationFailures', 5),
	('maxSessionsPerIp', 25),
	])
def testReadingDefaultConfig(configfile, key, expected):
	config = readConfigFile(configfile)

	assert config[key] == expected

