# -*- coding: utf-8 -*-

# This file is part of python-opsi.
# Copyright (C) 2018-2019 uib GmbH <info@uib.de>

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
Config handling.

:copyright:uib GmbH <info@uib.de>
:author: Jan Schneider <j.schneider@uib.de>
:author: Erol Ueluekmen <e.ueluekmen@uib.de>
:author: Niko Wenselowski <n.wenselowski@uib.de>
:license: GNU Affero General Public License version 3
"""

from OPSI.Logger import Logger
from OPSI.Types import (
	forceBool, forceFilename, forceInt, forceNetworkAddress, forceUnicode)
from OPSI.Util import removeUnit
from OPSI.Util.File import IniFile

logger = Logger()


def readConfigFile(filename):
	'''
	Read settings from config file.

	:param filename: Path to the config file.
	:type filename: str
	'''
	logger.notice(u"Trying to read config from file: '%s'" % filename)
	settings = {}
	try:
		iniFile = IniFile(filename=filename, raw=True)
		config = iniFile.parse()

		for section in config.sections():
			logger.debug(
				u"Processing section {!r} in config file {!r}",
				section, filename
			)
			if section.lower() == 'global':
				# Global settings
				for (option, value) in config.items(section):
					if option == 'pid file':
						settings['pidFile'] = forceFilename(value)
					elif option == 'log level':
						settings['logLevel'] = forceInt(value)
					elif option == 'log file':
						settings['logFile'] = forceFilename(value)
					elif option == 'log format':
						settings['logFormat'] = forceUnicode(value)
					elif option == 'max log size':
						settings['maxlogsize'] = removeUnit(value)
					elif option == 'symlink logs':
						settings['symlinkLogs'] = forceBool(value)
					elif option == 'backend config dir':
						settings['backendConfigDir'] = forceFilename(value)
					elif option == 'dispatch config file':
						settings['dispatchConfigFile'] = forceFilename(value)
					elif option == 'extension config dir':
						settings['extensionConfigDir'] = forceFilename(value)
					elif option == 'acl file':
						settings['aclFile'] = forceFilename(value)
					elif option == 'max execution statistics':
						settings['maxExecutionStatisticValues'] = forceInt(value)
					elif option == 'loadbalancing':
						settings['loadbalancing'] = forceBool(value)
					elif option == 'admin networks':
						settings['adminNetworks'] = [
							forceNetworkAddress(net.strip())
							for net in value.split(',')
						]
					elif option == 'monitoring user':
						settings['monitoringUser'] = forceUnicode(value)
					elif option == 'monitoring debug':
						settings['monitoringDebug'] = forceBool(value)
					else:
						logger.warning(
							u"Ignoring unknown option {!r} in config file {!r}",
							option, filename
						)
			elif section.lower() == 'service':
				# Service settings
				for (option, value) in config.items(section):
					if option == 'http port':
						settings['httpPort'] = forceInt(value)
					elif option == 'https port':
						settings['httpsPort'] = forceInt(value)
					elif option == 'interface':
						settings['interface'] = forceUnicode(value)
					elif option == 'ssl server cert':
						settings['sslServerCertFile'] = forceFilename(value)
					elif option == 'ssl server key':
						settings['sslServerKeyFile'] = forceFilename(value)
					elif option == 'accepted ciphers':
						settings['acceptedCiphers'] = forceUnicode(value)
					else:
						logger.warning(
							u"Ignoring unknown option {!r} in config file {!r}",
							option, filename
						)
			elif section.lower() == 'session':
				# Session settings
				for (option, value) in config.items(section):
					if option == 'session name':
						settings['sessionName'] = forceUnicode(value)
					elif option == 'verify ip':
						settings['resolveVerifyIp'] = forceBool(value)
					elif option == 'update ip':
						settings['updateIpAddress'] = forceBool(value)
					elif option == 'max inactive interval':
						settings['sessionMaxInactiveInterval'] = forceInt(value)
					elif option == 'max sessions per ip':
						settings['maxSessionsPerIp'] = forceInt(value)
					elif option == 'max authentication failures':
						settings['maxAuthenticationFailures'] = forceInt(value)
					else:
						logger.warning(
							u"Ignoring unknown option {!r} in config file {!r}",
							option, filename
						)
			elif section.lower() == 'directories':
				# Static directories
				settings['staticDirectories'] = {}
				for (directory, path) in config.items(section):
					opt = []
					if '(' in path:
						(path, opt) = path.split('(', 1)
						path = path.strip()
						opt = [
							o.strip()
							for o
							in opt.lower().replace(')', '').strip().split(',')
						]

					settings['staticDirectories'][directory] = {
						"path": forceFilename(path),
						"options": opt
					}
			else:
				logger.warning(
					u"Ignoring unknown section {!r} in config file {!r}",
					section, filename
				)

		logger.notice(u"Config read")
	except Exception as error:
		logger.logException(error)
		logger.error(u"Failed to read config file {!r}: {}", filename, error)
		raise

	return settings
