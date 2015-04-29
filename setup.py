#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of python-opsi.
# Copyright (C) 2010-2015 uib GmbH <info@uib.de>

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
opsi configuration daemon (opsiconfd) setup file

:copyright: uib GmbH <info@uib.de>
:author: Christian Kampka <c.kampka@uib.de>
:author: Niko Wenselowski <n.wenselowski@uib.de>
:license: GNU Affero General Public License version 3
"""

import os
from setuptools import setup

POSSIBLE_SERVICE_FILE_PATHS = (
	'/usr/lib/systemd/system/',  # systemd default
	'/lib/systemd/system',  # path on Ubuntu 15.04
	'/etc/systemd/system/'  # usually meant for units installed by sysadmin
)

cmdclass = {}

try:
	from opsidistutils.commands.osc_cmd import osc_publish as osc
	cmdclass['osc'] = osc
except ImportError:
	print("osc integration is not available on this machine. please install ospi-distutils.")


version = None
with open("opsiconfd/opsiconfd.py") as f:
	for line in f:
		if '__version__' in line:
			version = line.split('=')[1].strip()
			break

setup(
	name='opsiconfd',
	version=version,
	license='GPL-2',
	url="http://www.opsi.org",
	description='The opsi configiration management daemon',
	packages=['opsiconfd'],
	scripts=['scripts/opsiconfd', 'scripts/opsiconfd-guard'],
	data_files=[
		('/etc/opsi', ['data/etc/opsi/opsiconfd.conf']),
		('/etc/init.d', ['data/etc/init.d/opsiconfd']),
		('/etc/logrotate.d', ['data/etc/logrotate.d/opsiconfd']),
		('share/opsiconfd/static', [
			'data/shared/index.html',
			'data/shared/favicon.ico',
			'data/shared/opsi_logo.png'
		])
	],
	cmdclass = cmdclass
)
