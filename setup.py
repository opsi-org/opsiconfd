#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of opsiconfd
# Copyright (C) 2010-2019 uib GmbH <info@uib.de>

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

import codecs
import os
from setuptools import setup


VERSION = None
with codecs.open(os.path.join("debian", "changelog"), 'r', 'utf-8') as changelog:
	VERSION = changelog.readline().split('(')[1].split('-')[0]

if not VERSION:
	raise Exception(u"Failed to get version info")

# Always set __version__ in opsiconfd.__init__.py to the version found
# in the changelog to make sure the version is always up-to-date
# and nobody needs to manually update it.
initFilePath = os.path.join('opsiconfd', '__init__.py')
newInitLines = []
with codecs.open(initFilePath, 'r', 'utf-8') as originalFile:
	for line in originalFile:
		if line.startswith('__version__'):
			newInitLines.append("__version__ = '{0}'\n".format(VERSION))
			continue

		newInitLines.append(line)

with codecs.open(initFilePath, 'w', 'utf-8') as newInitFile:
	newInitFile.writelines(newInitLines)
print("Patched version {1!r} from changelog into {0}".format(initFilePath, VERSION))

data_files = [
	('/etc/opsi', ['data/etc/opsi/opsiconfd.conf']),
	('/etc/logrotate.d', ['data/etc/logrotate.d/opsiconfd']),
	('share/opsiconfd/static', [
		'data/shared/index.html',
		'data/shared/opsi_logo.png',
		'data/shared/favicon.ico',
		'data/shared/browserconfig.xml',
		'data/shared/manifest.json',
		'data/shared/android-icon-36x36.png',
		'data/shared/android-icon-48x48.png',
		'data/shared/android-icon-72x72.png',
		'data/shared/android-icon-96x96.png',
		'data/shared/android-icon-144x144.png',
		'data/shared/android-icon-192x192.png',
		'data/shared/apple-icon-57x57.png',
		'data/shared/apple-icon-60x60.png',
		'data/shared/apple-icon-72x72.png',
		'data/shared/apple-icon-76x76.png',
		'data/shared/apple-icon-114x114.png',
		'data/shared/apple-icon-120x120.png',
		'data/shared/apple-icon-144x144.png',
		'data/shared/apple-icon-152x152.png',
		'data/shared/apple-icon-180x180.png',
		'data/shared/apple-icon-precomposed.png',
		'data/shared/apple-icon.png',
		'data/shared/ms-icon-70x70.png',
		'data/shared/ms-icon-144x144.png',
		'data/shared/ms-icon-150x150.png',
		'data/shared/ms-icon-310x310.png',
		'data/shared/favicon-16x16.png',
		'data/shared/favicon-32x32.png',
		'data/shared/favicon-96x96.png',
	])
]

setup(
	name='opsiconfd',
	version=VERSION,
	license='AGPL-3',
	url="http://www.opsi.org",
	description='The opsi configiration management daemon',
	packages=['opsiconfd'],
	entry_points={
		'console_scripts': [
			'opsiconfd = opsiconfd.opsiconfd:rumFromCommandline',
		]
	},
	data_files=data_files,
)
