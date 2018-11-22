# -*- coding: utf-8 -*-

# This file is part of opsiconfd.
# Copyright (C) 2016-2018 uib GmbH <info@uib.de>

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
Testing the resources that provide concrete sites.

:author: Niko Wenselowski <n.wenselowski@uib.de>
:license: GNU Affero General Public License version 3
"""

from opsiconfd.resources import ResourceOpsiconfdConfigedJNLP


class FakeHeaders:
    def __init__(self, **kwargs):
        self._headers = kwargs

    def getHeader(self, key):
        return self._headers[key]


class FakeRequest:
    def __init__(self, uri, headers):
        self.uri = uri
        self.headers = headers


def testDefaultArgumentIsTheAddressOfTheServer():
    arguments = list(ResourceOpsiconfdConfigedJNLP.getArguments(FakeRequest('', FakeHeaders(host='blabla'))))

    assert ['-h', 'blabla'] == arguments


def testAdditionalArgumentsAreInTags():
    arguments = list(ResourceOpsiconfdConfigedJNLP.getArguments(FakeRequest('?foo=bar', FakeHeaders(host='blabla'))))

    assert ['-h', 'blabla', '--foo', 'bar'] == arguments


def testPassingAdditionalArguments():
    arguments = ';;'.join(ResourceOpsiconfdConfigedJNLP.getArguments(FakeRequest('?foo=bar&hey=ho', FakeHeaders(host='blabla'))))

    assert '-h;;blabla;;--foo;;bar;;--hey;;ho' == arguments


def testHandlingShortOptAndLongOpt():
    arguments = list(ResourceOpsiconfdConfigedJNLP.getArguments(FakeRequest('?f=bar&hey=ho', FakeHeaders(host='a'))))

    assert '-f' in arguments
    assert 'bar' == arguments[arguments.index('-f') + 1]
    assert '--hey' in arguments
    assert 'ho' == arguments[arguments.index('--hey') + 1]
