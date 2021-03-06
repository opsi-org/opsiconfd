# -*- coding: utf-8 -*-

# This file is part of opsiconfd.
# Copyright (C) 2014-2018 uib GmbH <info@uib.de>

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
Testing the opsiconfd.

opsiconfd is part of opsi - https://opsi.org

:author: Niko Wenselowski <n.wenselowski@uib.de>
:license: GNU Affero General Public License version 3
"""

import time

import pytest

from opsiconfd.statistics import Statistics

try:
    xrange
except NameError:
    xrange = range


class FakeOpsiconfd(object):
    def __init__(self):
        self.config = {
            'maxExecutionStatisticValues': 250,
            'rrdDir': '/tmp'
        }


class FakeRPC(object):
    def __init__(self, exception=False, methodName="dummy_method", duration=0.0):
        self.exception = exception
        self.result = []
        self.params = []
        self.started = time.time()
        self.methodName = methodName

        if duration:
            self.ended = self.started + duration
        else:
            self.ended = time.time()

    def getMethodName(self):
        return self.methodName


def testNumberOfStatisticsIsLimited():
    stats = Statistics(FakeOpsiconfd())
    [stats.addRpc(FakeRPC()) for _ in xrange(500000)]
    assert 250 == len(stats.getRpcs())


def testGettingOverallCallCount():
    stats = Statistics(FakeOpsiconfd())
    [stats.addRpc(FakeRPC()) for _ in xrange(500000)]

    assert 250 == len(stats.getRpcs())
    assert 1 == len(stats.getRPCCallCounts())
    assert "dummy_method" in stats.getRPCCallCounts()
    assert 500000 == stats.getRPCCallCounts()['dummy_method']

    stats.addRpc(FakeRPC(methodName="another_method"))
    assert 2 == len(stats.getRPCCallCounts())
    assert "another_method" in stats.getRPCCallCounts()


def testCollectingCountAlsoHasInformationAboutDuration():
    stats = Statistics(FakeOpsiconfd())
    [stats.addRpc(FakeRPC(duration=10.0)) for _ in xrange(100)]

    averages = stats.getRPCAverageDurations()
    assert 1 == len(averages)
    assert 10.0 == averages["dummy_method"]

    stats.addRpc(FakeRPC(duration=5))
    newAverages = stats.getRPCAverageDurations()
    assert pytest.approx(9.950495049504951) == newAverages["dummy_method"]


def testCollectingUseragents():
    stats = Statistics(FakeOpsiconfd())

    for _ in range(10):
        stats.addUserAgent('test agent 1.2.3')

    stats.addUserAgent('test agent 1.2.4')
    stats.addUserAgent('test agent 1.2.4')
    stats.addUserAgent('another agent 5.6')

    collectedAgents = stats.getUserAgents()
    assert collectedAgents['test agent 1.2.3'] == 10
    assert collectedAgents['test agent 1.2.4'] == 2
    assert collectedAgents['another agent 5.6'] == 1
    assert 'not seen' not in collectedAgents
