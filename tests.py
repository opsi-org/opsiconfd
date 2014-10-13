#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of opsiconfd.
# Copyright (C) 2014 uib GmbH <info@uib.de>

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
import unittest

from opsiconfd.statistics import Statistics

try:
  xrange
except NameError:
  xrange = range


class StatisticsTestCase(unittest.TestCase):
    def testNumberOfStatisticsIsLimited(self):
        allowedNumberOfEntries = 250

        class FakeOpsiconfd(object):
            def __init__(self):
                self.config = {
                    'maxExecutionStatisticValues': allowedNumberOfEntries,
                    'rrdDir': '/tmp'
                }

        class FakeRPC(object):
            def __init__(self, exception=False):
                self.exception = exception
                self.result = []
                self.params = []
                self.started = time.time()
                self.ended = time.time()

            def getMethodName(self):
                return "dummy_method"


        stats = Statistics(FakeOpsiconfd())
        [stats.addRpc(FakeRPC()) for _ in xrange(500000)]

        self.assertEquals(allowedNumberOfEntries, len(stats.getRpcs()))


if __name__ == '__main__':
    unittest.main()
