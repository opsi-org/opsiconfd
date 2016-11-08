#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of python-opsi.
# Copyright (C) 2010-2016 uib GmbH <info@uib.de>

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
Statistics about an running opsiconfd.

These classes provide the data that is shown on the info page.

:author: Jan Schneider <j.schneider@uib.de>
:author: Niko Wenselowski <n.wenselowski@uib.de>
:license: GNU Affero General Public License version 3
"""

import collections
import datetime
import os
import time
import threading
from twisted.internet.task import LoopingCall
import resource as pyresource

try:
	import rrdtool
except ImportError:
	rrdtool = None

try:
	import objgraph
except ImportError:
	objgraph = None

from OPSI.web2 import http, resource
from OPSI.Logger import Logger
from OPSI.Types import forceUnicode

logger = Logger()

CallStatistics = collections.namedtuple('CallStatistics', ['count', 'average'])


class ResourceOpsiconfdStatistics(resource.Resource):
	def __init__(self, opsiconfd):
		self._opsiconfd = opsiconfd

	def renderHTTP(self, request):
		''' Process request. '''
		return http.Response(
			stream='\n'.join(
				'{0}:{1}'.format(k, v) for (k, v) in
				self._opsiconfd.statistics().getStatistics().items()
			)
		)


class Statistics(object):
	"""
	Statistics about the opsiconfd.

	These are mainly data about the executed rpcs, possibly encountered
	encoding errors and the expired sessions.
	This class is also used for creating graphics via rrdtool.

	.. versionchanged:: 4.0.6

		Storing RPCs and expired sessions in a length-limited deque.
	"""

	def __init__(self, opsiconfd):
		self.opsiconfd = opsiconfd
		self._rpcs = collections.deque(maxlen=self.opsiconfd.config['maxExecutionStatisticValues'])
		self._rpcStatistics = collections.defaultdict(lambda: CallStatistics(0, 0.0))
		self._encodingErrors = []
		self._maxExpiredSessionInfos = 300
		self._expiredSessionInfo = collections.deque(maxlen=self._maxExpiredSessionInfos)
		self._utime = 0.0
		self._stime = 0.0
		self._last = time.time()
		self._rrdConfig = {
			'step': 60,  # in seconds
			'heartbeat': 120,
			'xPoints': 800,
			'yPoints': 160,
			'rrdFile': os.path.join(self.opsiconfd.config['rrdDir'], 'opsiconfd.rrd')
		}
		self._rrdCache = {
			'requests': 0,
			'sessions': 0,
			'davrequests': 0,
			'rpcs': 0,
			'rpcerrors': 0
		}

		if not os.path.exists(self._rrdConfig['rrdFile']):
			self.createRrd()
		loop = LoopingCall(self.updateRrd)
		loop.start(int(self._rrdConfig['step']), now=False)

	@staticmethod
	def rrdsAvailable():
		return bool(rrdtool)

	def createObjectGraph(self, maxDepth):
		if objgraph is not None:
			path = os.getcwd()
			try:
				os.chdir('/tmp')
				objgraph.show_backrefs([self.opsiconfd], max_depth=maxDepth)
			finally:
				os.chdir(path)

	def createRrd(self):
		if rrdtool is None:
			return

		if os.path.exists(self._rrdConfig['rrdFile']):
			os.unlink(self._rrdConfig['rrdFile'])

		start = int(time.time())
		logger.notice(u"Creating rrd '{rrdFile}', start: {0}", start, rrdFile=self._rrdConfig['rrdFile'])

		step = 3600 / self._rrdConfig['step']
		stepForDay = step * 24
		heartbeat = self._rrdConfig['heartbeat']

		rrdtool.create(str(self._rrdConfig['rrdFile']), '--start', str(start), '--step', str(self._rrdConfig['step']),
			'DS:requests:ABSOLUTE:%d:0:U' % heartbeat,
			'DS:sessions:DERIVE:%d:0:U' % heartbeat,
			'DS:davrequests:ABSOLUTE:%d:0:U' % heartbeat,
			'DS:rpcs:ABSOLUTE:%d:0:U' % heartbeat,
			'DS:rpcerrors:ABSOLUTE:%d:0:U' % heartbeat,
			'DS:cpu:GAUGE:%d:0:U' % heartbeat,
			'DS:mem:GAUGE:%d:0:U' % heartbeat,
			'DS:threads:GAUGE:%d:0:U' % heartbeat,
			'RRA:AVERAGE:0.5:1:%d' % step,    # hour
			'RRA:AVERAGE:0.5:1:%d' % stepForDay, # day
			'RRA:AVERAGE:0.5:7:%d' % stepForDay, # week
			'RRA:AVERAGE:0.5:31:%d' % stepForDay, # month
			'RRA:AVERAGE:0.5:365:%d' % stepForDay, # year
			'RRA:MAX:0.5:1:%d' % step,    # hour
			'RRA:MAX:0.5:1:%d' % stepForDay, # day
			'RRA:MAX:0.5:7:%d' % stepForDay, # week
			'RRA:MAX:0.5:31:%d' % stepForDay, # month
			'RRA:MAX:0.5:365:%d' % stepForDay, # year
		)

	def getStatistics(self):
		now = int(time.time())

		try:
			self._utime, self._stime, cpu, virtMem = self._getOwnResourceUsage(now, self._last)
			self._last = now

			return {
				"requests": self._rrdCache['requests'],
				"sessions": self._rrdCache['sessions'],
				"davrequests": self._rrdCache['davrequests'],
				"rpcs": self._rrdCache['rpcs'],
				"rpcerrors": self._rrdCache['rpcerrors'],
				"cpu": cpu,
				"virtmem": virtMem,
				"threads": len([t for t in threading.enumerate()])
			}
		except Exception as error:
			logger.logException(error)
			logger.error(u"Failed to get Statistics: {0}", error)
			return {}

	def _getOwnResourceUsage(self, currentTime, unixtimeOfLastCall):
		utime, stime, _ = pyresource.getrusage(pyresource.RUSAGE_SELF)[0:3]
		if int(utime - self._utime) == 0:
			usr = 0.0
		else:
			usr = (utime - self._utime) / (currentTime - unixtimeOfLastCall)

		if int(stime - self._stime) == 0:
			sys = 0.0
		else:
			sys = (stime - self._stime) / (currentTime - unixtimeOfLastCall)

		cpu = int("%0.0f" % ((usr + sys) * 100))
		if cpu > 100:
			cpu = 100

		with open('/proc/%s/stat' % os.getpid()) as f:
			data = f.read().split()
		virtMem = int("%0.0f" % (float(data[22]) / (1024 * 1024)))

		return (utime, stime, cpu, virtMem)

	def updateRrd(self):
		if rrdtool is None:
			return

		now = int(time.time())
		try:
			self._utime, self._stime, cpu, virtMem = self._getOwnResourceUsage(now, self._last)
			self._last = now

			threadCount = len([thread for thread in threading.enumerate()])
			# TODO: improve the following by using format and unpacking of a dict.
			rrdValues = '%d:%d:%d:%d:%d:%d:%d:%d:%d' \
				% (now, self._rrdCache['requests'], self._rrdCache['sessions'],
					self._rrdCache['davrequests'], self._rrdCache['rpcs'],
					self._rrdCache['rpcerrors'], cpu, virtMem, threadCount)
			logger.debug2(u'Updating rrd: {0}', rrdValues)
			rrdtool.update(str(self._rrdConfig['rrdFile']), rrdValues)
			self._rrdCache['requests'] = 0
			self._rrdCache['davrequests'] = 0
			self._rrdCache['rpcs'] = 0
			self._rrdCache['rpcerrors'] = 0
		except Exception as error:
			logger.error(u"Failed to update rrd: {0}", error)

	def getRrdGraphImage(self, imageType, range):
		"""
		Create an graph image with rrdtool.

		:param imageType: Type of the Image. 1 is webservice data, 2 is \
information about the host.
		"""
		if rrdtool is None:
			return None

		if imageType == 1:
			graphImage = os.path.join(self.opsiconfd.config['rrdDir'], '1_%s.png' % range)
		else:
			graphImage = os.path.join(self.opsiconfd.config['rrdDir'], '2_%s.png' % range)

		date = time.strftime("%a, %d %b %Y %H\:%M\:%S", time.localtime())
		end = int(time.time())
		start = end - range

		logger.debug(u"Creating rrd graph image '{0}', start: {1}, end: {2}", graphImage, start, end)

		if os.path.exists(graphImage):
			os.unlink(graphImage)
		# TODO: for the imageType use some kind of constant

		if imageType == 1:
			rrdtool.graph(str(graphImage),
				'--imgformat', 'PNG',
				'--width', str(self._rrdConfig['xPoints']),
				'--height', str(self._rrdConfig['yPoints']),
				'--start', str(start),
				'--end', str(end),
				'--vertical-label', 'avg per minute',
				'--lower-limit', str(0),
				'--units-exponent', str(0), # don't show milli-messages/s
				'--slope-mode',
				'--color', 'SHADEA#ffffff',
				'--color', 'SHADEB#ffffff',
				'--color', 'BACK#ffffff',

				'DEF:avg_requ=%s:requests:AVERAGE' % str(self._rrdConfig['rrdFile']),
				'DEF:max_requ=%s:requests:MAX' % str(self._rrdConfig['rrdFile']),
				'CDEF:avg_requ_permin=avg_requ,60,*',
				'CDEF:max_requ_permin=max_requ,60,*',
				'VDEF:total_requ=avg_requ,TOTAL',
				'LINE2:avg_requ_permin#0000dd:Requests     ',
				'GPRINT:total_requ:total\: %8.0lf requests     ',
				'GPRINT:avg_requ_permin:AVERAGE:avg\: %5.2lf requests/min     ',
				'GPRINT:max_requ_permin:MAX:max\: %4.0lf requests/min\\l',

				'DEF:avg_davrequ=%s:davrequests:AVERAGE' % str(self._rrdConfig['rrdFile']),
				'DEF:max_davrequ=%s:davrequests:MAX' % str(self._rrdConfig['rrdFile']),
				'CDEF:avg_davrequ_permin=avg_davrequ,60,*',
				'CDEF:max_davrequ_permin=max_davrequ,60,*',
				'VDEF:total_davrequ=avg_davrequ,TOTAL',
				'LINE2:avg_davrequ_permin#ff8000:DAV requests ',
				'GPRINT:total_davrequ:total\: %8.0lf dav requests ',
				'GPRINT:avg_davrequ_permin:AVERAGE:avg\: %5.2lf dav requests/min ',
				'GPRINT:max_davrequ_permin:MAX:max\: %4.0lf dav requests/min\\l',

				'DEF:avg_rpc=%s:rpcs:AVERAGE' % str(self._rrdConfig['rrdFile']),
				'DEF:max_rpc=%s:rpcs:MAX' % str(self._rrdConfig['rrdFile']),
				'CDEF:avg_rpc_permin=avg_rpc,60,*',
				'CDEF:max_rpc_permin=max_rpc,60,*',
				'VDEF:total_rpc=avg_rpc,TOTAL',
				'LINE2:avg_rpc_permin#00dd00:RPCs         ',
				'GPRINT:total_rpc:total\: %8.0lf rpcs         ',
				'GPRINT:avg_rpc_permin:AVERAGE:avg\: %5.2lf rpcs/min         ',
				'GPRINT:max_rpc_permin:MAX:max\: %4.0lf rpcs/min\\l',

				'DEF:avg_rpcerror=%s:rpcerrors:AVERAGE' % str(self._rrdConfig['rrdFile']),
				'DEF:max_rpcerror=%s:rpcerrors:MAX' % str(self._rrdConfig['rrdFile']),
				'CDEF:avg_rpcerror_permin=avg_rpcerror,60,*',
				'CDEF:max_rpcerror_permin=max_rpcerror,60,*',
				'VDEF:total_rpcerror=avg_rpcerror,TOTAL',
				'LINE2:avg_rpcerror_permin#dd0000:RPC errors   ',
				'GPRINT:total_rpcerror:total\: %8.0lf rpc errors   ',
				'GPRINT:avg_rpcerror_permin:AVERAGE:avg\: %5.2lf rpc errors/min   ',
				'GPRINT:max_rpcerror_permin:MAX:max\: %4.0lf rpc errors/min\\l',

				'COMMENT:[%s]\\r' % date,
			)
		else:
			rrdtool.graph(str(graphImage),
				'--imgformat', 'PNG',
				'--width', str(self._rrdConfig['xPoints']),
				'--height', str(self._rrdConfig['yPoints']),
				'--start', str(start),
				'--end', str(end),
				'--vertical-label', '% / num / MByte*0.1',
				'--lower-limit', str(0),
				'--units-exponent', str(0), # don't show milli-messages/s
				'--slope-mode',
				'--color', 'SHADEA#ffffff',
				'--color', 'SHADEB#ffffff',
				'--color', 'BACK#ffffff',

				'DEF:avg_threads=%s:threads:AVERAGE' % str(self._rrdConfig['rrdFile']),
				'DEF:max_threads=%s:threads:MAX' % str(self._rrdConfig['rrdFile']),
				'LINE2:avg_threads#00dd00:Threads      ',
				'GPRINT:max_threads:LAST:cur\: %8.0lf threads      ',
				'GPRINT:avg_threads:AVERAGE:avg\: %8.2lf threads          ',
				'GPRINT:max_threads:MAX:max\: %8.0lf threads\\l',

				'DEF:avg_sess=%s:sessions:AVERAGE' % str(self._rrdConfig['rrdFile']),
				'DEF:max_sess=%s:sessions:MAX' % str(self._rrdConfig['rrdFile']),
				'CDEF:avg_sess_permin=avg_sess,60,*',
				'CDEF:max_sess_permin=max_sess,60,*',
				'VDEF:total_sess=avg_sess,TOTAL',
				'LINE2:avg_sess_permin#ff8000:Sessions     ',
				'GPRINT:max_sess:LAST:cur\: %8.0lf sessions     ',
				'GPRINT:avg_sess_permin:AVERAGE:avg\: %8.2lf sessions/min     ',
				'GPRINT:max_sess_permin:MAX:max\: %8.0lf sessions/min\\l',

				'DEF:avg_cpu=%s:cpu:AVERAGE' % str(self._rrdConfig['rrdFile']),
				'DEF:max_cpu=%s:cpu:MAX' % str(self._rrdConfig['rrdFile']),
				'LINE2:avg_cpu#dd0000:CPU usage    ',
				'GPRINT:max_cpu:LAST:cur\: %8.2lf %%            ',
				'GPRINT:avg_cpu:AVERAGE:avg\: %8.2lf %%                ',
				'GPRINT:max_cpu:MAX:max\: %8.2lf %%\\l',

				'DEF:avg_mem=%s:mem:AVERAGE' % str(self._rrdConfig['rrdFile']),
				'DEF:max_mem=%s:mem:MAX' % str(self._rrdConfig['rrdFile']),
				'CDEF:avg_mem_scaled=avg_mem,10,/',
				'LINE2:avg_mem_scaled#0000dd:MEM usage    ',
				'GPRINT:max_mem:LAST:cur\: %8.2lf MByte        ',
				'GPRINT:avg_mem:AVERAGE:avg\: %8.2lf MByte            ',
				'GPRINT:max_mem:MAX:max\: %8.2lf MByte\\l',

				'COMMENT:[%s]\\r' % date,
			)

		return graphImage

	def addSession(self, session):
		if not session:
			return

		self._rrdCache['sessions'] += 1

	def removeSession(self, session):
		if not session:
			return

		if self._rrdCache['sessions'] > 0:
			self._rrdCache['sessions'] -= 1

	def sessionExpired(self, session):
		now = time.time()
		self._expiredSessionInfo.append({
			"creationTime": session.created,
			"expirationTime": now,
			"exipredAfterSeconds": int(now - session.lastModified),
			"userAgent": session.userAgent,
			"lastRpcMethod": session.lastRpcMethod,
			"ip": session.ip,
			"user": session.user
		})

	def getExpiredSessionInfo(self):
		return self._expiredSessionInfo

	def addRequest(self, request):
		self._rrdCache['requests'] += 1

	def addWebDAVRequest(self, request):
		self._rrdCache['davrequests'] += 1

	def addRpc(self, jsonrpc):
		results = 0
		if not jsonrpc.exception:
			if isinstance(jsonrpc.result, (list, tuple, dict)):
				results = len(jsonrpc.result)

		methodName = jsonrpc.getMethodName()
		duration = jsonrpc.ended - jsonrpc.started

		self._rpcs.append({
			'started': jsonrpc.started,
			'duration': duration,
			'method': methodName,
			'failed': bool(jsonrpc.exception),
			'params': len(jsonrpc.params),
			'results': results,
		})

		current = self._rpcStatistics[methodName]
		newCount = current.count + 1
		average = ((current.average * current.count) + duration) / newCount
		self._rpcStatistics[methodName] = CallStatistics(newCount, average)

		self._rrdCache['rpcs'] += 1
		if jsonrpc.exception:
			self._rrdCache['rpcerrors'] += 1
			logger.warning("Failed RPC on {name!r} with params {params!r}: {error}".format(name=methodName, params=jsonrpc.params, error=jsonrpc.exception))

	def getRpcs(self):
		return self._rpcs

	def getRPCCallCounts(self):
		return dict((name, rpcStat.count) for name, rpcStat in self._rpcStatistics.items())

	def getRPCAverageDurations(self):
		return dict((name, rpcStat.average) for name, rpcStat in self._rpcStatistics.items())

	def addEncodingError(self, what, client, application, error):
		self._encodingErrors.append({
			'what': forceUnicode(what),
			'client': forceUnicode(client),
			'application': forceUnicode(application),
			'error': forceUnicode(error),
			'when': datetime.datetime.now(),
		})

	def getEncodingErrors(self):
		return self._encodingErrors
