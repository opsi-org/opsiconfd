# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi
# (open pc server integration) http://www.opsi.org

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
opsi configuration daemon - info page

.. versionchanged:: 4.0.5


.. versionchanged:: 4.0.6

	Extended info page.


:copyright:  uib GmbH <info@uib.de>
:author: Jan Schneider <j.schneider@uib.de>
:author: Niko Wenselowski <n.wenselowski@uib.de>
:license: GNU Affero General Public License version 3
"""

from __future__ import absolute_import

import cgi
import heapq
import os
import operator
import threading
import time
from datetime import datetime

from OPSI import __version__ as pythonOpsiVersion
from OPSI.Exceptions import OpsiAuthenticationError
from OPSI.Logger import Logger
from OPSI.System import getDiskSpaceUsage
from OPSI.Types import forceUnicode
from OPSI.web2 import responsecode, http, stream

from . import __version__ as opsiconfdVersion
from .resources import ResourceOpsiconfd
from .workers import WorkerOpsiconfd

LOGGER = Logger()

_GRAPH_MAPPING = (
	('hour', 3600),
	('day', 86400),  # 3600 * 24
	('week', 604800),  # 3600 * 24 * 7
	('month', 2678400),  # 3600 * 24 * 31
	('year', 31536000),  # 3600 * 24 * 365
)

PAGE_TEMPLATE = u'''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<title>opsiconfd info</title>
	{css}
</head>
<body>
	<span id="title">
		<img src="/opsi_logo.png" /><br /><br />
		<span sytle="padding: 1px">opsiconfd info</span>
	</span>
	<div id="infos">
		{content}
	</div>
</body>
</html>
'''

CSS = """\
	<style>
	a:link 	  { color: #555555; text-decoration: none; }
	a:visited { color: #555555; text-decoration: none; }
	a:hover	  { color: #46547f; text-decoration: none; }
	a:active  { color: #555555; text-decoration: none; }
	body      { font-family: verdana, arial; font-size: 12px; }
	#title    { padding: 10px; color: #6276a0; font-size: 20px; letter-spacing: 5px; }
	#infos    { padding: 50px; color: #555555; font-size: 14px; }
	#info     { padding-bottom: 20px }
	h1        { font-size: 14px; font-weight; bold; letter-spacing: 2px; }
	table     { table-layout: auto; background-color: #fafafa; }
	td, th    { font-size: 12px; border: 1px #6276a0 solid; text-align: left; padding: 2px 10px 2px 10px; }
	th        { color: #eeeeee; background-color: #6276a0; }
	</style>\
"""


class WorkerOpsiconfdInfo(WorkerOpsiconfd):
	def __init__(self, service, request, resource):
		WorkerOpsiconfd.__init__(self, service, request, resource)

	def _generateResponse(self, result):
		LOGGER.info(u"Creating opsiconfd info page")

		if not self.session.isAdmin:
			raise OpsiAuthenticationError(u"Permission denied")

		startDatetime = datetime.now()
		content = [
			info.join(('<div id="info">', '</div>')) for info in (
				str(startDatetime),
				self.getGraphs(),
				self.getObjectInfo(),
				self.getConfigInfo(),
				self.getThreadInfo(),
				self.getSessionInfo(),
				self.getExpiredSessionInfo(),
				self.getUserAgents(),
				self.getDiskUsageInfo(),
				self.getStatisticsInfo(),
			)
		]
		content.append('<!-- Rendered info page in {0} seconds -->'.format(datetime.now() - startDatetime))

		html = PAGE_TEMPLATE.format(content='\n'.join(content), css=CSS)
		LOGGER.debug('Total render time for info page: {0} seconds'.format(datetime.now() - startDatetime))

		if not isinstance(result, http.Response):
			result = http.Response()
		result.code = responsecode.OK
		result.stream = stream.IByteStream(html.encode('utf-8').strip())
		return result

	def _processQuery(self, result):
		if self.query.startswith('objgraph'):
			maxDepth = 10
			if '=' in self.query:
				maxDepth = int(self.query.split('=')[1])
			self.service.statistics().createObjectGraph(maxDepth)
		return result

	def getGraphs(self):
		def getGraphCode():
			if self.service.statistics().rrdsAvailable():
				for term, duration in _GRAPH_MAPPING:
					yield u'<h1>Last {0}</h1>'.format(term)
					for imageType in (1, 2):
						yield u'<img src="/rrd/%s" />' % os.path.basename(self.service.statistics().getRrdGraphImage(imageType, duration))

		return ''.join(getGraphCode())

	def getObjectInfo(self):
		def getObjectInfoHTML():
			yield u'<h1>Object info</h1>'
			yield u'<table>'
			yield self.createTableHeader('type', 'number')
			yield self.createTableRow('Depotserver', len(self.service._backend.host_getIdents(returnType='unicode', type='OpsiDepotserver')))
			yield self.createTableRow('Client', len(self.service._backend.host_getIdents(returnType='unicode', type='OpsiClient')))
			yield self.createTableRow('Product', len(self.service._backend.product_getIdents(returnType='unicode')))
			yield self.createTableRow('Config', len(self.service._backend.config_getIdents(returnType='unicode')))
			yield u'</table>'

		return ''.join(getObjectInfoHTML())

	@staticmethod
	def createTableHeader(*header):
		def createHeader():
			yield u'<tr>'
			for term in header:
				yield u'<th>'
				yield term
				yield u'</th>'
			yield u'</tr>'

		return ''.join(createHeader())

	@staticmethod
	def createTableRow(*values):
		def createRow():
			yield u'<tr>'
			for value in values:
				yield u'<td>'
				yield forceUnicode(value)
				yield u'</td>'
			yield u'</tr>'

		return ''.join(createRow())

	def getConfigInfo(self):
		def getConfigHTML():
			yield u'<h1>Server config</h1>'
			yield u'<table>'
			yield self.createTableHeader('key', 'value')
			for key in sorted(self.service.config):
				if key == 'staticDirectories':
					continue
				yield self.createTableRow(key, self.service.config[key])

			try:
				yield self.createTableRow(
					"uptime",
					str(datetime.now() - self.service.config['startTime'])
				)
			except KeyError:
				# For when no startTime is found.
				pass

			yield self.createTableRow("opsiconfd version", opsiconfdVersion)
			yield self.createTableRow("python-opsi version", pythonOpsiVersion)
			yield u'</table>'

		return ''.join(getConfigHTML())

	def getThreadInfo(self):
		def getReadableTime(timeObject):
			return time.strftime("%d %b %Y %H:%M:%S", time.gmtime(timeObject))

		def getAdditionalInfo(thread):
			try:
				yield 'Started at: {0}'.format(getReadableTime(thread.started))

				if thread.ended:
					yield 'Ended at: {0}'.format(getReadableTime(thread.ended))
			except AttributeError:
				pass

			try:
				yield 'HostID: {0}'.format(thread.hostId)
			except AttributeError:
				pass

			try:
				yield 'Address: {0}'.format(thread.address)
			except AttributeError:
				pass

			try:
				yield 'Connection: {0}'.format(thread.jsonrpcBackend)
			except AttributeError:
				pass

			try:
				yield 'Method: {0}'.format(thread.method)
				yield 'Parameters: {0}'.format(thread.params)
			except AttributeError:
				pass

		def getThreadInfoHTML():
			threads = [thread for thread in threading.enumerate()]

			yield u'<h1>Running threads ({0:d})</h1>'.format(len(threads))
			yield u'<table>'
			yield self.createTableHeader('class', 'name', 'ident', 'alive', 'additional information')

			for thread in threads:
				try:
					threadName = thread.name
				except Exception:
					threadName = u''

				try:
					threadIdent = thread.ident
				except Exception:
					threadIdent = u''

				yield self.createTableRow(
					thread.__class__.__name__, threadName, threadIdent,
					thread.isAlive(),
					', '.join(cgi.escape(i) for i in getAdditionalInfo(thread))
				)
			yield u'</table>'

		return ''.join(getThreadInfoHTML())

	def getSessionInfo(self):
		sessions = self.service._getSessionHandler().getSessions()
		sessionInfo = [u'<h1>Active sessions (%d)</h1>' % len(sessions)]
		sessionInfo.append(u'<table>')
		sessionInfo.append(
			self.createTableHeader(
				'created', 'last modified', 'validity', 'marked for deletion',
				'ip', 'hostname', 'user', 'is host', 'usage count',
				'application', 'last rpc decoded', 'last rpc method'
			)
		)

		for session in sessions.values():
			sessionInfo.append(
				self.createTableRow(
					time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session.created)),
					time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session.lastModified)),
					session.getValidity(), session.getMarkedForDeletion(),
					session.ip, session.hostname, session.user, session.isHost,
					session.usageCount, session.userAgent,
					session.lastRpcSuccessfullyDecoded, session.lastRpcMethod
				)
			)
		sessionInfo.append(u'</table>')

		return ''.join(sessionInfo)

	def getExpiredSessionInfo(self):
		expiredSessions = self.service.statistics().getExpiredSessionInfo()
		expiredSessionInfo = [u'<h1>Expired sessions (%d)</h1>' % len(expiredSessions)]
		expiredSessionInfo.append(u'<table>')
		expiredSessionInfo.append(
			self.createTableHeader(
				'created', 'expired', 'timed out after', 'ip', 'user',
				'user agent', 'last rpc method'
			)
		)

		for expiredSession in expiredSessions:
			expiredSessionInfo.append(
				self.createTableRow(
					time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expiredSession['creationTime'])),
					time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expiredSession['expirationTime'])),
					'{0} secs'.format(expiredSession['exipredAfterSeconds']),
					expiredSession['ip'],
					expiredSession['user'],
					cgi.escape(expiredSession['userAgent']),
					expiredSession['lastRpcMethod']
				)
			)
		expiredSessionInfo.append(u'</table>')

		return ''.join(expiredSessionInfo)

	def getUserAgents(self):
		userAgentsInfo = [u'<h1>Seen useragents</h1>', u'<table>']
		userAgentsInfo.append(
			self.createTableHeader(
				'Useragent', 'requests'
			)
		)

		userAgentsAndCount = self.service.statistics().getUserAgents()
		for userAgent, count in sorted(userAgentsAndCount.items(), key=lambda x: x[0].upper()):
			userAgentsInfo.append(u'<tr><td>{agent}</td><td>{requests}</td></tr>'.format(agent=cgi.escape(userAgent), requests=count))

		userAgentsInfo.append(u'</table>')

		return ''.join(userAgentsInfo)

	def getDiskUsageInfo(self):
		diskUsageInfo = [u'<h1>Disk usage</h1>', u'<table>']
		diskUsageInfo.append(
			self.createTableHeader(
				'resource', 'path', 'capacity', 'used', 'available', 'usage'
			)
		)

		for resource in sorted(self.service.config['staticDirectories']):
			path = self.service.config['staticDirectories'][resource]['path']
			if os.path.isdir(path):
				if not resource.startswith('/'):
					resource = u'/{0}'.format(resource)

				info = getDiskSpaceUsage(path)

				diskUsageInfo.append(
					self.createTableRow(
						u'<a href="{0}">{0}</a>'.format(resource),
						path,
						u'{0:0.2f} GB'.format(float(info['capacity']) / 1073741824),
						u'{0:0.2f} GB'.format(float(info['used']) / 1073741824),
						u'{0:0.2f} GB'.format(float(info['available']) / 1073741824),
						u'{0:0.2f} %'.format(info['usage'] * 100),
					)
				)
		diskUsageInfo.append(u'</table>')

		return ''.join(diskUsageInfo)

	def getStatisticsInfo(self):
		statisticInfo = [u'<h1>RPC statistics (last {0:d})</h1>'.format(self.service.config['maxExecutionStatisticValues'])]
		statisticInfo.append(u'<table>')
		statisticInfo.append(
			self.createTableHeader(
				'method', 'params', 'results', 'duration', 'success'
			)
		)
		rpcs = self.service.statistics().getRpcs()
		if rpcs:
			average = {
				'params': 0,
				'results': 0,
				'duration': 0.0,
				'failed': 0
			}
			maxDuration = {'duration': 0}

			def uppercaseGetter(field):
				"Returns the value for `field` in uppercase."
				def getUppercaseField(obj):
					return obj[field].upper()
				return getUppercaseField

			for statistic in sorted(rpcs, key=uppercaseGetter('method')):
				for key in ('params', 'results', 'duration'):
					average[key] += statistic[key]

				if statistic['failed']:
					average['failed'] += 1

				if statistic['duration'] > maxDuration['duration']:
					for key in ('duration', 'method', 'params', 'results', 'failed'):
						maxDuration[key] = statistic[key]

				statisticInfo.append(
					self.createTableRow(
						statistic['method'],
						statistic['params'],
						statistic['results'],
						'{0:0.3f} s'.format(statistic['duration']),
						not statistic['failed']
					)
				)

			overallResults = len(rpcs)
			statisticInfo.append(u'<tr><td colspan="5" style="border:none; text-align:left">average</td></tr>')
			statisticInfo.append(
				self.createTableRow(
					'',
					'{0:0.0f}'.format(average['params'] / overallResults),
					'{0:0.0f}'.format(average['results'] / overallResults),
					'{0:0.3f}s'.format(average['duration'] / overallResults),
					'{0:0.2f}%'.format(((overallResults - average['failed']) / float(overallResults)) * 100)
				)
			)
			statisticInfo.append(u'<tr><td colspan="5" style="border:none; text-align:left">max duration</td></tr>')
			statisticInfo.append(
				self.createTableRow(
					maxDuration['method'],
					maxDuration['params'],
					maxDuration['results'],
					'{0:0.3f}s'.format(maxDuration['duration']),
					not maxDuration['failed']
				)
			)
		statisticInfo.append(u'</table>')

		statisticInfo.append(u'<br />')
		statisticInfo.append(self.getMostCalledFunctions())
		statisticInfo.append(u'<br />')
		statisticInfo.append(self.getEncodingErrorStatistics())
		statisticInfo.append(u'<br />')
		statisticInfo.append(self.getAuthenticationFailures())

		return ''.join(statisticInfo)

	def getMostCalledFunctions(self):
		numberOfFunctions = 15
		statisticInfo = [
			u'<h1>{0:d} most called RPCs</h1>'.format(numberOfFunctions),
			u'<table>',
			self.createTableHeader('', 'method', 'count', 'average')
		]

		callStatistics = self.service.statistics().getRPCCallCounts()
		callAverages = self.service.statistics().getRPCAverageDurations()
		for (index, key) in enumerate(heapq.nlargest(numberOfFunctions, callStatistics, key=callStatistics.get), start=1):
			statisticInfo.append(
				self.createTableRow(
					'{0:d}.'.format(index),
					key,
					str(callStatistics[key]),
					'{0:0.3f}s'.format(callAverages[key])
				)
			)

		statisticInfo.append(u'''<tr><td colspan="2" style="text-align:left">
Total number of calls:</td><td>{0}</td></tr>'''.format(sum(callStatistics.values())))

		statisticInfo.append('</table>')
		return ''.join(statisticInfo)

	def getEncodingErrorStatistics(self):
		wantedKeys = ('when', 'application', 'what', 'client', 'error')

		statisticInfo = [u'<h1>Encoding error statistics</h1>', u'<table>']
		statisticInfo.append(
			self.createTableHeader(*[key for key in wantedKeys])
		)

		for statistic in sorted(self.service.statistics().getEncodingErrors(), key=operator.itemgetter('when')):
			statisticInfo.append(
				self.createTableRow(
					*[statistic[key] for key in wantedKeys]
				)
			)

		statisticInfo.append(u'</table>')

		return ''.join(statisticInfo)

	def getAuthenticationFailures(self):
		statisticInfo = [u'<h1>Authentication failures</h1>', u'<table>']
		statisticInfo.append(self.createTableHeader('ip address', 'count'))
		for (ipAddress, count) in self.service.authFailureCount.items():
			if count > self.service.config['maxAuthenticationFailures']:
				statisticInfo.append(self.createTableRow(ipAddress, count))
		statisticInfo.append(u'</table>')

		return ''.join(statisticInfo)


class ResourceOpsiconfdInfo(ResourceOpsiconfd):
	WorkerClass = WorkerOpsiconfdInfo

	def __init__(self, service):
		ResourceOpsiconfd.__init__(self, service)
