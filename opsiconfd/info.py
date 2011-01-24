#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
   = = = = = = = = = = = = = = = = =
   =   opsi configuration daemon   =
   = = = = = = = = = = = = = = = = =

   opsiconfd is part of the desktop management solution opsi
   (open pc server integration) http://www.opsi.org

   Copyright (C) 2010 uib GmbH

   http://www.uib.de/

   All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

   @copyright:  uib GmbH <info@uib.de>
   @author: Jan Schneider <j.schneider@uib.de>
   @license: GNU General Public License version 2
"""

import operator

from OPSI.web2 import responsecode, http, stream
from OPSI.System import getDiskSpaceUsage
from OPSI.Logger import *

from resources import ResourceOpsiconfd
from workers import WorkerOpsiconfd

logger = Logger()

infoPage = u'''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<title>opsiconfd info</title>
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
	</style>
</head>
<body>
	<span id="title">
		<img src="/opsi_logo.png" />
		<span sytle="padding: 1px">opsiconfd info</span>
	</span>
	<div id="infos">
		<div id="info">%time%</div>
		<div id="info">%graphs%</div>
		<div id="info">%object_info%</div>
		<div id="info">%config_info%</div>
		<div id="info">%thread_info%</div>
		<div id="info">%session_info%</div>
		<div id="info">%disk_usage_info%</div>
		<div id="info">%rpc_statistic_info%</div>
	</div>
</body>
</html>
'''

class WorkerOpsiconfdInfo(WorkerOpsiconfd):
	def __init__(self, service, request, resource):
		WorkerOpsiconfd.__init__(self, service, request, resource)
	
	def _generateResponse(self, result):
		logger.info(u"Creating opsiconfd info page")
		
		if not self.session.isAdmin:
			raise OpsiAuthenticationError(u"Permission denied")
		
		graphs = u''
		if self.service.statistics().rrdsAvailable():
			graphs += u'<h1>Last hour</h1>'
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.service.statistics().getRrdGraphImage(1, 3600))
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.service.statistics().getRrdGraphImage(2, 3600))
			graphs += u'<h1>Last day</h1>'
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.service.statistics().getRrdGraphImage(1, 3600*24))
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.service.statistics().getRrdGraphImage(2, 3600*24))
			graphs += u'<h1>Last week</h1>'
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.service.statistics().getRrdGraphImage(1, 3600*24*7))
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.service.statistics().getRrdGraphImage(2, 3600*24*7))
			graphs += u'<h1>Last month</h1>'
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.service.statistics().getRrdGraphImage(1, 3600*24*31))
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.service.statistics().getRrdGraphImage(2, 3600*24*31))
			graphs += u'<h1>Last year</h1>'
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.service.statistics().getRrdGraphImage(1, 3600*24*365))
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.service.statistics().getRrdGraphImage(2, 3600*24*365))
		
		objectInfo  = u'<h1>Object info</h1>'
		objectInfo += u'<table>'
		objectInfo += u'<tr><th>type</th><th>number</th></tr>'
		objectInfo += u'<tr><td>Depotserver</td><td>%d</td></tr>' % len(self.service._backend.host_getIdents(returnType = 'unicode', type = 'OpsiDepotserver'))
		objectInfo += u'<tr><td>Client</td><td>%d</td></tr>' % len(self.service._backend.host_getIdents(returnType = 'unicode', type = 'OpsiClient'))
		objectInfo += u'<tr><td>Product</td><td>%d</td></tr>' % len(self.service._backend.product_getIdents(returnType = 'unicode'))
		objectInfo += u'<tr><td>Config</td><td>%d</td></tr>' % len(self.service._backend.config_getIdents(returnType = 'unicode'))
		objectInfo += u'</table>'
		
		configInfo  = u'<h1>Server config</h1>'
		configInfo += u'<table>'
		configInfo += u'<tr><th>key</th><th>value</th></tr>'
		keys = self.service.config.keys()
		keys.sort()
		for key in keys:
			if key in ('staticDirectories',):
				continue
			configInfo += u'<tr><td>%s</td><td>%s</td></tr>' % (key, self.service.config[key])
		configInfo += u'</table>'
		
		threads = []
		for thread in threading.enumerate():
			threads.append(thread)
		threadInfo  = u'<h1>Running threads (%d)</h1>' % len(threads)
		threadInfo += u'<table>'
		threadInfo += u'<tr><th>class</th><th>name</th><th>ident</th><th>alive</th></tr>'
		for thread in threads:
			threadName = u''
			try:
				threadName = thread.name
			except:
				pass
			threadIdent = u''
			try:
				threadIdent = thread.ident
			except:
				pass
			threadInfo += u'<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (thread.__class__.__name__, threadName, threadIdent, thread.isAlive())
		threadInfo += u'</table>'
		
		sessions = self.service._getSessionHandler().getSessions()
		sessionInfo  = u'<h1>Active sessions (%d)</h1>' % len(sessions.keys())
		sessionInfo += u'<table>'
		sessionInfo += u'<tr><th>created</th><th>last modified</th><th>validity</th><th>marked for deletion</th><th>ip</th><th>hostname</th><th>user</th>' + \
		               u'<th>is host</th><th>usage count</th><th>application</th><th>last rpc decoded</th><th>last rpc method</th></tr>'
		for session in sessions.values():
			sessionInfo += u'<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' \
				% (time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session.created)), time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session.lastModified)), \
					session.getValidity(), session.getMarkedForDeletion(), \
					session.ip, session.hostname, session.user, session.isHost, session.usageCount, session.userAgent, \
					session.lastRpcSuccessfullyDecoded, session.lastRpcMethod)
		sessionInfo += u'</table>'
		
		
		diskUsageInfo  = u'<h1>Disk usage</h1>'
		diskUsageInfo += u'<table>'
		diskUsageInfo += u'<tr><th>resource</th><th>path</th><th>capacity</th><th>used</th><th>available</th><th>usage</th></tr>'
		resources = self.service.config['staticDirectories'].keys()
		resources.sort()
		for resource in resources:
			path = self.service.config['staticDirectories'][resource]['path']
			if os.path.isdir(path):
				if not resource.startswith('/'): resource = u'/' + resource
				info = getDiskSpaceUsage(path)
				diskUsageInfo += u'<tr><td><a href="%s">%s</a></td><td>%s</td><td>%0.2f GB</td><td>%0.2f GB</td><td>%0.2f GB</td><td>%0.2f %%</td></tr>' \
					% (resource, resource, path, (float(info['capacity'])/1073741824), (float(info['used'])/1073741824), (float(info['available'])/1073741824), (info['usage']*100))
		diskUsageInfo += u'</table>'
		
		average = { 'params': 0.0, 'results': 0.0, 'duration': 0.0, 'failed': 0.0 }
		maxDuration = { 'duration': 0 }
		statisticInfo  = u'<h1>RPC statistics (last %d)</h1>' % self.service.config['maxExecutionStatisticValues']
		statisticInfo += u'<table>'
		statisticInfo += u'<tr><th>method</th><th>params</th><th>results</th><th>duration</th><th>success</th></tr>'
		rpcs = self.service.statistics().getRpcs()
		for statistic in sorted(rpcs, key=operator.itemgetter('method')):
			average['params']   += statistic['params']
			average['results']  += statistic['results']
			average['duration'] += statistic['duration']
			if statistic['failed']: average['failed'] += 1
			if (statistic['duration'] > maxDuration['duration']):
				maxDuration['duration'] = statistic['duration']
				maxDuration['method']   = statistic['method']
				maxDuration['params']   = statistic['params']
				maxDuration['results']  = statistic['results']
				maxDuration['failed']   = statistic['failed']
			statisticInfo += u'<tr><td>%s</td><td>%d</td><td>%d</td><td>%0.3f s</td><td>%s</td></tr>' \
					% (statistic['method'], statistic['params'], statistic['results'], statistic['duration'], not statistic['failed'])
		if rpcs:
			statisticInfo += u'<tr><td colspan="5" style="border:none; text-align:left">average</td></tr>'
			statisticInfo += u'<tr><td></td><td>%0.0f</td><td>%0.0f</td><td>%0.3f s</td><td>%0.2f %%</td></tr>' \
					% (average['params']/len(rpcs), average['results']/len(rpcs), average['duration']/len(rpcs), ((len(rpcs)-average['failed'])/len(rpcs))*100)
			statisticInfo += u'<tr><td colspan="5" style="border:none; text-align:left">max duration</td></tr>'
			statisticInfo += u'<tr><td>%s</td><td>%d</td><td>%d</td><td>%0.3f s</td><td>%s</td></tr>' \
					% (maxDuration['method'], maxDuration['params'], maxDuration['results'], maxDuration['duration'], not maxDuration['failed'])
		statisticInfo += u'</table>'
		
		statisticInfo += u'<br />'
		
		statisticInfo += u'<h1>Encoding error statistics</h1>'
		statisticInfo += u'<table>'
		statisticInfo += u'<tr><th>application</th><th>what</th><th>client</th><th>error</th></tr>'
		for statistic in sorted(self.service.statistics().getEncodingErrors(), key=operator.itemgetter('application')):
			statisticInfo += u'<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' \
					% (statistic['application'], statistic['what'], statistic['client'], statistic['error'])
		statisticInfo += u'</table>'
		
		statisticInfo += u'<br />'
		
		statisticInfo += u'<h1>Authentication failures</h1>'
		statisticInfo += u'<table>'
		statisticInfo += u'<tr><th>ip address</th><th>count</th></tr>'
		for (ipAddress, count) in self.service.authFailureCount.items():
			if (count > self.service.config['maxAuthenticationFailures']):
				statisticInfo += u'<tr><td>%s</td><td>%d</td></tr>' % (ipAddress, count)
		statisticInfo += u'</table>'
		
		html = infoPage.replace('%time%', time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()))
		html = html.replace('%graphs%', graphs)
		html = html.replace('%object_info%', objectInfo)
		html = html.replace('%config_info%', configInfo)
		html = html.replace('%thread_info%', threadInfo)
		html = html.replace('%session_info%', sessionInfo)
		html = html.replace('%disk_usage_info%', diskUsageInfo)
		html = html.replace('%rpc_statistic_info%', statisticInfo)
		
		if not isinstance(result, http.Response):
			result = http.Response()
		result.code = responsecode.OK
		result.stream = stream.IByteStream(html.encode('utf-8').strip())
		return result

class ResourceOpsiconfdInfo(ResourceOpsiconfd):
	WorkerClass = WorkerOpsiconfdInfo
	
	def __init__(self, service):
		ResourceOpsiconfd.__init__(self, service)



