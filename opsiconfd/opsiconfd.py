#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
   = = = = = = = = = = = = = = = = = = = = = = =
   =   opsi configuration daemon (opsiconfd)   =
   = = = = = = = = = = = = = = = = = = = = = = =
   
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
   
   @copyright:	uib GmbH <info@uib.de>
   @author: Jan Schneider <j.schneider@uib.de>
   @license: GNU General Public License version 2
"""

__version__ = "4.0.0.1"

# Imports
import os, sys, getopt, threading, time, socket, base64, urllib, operator, types, zlib
try:
	import rrdtool
except:
	rrdtool = None
try:
	import dbus
except:
	dbus = None
try:
	import avahi
except:
	avahi = None

import resource as pyresource
from OpenSSL import SSL
from signal import *
from ctypes import *

# Twisted imports
from twisted.internet import epollreactor
epollreactor.install()
#from twisted.internet import pollreactor
#pollreactor.install()
#from twisted.internet import selectreactor
#selectreactor.install()
from twisted.internet import defer, threads, reactor
from twisted.internet.task import LoopingCall
from twisted.python.failure import Failure
from twisted.python import log
from OPSI.web2 import resource, stream, server, http, responsecode, http_headers
from OPSI.web2.channel.http import HTTPFactory
import OPSI.web2.dav.static
import OPSI.web2.static

# OPSI imports
from OPSI.Logger import *
from OPSI.Util import timestamp, objectToHtml, randomString, toJson, fromJson
from OPSI.Util.File import IniFile
from OPSI.Types import *
from OPSI.System import which, execute, getDiskSpaceUsage
from OPSI.Backend.BackendManager import BackendManager, BackendAccessControl
from OPSI.Object import BaseObject, serialize, deserialize

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

interfacePage = u'''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<title>opsi config interface</title>
	<style>
	a:link 	      { color: #555555; text-decoration: none; }
	a:visited     { color: #555555; text-decoration: none; }
	a:hover	      { color: #46547f; text-decoration: none; }
	a:active      { color: #555555; text-decoration: none; }
	body          { font-family: verdana, arial; font-size: 12px; }
	#title        { padding: 10px; color: #6276a0; font-size: 20px; letter-spacing: 5px; }
	input, select { background-color: #fafafa; border: 1px #abb1ef solid; width: 430px; font-family: verdana, arial; }
	.json         { color: #555555; width: 95%; float: left; clear: both; margin: 30px; padding: 20px; background-color: #fafafa; border: 1px #abb1ef dashed; font-size: 11px; }
	.json_key     { color: #9e445a; }
	.json_label   { color: #abb1ef; margin-top: 20px; margin-bottom: 5px; font-size: 11px; }
	.title        { color: #555555; font-size: 20px; font-weight: bolder; letter-spacing: 5px; }
	.button       { color: #9e445a; background-color: #fafafa; border: none; margin-top: 20px; font-weight: bolder; }
	.box          { background-color: #fafafa; border: 1px #555555 solid; padding: 20px; margin-left: 30px; margin-top: 50px;}
	</style>
	<script type="text/javascript">
	<![CDATA[
		var path = 'interface';
		var parameters = new Array();
		var method = '';
		var params = '';
		var id = '"id": 1';
		%javascript%
		
		function createElement(element) {
			if (typeof document.createElementNS != 'undefined') {
				return document.createElementNS('http://www.w3.org/1999/xhtml', element);
			}
			if (typeof document.createElement != 'undefined') {
				return document.createElement(element);
			}
			return false;
		}
		
		function selectPath(select) {
			path = select.value;
			document.getElementById('json_method').firstChild.data = '"backend_getInterface"';
			document.getElementById('json_params').firstChild.data = '[]';
			onSubmit();
		}
		function selectMethod(select) {
			method = select.value;
			tbody = document.getElementById('tbody');
			var button;
			var json;
			for (i=tbody.childNodes.length-1; i>=0; i--) {
				if (tbody.childNodes[i].id == 'tr_path') {
				}
				else if (tbody.childNodes[i].id == 'tr_method') {
				}
				else if (tbody.childNodes[i].id == 'tr_submit') {
					button = tbody.childNodes[i];
					tbody.removeChild(button);
				}
				else if (tbody.childNodes[i].id == 'tr_json') {
					json = tbody.childNodes[i];
					tbody.removeChild(json);
				}
				else {
					tbody.removeChild(tbody.childNodes[i]);
				}
			}
			
			for (i=0; i < parameters[select.value].length; i++) {
				tr = createElement("tr");
				td1 = createElement("td");
				text = document.createTextNode(parameters[select.value][i] + ":");
				td1.appendChild(text);
				td2 = createElement("td");
				input = createElement("input");
				input.setAttribute('onchange', 'jsonString()');
				input.setAttribute('type', 'text');
				if ((method == currentMethod) && (currentParams[i] != null)) {
					input.value = currentParams[i];
				}
				td2.appendChild(input);
				tr.appendChild(td1);
				tr.appendChild(td2);
				tbody.appendChild(tr)
			}
			tbody.appendChild(json)
			tbody.appendChild(button)
			
			jsonString();
		}
		
		function onSubmit() {
			var json = '{ "id": 1, "method": ';
			json += document.getElementById('json_method').firstChild.data;
			json += ', "params": ';
			json += document.getElementById('json_params').firstChild.data;
			json += ' }';
			window.location.href = '/' + path + '?' + json;
			return false;
		}
		
		function jsonString() {
			span = document.getElementById('json_method');
			for (i=span.childNodes.length-1; i>=0; i--) {
				span.removeChild(span.childNodes[i])
			}
			span.appendChild(document.createTextNode('"' + method + '"'));
			
			span = document.getElementById('json_params');
			for (i=span.childNodes.length-1; i>=0; i--) {
				span.removeChild(span.childNodes[i])
			}
			params = '['
			inputs = document.getElementsByTagName('input');
			for (i=0; i<inputs.length; i++) {
				if (inputs[i].id != 'submit') {
					if (inputs[i].value == '') {
						i = inputs.length;
					}
					else {
						if (i>0) {
							params += ', ';
						}
						params += inputs[i].value.replace(/\\\/g, '\\\\\\\\');
					}
				}
			}
			span.appendChild(document.createTextNode(params + ']'));
		}
	]]>
	</script>
</head>
<body onload="selectMethod(document.getElementById('method_select'))">
	<span id="title">
		<img src="/opsi_logo.png" />
		<span sytle="padding: 1px">opsi config interface</span>
	</span>
	<form method="post" onsubmit="return onSubmit()">
		<table class="box">
			<tbody id="tbody">
				<tr id="tr_path">
					<td style="width: 150px;">Path:</td>
					<td style="width: 440px;">
						<select id="path_select" onchange="selectPath(this)" name="path">
							%select_path%
						</select>
					</td>
				</tr>
				<tr id="tr_method">
					<td style="width: 150px;">Method:</td>
					<td style="width: 440px;">
						<select id="method_select" onchange="selectMethod(this)" name="method">
							%select_method%
						</select>
					</td>
				</tr>
				<tr id="tr_json">
					<td colspan="2">
						<div class="json_label">
							resulting json remote procedure call:
						</div>
						<div class="json" style="width: 480px;">
							{&nbsp;"<font class="json_key">method</font>": <span id="json_method"></span>,<br />
							&nbsp;&nbsp;&nbsp;"<font class="json_key">params</font>": <span id="json_params">[]</span>,<br />
							&nbsp;&nbsp;&nbsp;"<font class="json_key">id</font>": 1 }
						</div>
					</td>
				</tr>
				<tr id="tr_submit">
					<td align="center" colspan="2">
						<input value="Execute" id="submit" class="button" type="submit" />
					</td>
				</tr>
			</tbody>
		</table>
	</form>
	<div class="json_label" style="padding-left: 30px">json-rpc result</div>
	%result%
</body>
</html>
'''


# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
# =                                        CLASS WORKER                                               =
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
class Worker:
	def __init__(self, opsiconfd, request, resource):
		self.opsiconfd = opsiconfd
		self.request   = request
		self.query     = u''
		self.resource  = resource
		self.session   = None
		self._setLogFile(self)
	
	def process(self):
		logger.info("Worker %s started processing" % self)
		deferred = defer.Deferred()
		deferred.addCallback(self._getSession)
		deferred.addCallback(self._linkLogFile)
		deferred.addCallback(self._authenticate)
		deferred.addCallback(self._createBackend)
		deferred.addCallback(self._getQuery)
		deferred.addCallback(self._decodeQuery)
		deferred.addCallback(self._setResponse)
		deferred.addCallback(self._setCookie)
		deferred.addCallback(self._freeSession)
		deferred.addErrback(self._errback)
		deferred.callback(None)
		return deferred
	
	def _errback(self, failure):
		logger.debug2("%s._errback" % self.__class__.__name__)
		
		self._freeSession(failure)
		
		result = self._renderError(failure)
		result.code = responsecode.INTERNAL_SERVER_ERROR
		result = self._setCookie(result)
		try:
			failure.raiseException()
		except AttributeError, e:
			logger.debug(e)
			result = http.Response()
			result.code = responsecode.NOT_FOUND
		except OpsiAuthenticationError, e:
			logger.error(e)
			result.code = responsecode.UNAUTHORIZED
			result.headers.setHeader('www-authenticate', [('basic', { 'realm': 'OPSI Configuration Service' } )])
			if self.request.remoteAddr.host not in (self.opsiconfd.config['ipAddress'], '127.0.0.1'):
				if (self.opsiconfd.config['maxAuthenticationFailures'] > 0):
					if not self.opsiconfd.authFailureCount.has_key(self.request.remoteAddr.host):
						self.opsiconfd.authFailureCount[self.request.remoteAddr.host] = 0
					self.opsiconfd.authFailureCount[self.request.remoteAddr.host] += 1
					if (self.opsiconfd.authFailureCount[self.request.remoteAddr.host] > self.opsiconfd.config['maxAuthenticationFailures']):
						logger.error("%s authentication failures from '%s' in a row, waiting 60 seconds to prevent flooding" \
								% (self.opsiconfd.authFailureCount[self.request.remoteAddr.host], self.request.remoteAddr.host))
						return self._delayResult(60, result)
					
		except OpsiBadRpcError, e:
			logger.error(e)
			result.code = responsecode.BAD_REQUEST
		except Exception, e:
			# logger.logException(e)
			logger.error(failure)
		
		return result
	
	def _delayResult(self, seconds, result):
		class DelayResult:
			def __init__(self, seconds, result):
				self.result = result
				self.deferred = defer.Deferred()
				reactor.callLater(seconds, self.returnResult)
				
			def returnResult(self):
				self.deferred.callback(self.result)
		return DelayResult(seconds, result).deferred
		
	def _renderError(self, failure):
		result = http.Response()
		result.headers.setHeader('content-type', http_headers.MimeType("text", "html", {"charset": "utf-8"}))
		error = u'Unknown error'
		try:
			failure.raiseException()
		except Exception, e:
			error = {'class': e.__class__.__name__, 'message': unicode(e)}
			error = toJson({"id": None, "result": None, "error": error})
		result.stream = stream.IByteStream(error.encode('utf-8'))
		return result
		
	def _setLogFile(self, obj):
		if self.opsiconfd.config['machineLogs'] and self.opsiconfd.config['logFile']:
			logger.setLogFile( self.opsiconfd.config['logFile'].replace('%m', self.request.remoteAddr.host), object = obj )
	
	def _linkLogFile(self, result):
		if self.session.hostname and self.opsiconfd.config['machineLogs'] and self.opsiconfd.config['logFile']:
			logger.linkLogFile( self.opsiconfd.config['logFile'].replace('%m', self.session.hostname), object = self )
		return result
		
	def _freeSession(self, result):
		if self.session:
			logger.debug(u"Freeing session %s" % self.session)
			self.session.decreaseUsageCount()
		return result
	
	def _getAuthorization(self):
		(user, password) = (u'', u'')
		logger.debug(u"Trying to get username and password from Authorization header")
		auth = self.request.headers.getHeader('Authorization')
		if auth:
			logger.debug(u"Authorization header found (type: %s)" % auth[0])
			try:
				encoded = auth[1]
				
				logger.confidential(u"Auth encoded: %s" % encoded)
				parts = unicode(base64.decodestring(encoded), 'latin-1').split(':')
				if (len(parts) > 6):
					user = u':'.join(parts[:6])
					password = u':'.join(parts[6:])
				else:
					user = parts[0]
					password = u':'.join(parts[1:])
				user = user.strip()
				logger.confidential(u"Client supplied username '%s' and password '%s'" % (user, password))
			except Exception, e:
				logger.error(u"Bad Authorization header from '%s': %s" % (self.request.remoteAddr.host, e))
		return (user, password)
		
	def _getSession(self, result):
		''' This method restores a session or generates a new one. '''
		self.session = None
		
		logger.confidential(u"Request headers: %s " % self.request.headers)
		
		# Get user agent
		userAgent = None
		try:
			userAgent = self.request.headers.getHeader('user-agent')
		except Exception, e:
			logger.info(u"Client '%s' did not supply user-agent" % self.request.remoteAddr.host)
		if not userAgent:
			userAgent = 'unknown'
		
		# Get session handler
		sessionHandler = self.opsiconfd.getSessionHandler()
		
		# Get authorization
		(user, password) = self._getAuthorization()
		
		# Get session id from cookie request header
		sessionId = u''
		try:
			for (k, v) in self.request.headers.getAllRawHeaders():
				if (k.lower() == 'cookie'):
					for cookie in v:
						for c in cookie.split(';'):
							if (c.find('=') == -1):
								continue
							(name, value) = c.split('=', 1)
							if (name.strip() == self.opsiconfd.config['sessionName']):
								sessionId = forceUnicode(value.strip())
								break
					break
		except Exception, e:
			logger.error(u"Failed to get cookie from header: %s" % e)
		
		if not sessionId:
			logger.notice(u"Application '%s' on client '%s' did not send cookie" % (userAgent, self.request.remoteAddr.host))
			if not password:
				raise OpsiAuthenticationError(u"Application '%s' on client '%s' did neither supply session id nor password" % (userAgent, self.request.remoteAddr.host))
		
		# Get Session object
		self.session = sessionHandler.getSession(sessionId, self.request.remoteAddr.host)
		if (sessionId == self.session.uid):
			logger.info(u"Reusing session for client '%s', application '%s'" % (self.request.remoteAddr.host, userAgent))
		elif sessionId:
			logger.notice(u"Application '%s' on client '%s' supplied non existing session id: %s" % (userAgent, self.request.remoteAddr.host, sessionId))
		
		if self.session.ip and (self.session.ip != self.request.remoteAddr.host):
			logger.critical(u"Client ip '%s' does not match session ip '%s', deleting old session and creating a new one" \
				% (self.request.remoteAddr.host, self.session.ip) )
			sessionHandler.deleteSession(self.session.uid)
			self.session = sessionHandler.getSession()
		
		# Set ip
		self.session.ip = self.request.remoteAddr.host
		
		# Set user-agent / application
		if self.session.userAgent and (self.session.userAgent != userAgent):
			logger.warning(u"Application changed from '%s' to '%s' for existing session of client '%s'" \
				% (self.session.userAgent, userAgent, self.request.remoteAddr.host))
		self.session.userAgent = userAgent
		
		logger.confidential(u"Session id is '%s' for client '%s', application '%s'" \
			% (self.session.uid, self.request.remoteAddr.host, self.session.userAgent))
		
		# Set user and password
		if not self.session.password:
			self.session.password = password
		
		if not self.session.user:
			if not user:
				logger.warning(u"No username from %s (application: %s)" % (self.session.ip, self.session.userAgent))
				try:
					(hostname, aliaslist, ipaddrlist) = socket.gethostbyaddr(self.session.ip)
					user = forceHostId(hostname)
				except Exception, e:
					raise Exception(u"No username given and resolve failed: %s" % e)
			
			if (user.count('.') >= 2):
				self.session.isHost = True
				if (user.find('_') != -1):
					user = user.replace('_', '-')
			elif re.search('^([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})$', user):
				self.session.isHost = True
				mac = forceHardwareAddress(user)
				logger.info(u"Found hardware address '%s' as username, searching host in backend" % mac)
				hosts = self.opsiconfd._backend.host_getObjects(hardwareAddress = mac)
				if not hosts:
					raise Exception(u"Host with hardware address '%s' found in backend" % mac)
				user = hosts[0].id
				logger.info(u"Hardware address '%s' found in backend, using '%s' as username" % (mac, user))
			
			if self.session.isHost:
				hosts = None
				try:
					hosts = self.opsiconfd._backend.host_getObjects(type = 'OpsiClient', id = forceHostId(user))
				except Exception, e:
					logger.debug(u"Host not found: %s" % e)
				
				if hosts:
					if self.session.password and hosts[0].getOneTimePassword() and (self.session.password == hosts[0].getOneTimePassword()):
						logger.info(u"Client '%s' supplied one-time password" % user)
						self.session.password = hosts[0].getOpsiHostKey()
						hosts[0].oneTimePassword = None
						self.opsiconfd._backend.host_createObjects(hosts[0])
			self.session.user = user
			
		# Set hostname
		if not self.session.hostname and self.session.isHost:
			logger.info(u"Storing hostname '%s' in session" % self.session.user)
			self.session.hostname = self.session.user
		
		logger.confidential(u"Session content: %s" % self.session.__dict__)
		return result
	
	def _setCookie(self, result):
		if not self.session:
			return result
		
		# Add cookie to headers
		cookie = http_headers.Cookie(self.session.name.encode('ascii', 'replace'), self.session.uid.encode('ascii', 'replace'), path='/')
		if not isinstance(result, http.Response):
			result = http.Response()
		result.headers.setHeader('set-cookie', [ cookie ] )
		return result
		
	def _authenticate(self, result):
		''' This function tries to authenticate a user.
		    Raises an exception on authentication failure. '''
		
		try:
			if self.session.authenticated:
				return result
			
			logger.notice(u"Authorization request from %s@%s (application: %s)" % (self.session.user, self.session.ip, self.session.userAgent))
			
			if not self.session.user:
				raise Exception(u"No username from %s (application: %s)" % (self.session.ip, self.session.userAgent))
				
			if not self.session.password:
				raise Exception(u"No password from %s (application: %s)" % (self.session.ip, self.session.userAgent))
				
			if self.session.hostname and self.opsiconfd.config['resolveVerifyIp'] and (self.session.user != self.opsiconfd.config['fqdn']):
				addressList = []
				try:
					(name, aliasList, addressList) = socket.gethostbyname_ex(self.session.hostname)
				except Exception, e:
					logger.warning(u"Failed to resolve hostname '%s': %s" % (self.session.hostname, e))
				
				if self.session.ip not in addressList:
					# Username (FQDN) of peer does not resolve to peer's ip address
					logger.critical(u"Host login attempt with username '%s'" % self.session.user +
							u" from ip '%s', but name resolves to '%s' (access denied)" % 
							( self.session.ip, addressList) )
					raise Exception(u"Access denied for username '%s' from '%s'" %
							(self.session.user, self.session.ip) )
			
			self._createBackend(result)
			
			self.session.authenticated = True
			if self.opsiconfd.authFailureCount.has_key(self.request.remoteAddr.host):
				del self.opsiconfd.authFailureCount[self.request.remoteAddr.host]
		except Exception, e:
			logger.logException(e, LOG_INFO)
			self._freeSession(result)
			self.opsiconfd.getSessionHandler().deleteSession(self.session.uid)
			raise OpsiAuthenticationError(u"Forbidden: %s" % e)
		return result
	
	def _getQuery(self, result):
		self.query = ''
		if   (self.request.method == 'GET'):
			self.query = urllib.unquote( self.request.querystring )
		elif (self.request.method == 'POST'):
			# Returning deferred needed for chaining
			d = stream.readStream(self.request.stream, self._handlePostData)
			d.addErrback(self._errback)
			return d
		else:
			raise ValueError(u"Unhandled method '%s'" % self.request.method)
		return result
		
	def _handlePostData(self, chunk):
		#logger.debug2(u"_handlePostData %s" % unicode(chunk, 'utf-8', 'replace'))
		self.query += chunk
		
	def _decodeQuery(self, result):
		try:
			if (self.request.method == 'POST'):
				contentType = self.request.headers.getHeader('content-type')
				logger.debug(u"Content-Type: %s" % contentType)
				if contentType and contentType.mediaType.startswith('gzip'):
					logger.debug(u"Expecting compressed data from client")
					self.query = zlib.decompress(self.query)
			self.query = unicode(self.query, 'utf-8')
		except (UnicodeError, UnicodeEncodeError), e:
			self.opsiconfd.statistics().addEncodingError('query', self.session.ip, self.session.userAgent, unicode(e))
			self.query = unicode(self.query, 'utf-8', 'replace')
		logger.debug2(u"query: %s" % self.query)
		return result
	
	def _createBackend(self, result):
		if self.session.backend and self.session.interface:
			if (len(self.session.postpath) == len(self.request.postpath)):
				postpathMatch = True
				for i in range(len(self.request.postpath)):
					if (self.request.postpath[i] != self.session.postpath[i]):
						postpathMatch = False
				if postpathMatch:
					return result
			self.session.interface = None
			self.session.backend.backend_exit()
		
		self.session.postpath = self.request.postpath
		if   (len(self.request.postpath) == 2) and (self.request.postpath[0] == 'backend'):
			self.session.backend = BackendManager(
				backend              = self.request.postpath[1],
				accessControlContext = self.opsiconfd._backend,
				backendConfigDir     = self.opsiconfd.config['backendConfigDir'],
				aclFile              = self.opsiconfd.config['aclFile'],
				username             = self.session.user,
				password             = self.session.password
			)
		elif (len(self.request.postpath) == 2) and (self.request.postpath[0] == 'extend'):
			extendPath = self.request.postpath[1]
			if not re.search('^[a-zA-Z0-9\_\-]+$', extendPath):
				raise ValueError(u"Extension config path '%s' refused" % extendPath)
			self.session.backend = BackendManager(
				dispatchConfigFile   = self.opsiconfd.config['dispatchConfigFile'],
				backendConfigDir     = self.opsiconfd.config['backendConfigDir'],
				extensionConfigDir   = os.path.join(self.opsiconfd.config['extensionConfigDir'], extendPath),
				aclFile              = self.opsiconfd.config['aclFile'],
				accessControlContext = self.opsiconfd._backend,
				depotBackend         = bool(self.opsiconfd.config['depotId']),
				hostControlBackend   = True,
				username             = self.session.user,
				password             = self.session.password
			)
		else:
			self.session.backend = BackendManager(
				dispatchConfigFile   = self.opsiconfd.config['dispatchConfigFile'],
				backendConfigDir     = self.opsiconfd.config['backendConfigDir'],
				extensionConfigDir   = self.opsiconfd.config['extensionConfigDir'],
				aclFile              = self.opsiconfd.config['aclFile'],
				accessControlContext = self.opsiconfd._backend,
				depotBackend         = bool(self.opsiconfd.config['depotId']),
				hostControlBackend   = True,
				username             = self.session.user,
				password             = self.session.password
			)
		logger.notice(u'Backend created: %s' % self.session.backend)
		
		self.session.interface = self.session.backend.backend_getInterface()
		self.session.isAdmin = self.session.backend.accessControl_userIsAdmin()
		
		if self.session.isHost:
			hosts = self.opsiconfd._backend.host_getObjects(['ipAddress', 'lastSeen'], id = self.session.user)
			if not hosts:
				raise Exception(u"Host '%s' not found in backend" % self.session.user)
			host = hosts[0]
			if (host.getType() == 'OpsiClient'):
				host.setLastSeen(timestamp())
				if self.opsiconfd.config['updateIpAddress'] and (host.ipAddress != self.session.ip) and (self.session.ip != '127.0.0.1'):
					host.setIpAddress(self.session.ip)
				else:
					# Value None on update means no change!
					host.ipAddress = None
				self.opsiconfd._backend.host_updateObjects(host)
		return result
		
	def _generateResponse(self, result):
		if not isinstance(result, http.Response):
			result = http.Response()
		result.code = responsecode.OK
		result.headers.setHeader('content-type', http_headers.MimeType("text", "html", {"charset": "utf-8"}))
		result.stream = stream.IByteStream("")
		return result
	
	def _setResponse(self, result):
		deferred = threads.deferToThread(self._generateResponse, result)
		return deferred
	
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
# =                                       CLASS JSON RPC                                              =
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
class JsonRpc(object):
	def __init__(self, worker, rpc):
		self._worker   = worker
		self.started   = None
		self.ended     = None
		self.type      = rpc.get('type')
		self.tid       = rpc.get('tid', rpc.get('id'))
		self.action    = rpc.get('action')
		self.method    = rpc.get('method')
		self.params    = rpc.get('params', rpc.get('data'))
		if not self.params:
			self.params = []
		self.result    = None
		self.exception = None
		self.traceback = None
		if not self.tid:
			raise Exception(u"No transaction id ((t)id) found in rpc")
		if not self.method:
			raise Exception(u"No method found in rpc")
	
	def isStarted(self):
		return bool(self.started)
	
	def hasEnded(self):
		return bool(self.ended)
	
	def getMethodName(self):
		if self.action:
			return u'%s_%s' % (self.action, self.method)
		return self.method
	
	def getDuration(self):
		if not self.started or not self.ended:
			return None
		return round(self.ended - self.started, 3)
		
	def execute(self, result=None):
		# Execute rpc
		self.result = None
		params = []
		for param in self.params:
			params.append(param)
		try:
			self.started = time.time()
			
			methodInterface = None
			for m in self._worker.session.interface:
				if (self.getMethodName() == m['name']):
					methodInterface = m
					break
			if not methodInterface:
				raise OpsiRpcError(u"Method '%s' is not valid" % self.getMethodName())
			
			keywords = {}
			if methodInterface['keywords']:
				l = 0
				if methodInterface['args']:
					l += len(methodInterface['args'])
				if methodInterface['varargs']:
					l += len(methodInterface['varargs'])
				if (len(params) >= l):
					if not type(params[-1]) is types.DictType:
						raise Exception(u"kwargs param is not a dict: %s" % params[-1])
					for (key, value) in params.pop(-1).items():
						keywords[str(key)] = deserialize(value)
			
			params = deserialize(params)
			
			pString = forceUnicode(params)[1:-1]
			if keywords:
				pString += u', ' + forceUnicode(keywords)
			if (len(pString) > 200):
				pString = pString[:200] + u'...'
			
			logger.notice(u"-----> Executing: %s(%s)" % (self.getMethodName(), pString))
			
			backend = self._worker.session.backend
			if keywords:
				self.result = eval( "backend.%s(*params, **keywords)" % self.getMethodName() )
			else:
				self.result = eval( "backend.%s(*params)" % self.getMethodName() )
			
			logger.info(u'Got result')
			logger.debug2(self.result)
		
		except Exception, e:
			logger.logException(e, LOG_INFO)
			logger.error(u'Execution error: %s' % forceUnicode(e))
			self.exception = e
			self.traceback = []
			tb = sys.exc_info()[2]
			while (tb != None):
				f = tb.tb_frame
				c = f.f_code
				self.traceback.append(u"     line %s in '%s' in file '%s'" % (tb.tb_lineno, c.co_name, c.co_filename))
				tb = tb.tb_next
		self.ended = time.time()
		self._worker.opsiconfd.statistics().addRpc(self)
		
	def getResponse(self):
		response = {}
		if (self.type == 'rpc'):
			response['tid']    = self.tid
			response['action'] = self.action
			response['method'] = self.method
			if self.exception:
				response['type']    = 'exception'
				response['message'] = { 'class': self.exception.__class__.__name__, 'message': forceUnicode(self.exception) }
				response['where']   = self.traceback
			else:
				response['type']   = 'rpc'
				response['result'] = self.result
		else:
			response['id'] = self.tid
			if self.exception:
				response['error']  = { 'class': self.exception.__class__.__name__, 'message': forceUnicode(self.exception) }
				response['result'] = None
			else:
				response['error']  = None
				response['result'] = self.result
		return response

# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
# =                                  CLASS WORKER OPSI JSON RPC                                       =
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
class WorkerOpsiJsonRpc(Worker):
	def __init__(self, opsiconfd, request, resource):
		Worker.__init__(self, opsiconfd, request, resource)
		self._rpcs = []
	
	def process(self):
		logger.info("Worker %s started processing" % self)
		deferred = defer.Deferred()
		deferred.addCallback(self._getSession)
		deferred.addCallback(self._linkLogFile)
		deferred.addCallback(self._authenticate)
		deferred.addCallback(self._createBackend)
		deferred.addCallback(self._getQuery)
		deferred.addCallback(self._decodeQuery)
		deferred.addCallback(self._getRpcs)
		deferred.addCallback(self._executeRpcs)
		deferred.addCallback(self._setResponse)
		deferred.addCallback(self._setCookie)
		deferred.addCallback(self._freeSession)
		deferred.addErrback(self._errback)
		deferred.callback(None)
		return deferred
	
	def _getRpcs(self, result):
		if not self.query:
			return result
		
		self.session.setLastRpcSuccessfullyDecoded(False)
		
		rpcs = []
		try:
			rpcs = fromJson(self.query, preventObjectCreation = True)
			if not rpcs:
				raise Exception(u"Got no rpcs")
		
		except Exception, e:
			raise OpsiBadRpcError(u"Failed to decode rpc: %s" % e)
		
		for rpc in forceList(rpcs):
			rpc = JsonRpc(self, rpc)
			self._setLogFile(rpc)
			self._rpcs.append(rpc)
		
		self.session.setLastRpcSuccessfullyDecoded(True)
		
		return result
	
	def _executeRpc(self, result, rpc):
		self.session.setLastRpcMethod(rpc.getMethodName())
		if (rpc.getMethodName() == 'backend_exit'):
			logger.notice(u"User '%s' asked to close the session" % self.session.user)
			self._freeSession(result)
			self.opsiconfd.getSessionHandler().deleteSession(self.session.uid)
			return result
		deferred = threads.deferToThread(rpc.execute)
		return deferred
		
	def _executeRpcs(self, result):
		if not self.session.backend:
			raise OpsiconfdError(u"Failed to get backend from session")
		deferred = defer.Deferred()
		for rpc in self._rpcs:
			deferred.addCallback(self._executeRpc, rpc)
		deferred.addErrback(self._errback)
		deferred.callback(None)
		return deferred
		
	def _generateResponse(self, result):
		if not isinstance(result, http.Response):
			result = http.Response()
		result.code = responsecode.OK
		
		deflate = False
		try:
			if self.request.headers.getHeader('Accept'):
				for accept in self.request.headers.getHeader('Accept').keys():
					if accept.mediaType.startswith('gzip'):
						deflate = True
						break
		except Exception, e:
			logger.error(u"Failed to get accepted mime types from header: %s" % e)
		
		if deflate:
			result.headers.setHeader('content-type', http_headers.MimeType("gzip-application", "json", {"charset": "utf-8"}))
		else:
			result.headers.setHeader('content-type', http_headers.MimeType("application", "json", {"charset": "utf-8"}))
		
		response = []
		for rpc in self._rpcs:
			response.append(serialize(rpc.getResponse()))
		if (len(response) == 1):
			response = response[0]
		if not response:
			response = None
		
		if deflate:
			# level 1 (fastest) to 9 (most compression)
			level = 1
			logger.debug(u"Sending compressed (level: %d) data" % level)
			result.stream = stream.IByteStream(zlib.compress(toJson(response).encode('utf-8'), level))
		else:
			result.stream = stream.IByteStream(toJson(response).encode('utf-8'))
		return result
	
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
# =                               CLASS WORKER OPSI JSON INTERFACE                                    =
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
class WorkerOpsiJsonInterface(WorkerOpsiJsonRpc):
	def __init__(self, opsiconfd, request, resource):
		WorkerOpsiJsonRpc.__init__(self, opsiconfd, request, resource)
	
	def _generateResponse(self, result):
		logger.info(u"Creating opsiconfd interface page")
		
		javascript  = u"var currentParams = new Array();\n"
		javascript += u"var currentMethod = null;\n"
		currentMethod = u''
		if self._rpcs:
			currentMethod = self._rpcs[0].getMethodName()
			javascript += u"currentMethod = '%s';\n" % currentMethod
			for i in range(len(self._rpcs[0].params)):
				param = self._rpcs[0].params[i]
				javascript += u"currentParams[%d] = '%s';\n" % (i, toJson(param))
		
		currentPath = u'interface'
		selected = u' selected="selected"'
		for pp in self.request.postpath:
			currentPath += u'/%s' % pp
			selected = u''
		javascript += u"path = '%s';\n" % currentPath
		
		selectPath = u'<option%s>interface</option>' % selected
		for name in self.opsiconfd.getBackend().dispatcher_getBackendNames():
			selected = u''
			path = u'interface/backend/%s' % name
			if (path == currentPath):
				selected = u' selected="selected"'
			selectPath += '<option%s>%s</option>' % (selected, path)
		
		for name in os.listdir(self.opsiconfd.config['extensionConfigDir']):
			if not os.path.isdir(os.path.join(self.opsiconfd.config['extensionConfigDir'], name)):
				continue
			selected = u''
			path = u'interface/extend/%s' % name
			if (path == currentPath):
				selected = u' selected="selected"'
			selectPath += '<option%s>%s</option>' % (selected, path)
		
		selectMethod = u''
		for method in self.session.interface:
			javascript += u"parameters['%s'] = new Array();\n" % (method['name'])
			for param in range(len(method['params'])):
				javascript += u"parameters['%s'][%s]='%s';\n" % (method['name'], param, method['params'][param])
			selected = u''
			if (method['name'] == currentMethod):
				selected = u' selected="selected"'
			selectMethod += u'<option%s>%s</option>' % (selected, method['name'])
		
		resultDiv = u'<div id="result">'
		for rpc in self._rpcs:
			resultDiv += '<div class="json">'
			resultDiv += objectToHtml(serialize(rpc.getResponse()))
			resultDiv += u'</div>'
		resultDiv += u'</div>'
		
		html = interfacePage
		html = html.replace(u'%javascript%', javascript)
		html = html.replace(u'%select_path%', selectPath)
		html = html.replace(u'%select_method%', selectMethod)
		html = html.replace(u'%result%', resultDiv)
		
		if not isinstance(result, http.Response):
			result = http.Response()
		result.code = responsecode.OK
		result.stream = stream.IByteStream(html.encode('utf-8').strip())
		
		return result
	
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
# =                                 CLASS WORKER OPSICONFD INFO                                       =
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
class WorkerOpsiconfdInfo(Worker):
	def __init__(self, opsiconfd, request, resource):
		Worker.__init__(self, opsiconfd, request, resource)

	def _generateResponse(self, result):
		logger.info(u"Creating opsiconfd info page")
		
		graphs = u''
		if rrdtool:
			graphs += u'<h1>Last hour</h1>'
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.opsiconfd.statistics().getRrdGraphImage(1, 3600))
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.opsiconfd.statistics().getRrdGraphImage(2, 3600))
			graphs += u'<h1>Last day</h1>'
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.opsiconfd.statistics().getRrdGraphImage(1, 3600*24))
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.opsiconfd.statistics().getRrdGraphImage(2, 3600*24))
			graphs += u'<h1>Last week</h1>'
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.opsiconfd.statistics().getRrdGraphImage(1, 3600*24*7))
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.opsiconfd.statistics().getRrdGraphImage(2, 3600*24*7))
			graphs += u'<h1>Last month</h1>'
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.opsiconfd.statistics().getRrdGraphImage(1, 3600*24*31))
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.opsiconfd.statistics().getRrdGraphImage(2, 3600*24*31))
			graphs += u'<h1>Last year</h1>'
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.opsiconfd.statistics().getRrdGraphImage(1, 3600*24*365))
			graphs += u'<img src="/rrd/%s" />' % os.path.basename(self.opsiconfd.statistics().getRrdGraphImage(2, 3600*24*365))
		
		objectInfo  = u'<h1>Object info</h1>'
		objectInfo += u'<table>'
		objectInfo += u'<tr><th>type</th><th>number</th></tr>'
		objectInfo += u'<tr><td>Depotserver</td><td>%d</td></tr>' % len(self.opsiconfd._backend.host_getIdents(returnType = 'unicode', type = 'OpsiDepotserver'))
		objectInfo += u'<tr><td>Client</td><td>%d</td></tr>' % len(self.opsiconfd._backend.host_getIdents(returnType = 'unicode', type = 'OpsiClient'))
		objectInfo += u'<tr><td>Product</td><td>%d</td></tr>' % len(self.opsiconfd._backend.product_getIdents(returnType = 'unicode'))
		objectInfo += u'<tr><td>Config</td><td>%d</td></tr>' % len(self.opsiconfd._backend.config_getIdents(returnType = 'unicode'))
		objectInfo += u'</table>'
		
		configInfo  = u'<h1>Server config</h1>'
		configInfo += u'<table>'
		configInfo += u'<tr><th>key</th><th>value</th></tr>'
		keys = self.opsiconfd.config.keys()
		keys.sort()
		for key in keys:
			if key in ('staticDirectories',):
				continue
			configInfo += u'<tr><td>%s</td><td>%s</td></tr>' % (key, self.opsiconfd.config[key])
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
		
		sessions = self.opsiconfd.getSessionHandler().getSessions()
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
		resources = self.opsiconfd.config['staticDirectories'].keys()
		resources.sort()
		for resource in resources:
			path = self.opsiconfd.config['staticDirectories'][resource]
			if os.path.isdir(path):
				if not resource.startswith('/'): resource = u'/' + resource
				info = getDiskSpaceUsage(path)
				diskUsageInfo += u'<tr><td><a href="%s">%s</a></td><td>%s</td><td>%0.2f GB</td><td>%0.2f GB</td><td>%0.2f GB</td><td>%0.2f %%</td></tr>' \
					% (resource, resource, path, (float(info['capacity'])/1073741824), (float(info['used'])/1073741824), (float(info['available'])/1073741824), (info['usage']*100))
		diskUsageInfo += u'</table>'
		
		average = { 'params': 0.0, 'results': 0.0, 'duration': 0.0, 'failed': 0.0 }
		maxDuration = { 'duration': 0 }
		statisticInfo  = u'<h1>RPC statistics (last %d)</h1>' % self.opsiconfd.config['maxExecutionStatisticValues']
		statisticInfo += u'<table>'
		statisticInfo += u'<tr><th>method</th><th>params</th><th>results</th><th>duration</th><th>success</th></tr>'
		rpcs = self.opsiconfd.statistics().getRpcs()
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
		for statistic in sorted(self.opsiconfd.statistics().getEncodingErrors(), key=operator.itemgetter('application')):
			statisticInfo += u'<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' \
					% (statistic['application'], statistic['what'], statistic['client'], statistic['error'])
		statisticInfo += u'</table>'
		
		statisticInfo += u'<br />'
		
		statisticInfo += u'<h1>Authentication failures</h1>'
		statisticInfo += u'<table>'
		statisticInfo += u'<tr><th>ip address</th><th>count</th></tr>'
		for (ipAddress, count) in self.opsiconfd.authFailureCount.items():
			if (count > self.opsiconfd.config['maxAuthenticationFailures']):
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





# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
# =                                        CLASS DAVWORKER                                            =
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
class WorkerOpsiDAV(Worker):
	def __init__(self, opsiconfd, request, resource):
		Worker.__init__(self, opsiconfd, request, resource)
	
	def process(self):
		logger.debug("Worker %s started processing" % self)
		deferred = defer.Deferred()
		deferred.addCallback(self._getSession)
		deferred.addCallback(self._authenticate)
		deferred.addCallback(self._setResponse)
		deferred.addCallback(self._setCookie)
		deferred.addCallback(self._freeSession)
		deferred.addErrback(self._errback)
		deferred.callback(None)
		return deferred
	
	def _authenticate(self, result):
		''' This function tries to authenticate a user.
		    Raises an exception on authentication failure. '''
		
		try:
			if self.session.authenticated:
				return result
			
			logger.notice(u"Authorization request from %s@%s (application: %s)" % (self.session.user, self.session.ip, self.session.userAgent))
			
			if not self.session.user:
				raise Exception(u"No username from %s (application: %s)" % (self.session.ip, self.session.userAgent))
				
			if not self.session.password:
				raise Exception(u"No password from %s (application: %s)" % (self.session.ip, self.session.userAgent))
			
			bac = BackendAccessControl(
				backend  = self.opsiconfd._backend,
				username = self.session.user,
				password = self.session.password
			)
			if not bac.accessControl_authenticated():
				raise Exception(u"Bad user or password")
			
			self.session.isAdmin = bac.accessControl_userIsAdmin()
			
			if not self.session.isHost and not self.session.isAdmin:
				raise Exception(u"Neither host nor admin user")
			
			self.session.authenticated = True
			if self.opsiconfd.authFailureCount.has_key(self.request.remoteAddr.host):
				del self.opsiconfd.authFailureCount[self.request.remoteAddr.host]
		except Exception, e:
			logger.logException(e, LOG_INFO)
			self._freeSession(result)
			self.opsiconfd.getSessionHandler().deleteSession(self.session.uid)
			raise OpsiAuthenticationError(u"Forbidden: %s" % e)
		return result
	
	def _setResponse(self, result):
		logger.debug(u"Client requests DAV operation: %s" % self.request)
		if not self.session.isAdmin and self.request.method not in ('GET', 'PROPFIND', 'OPTIONS', 'USERINFO', 'HEAD'):
			logger.critical(u"Method '%s' not allowed (read only)" % self.request.method)
			return http.Response(
				code	= responsecode.FORBIDDEN,
				stream	= "Readonly!" )
		
		deferred = super(ResourceOpsiDAV, self.resource).renderHTTP(self.request)
		if isinstance(deferred, defer.Deferred):
			deferred.addErrback(self._errback)
		return deferred
	
	def _setCookie(self, result):
		if not self.session:
			return result
		
		# Add cookie to headers
		cookie = http_headers.Cookie(self.session.name.encode('ascii', 'replace'), self.session.uid.encode('ascii', 'replace'), path='/')
		result.headers.setHeader('set-cookie', [ cookie ] )
		return result


# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
# =                                     CLASS RESOURCE ROOT                                           =
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
class ResourceRoot(resource.Resource):
	addSlash = True
	def render(self, request):
		''' Process request. '''
		return http.Response(stream="<html><head><title>opsiconfd</title></head><body></body></html>")

# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
# =                                     CLASS RESOURCE OPSI                                           =
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
class ResourceOpsi(resource.Resource):
	WorkerClass = None
	isLeaf = True
	
	def __init__(self, opsiconfd):
		resource.Resource.__init__(self)
		self._opsiconfd = opsiconfd
	
	def checkPrivileges(self, request, privileges, recurse=False, principal=None, inherited_aces=None):
		deferred = defer.Deferred()
		deferred.callback(None)
		return deferred
	
	def isCollection(self):
		return not self.isLeaf
	
	def hasProperty(self, property, request):
		deferred = defer.Deferred()
		deferred.callback(None)
		return deferred
	
	def renderHTTP(self, request):
		''' Process request. '''
		try:
			self._opsiconfd.statistics().addRequest(request)
			logger.debug2(u"%s.renderHTTP()" % self.__class__.__name__)
			if not self.WorkerClass:
				raise Exception(u"No worker class defined in resource %s" % self.__class__.__name__)
			worker = self.WorkerClass(self._opsiconfd, request, self)
			return worker.process()
		except Exception, e:
			logger.logException(e)
	
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
# =                                 CLASS RESOURCE OPSI JSONRPC                                       =
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
class ResourceOpsiJsonRpc(ResourceOpsi):
	WorkerClass = WorkerOpsiJsonRpc
	isLeaf = False
	
	def __init__(self, opsiconfd):
		ResourceOpsi.__init__(self, opsiconfd)
	
	def locateChild(self, request, segments):
		return self, server.StopTraversal
	
	
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
# =                              CLASS RESOURCE OPSI JSON INTERFACE                                   =
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
class ResourceOpsiJsonInterface(ResourceOpsiJsonRpc):
	WorkerClass = WorkerOpsiJsonInterface
	
	def __init__(self, opsiconfd):
		ResourceOpsi.__init__(self, opsiconfd)
		self._interface = self._opsiconfd.getBackend().backend_getInterface()

# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
# =                                CLASS RESOURCE OPSICONFD INFO                                      =
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
class ResourceOpsiconfdInfo(ResourceOpsi):
	WorkerClass = WorkerOpsiconfdInfo
	
	def __init__(self, opsiconfd):
		ResourceOpsi.__init__(self, opsiconfd)
		

# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
# =                             CLASS RESOURCE OPSICONFD STATISTICS                                   =
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
class ResourceOpsiconfdStatistics(resource.Resource):
	def __init__(self, opsiconfd):
		self._opsiconfd = opsiconfd
	
	def renderHTTP(self, request):
		''' Process request. '''
		resp = ''
		for (k, v) in self._opsiconfd.statistics().getStatistics().items():
			resp += '%s:%s\n' % (k, v)
		return http.Response(stream=resp)
	
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
# =                                   CLASS RESOURCE OPSI DAV                                         =
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
class ResourceOpsiDAV(OPSI.web2.dav.static.DAVFile):
	
	def __init__(self, opsiconfd, path, readOnly=True, defaultType="text/plain", indexNames=None):
		path = forceUnicode(path).encode('utf-8')
		OPSI.web2.dav.static.DAVFile.__init__(self, path, defaultType, indexNames)
		self._opsiconfd = opsiconfd
		self._readOnly = readOnly
	
	def createSimilarFile(self, path):
		return self.__class__(self._opsiconfd, path, readOnly=self._readOnly, defaultType=self.defaultType, indexNames=self.indexNames[:])
	
	def renderHTTP(self, request):
		try:
			self._opsiconfd.statistics().addWebDAVRequest(request)
			if self._readOnly and request.method not in ('GET', 'PROPFIND', 'OPTIONS', 'USERINFO', 'HEAD'):
				logger.warning(u"Command %s not allowed (readonly)" % request.method)
				return http.Response(
					code	= responsecode.FORBIDDEN,
					stream	= "Readonly!" )
			worker = WorkerOpsiDAV(self._opsiconfd, request, self)
			return worker.process()
		except Exception, e:
			logger.logException(e)


# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
# =                                      CLASS SSL CONTEXT                                            =
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
class SSLContext:
	def __init__(self, sslServerKeyFile, sslServerCertFile):
		self._sslServerKeyFile  = sslServerKeyFile
		self._sslServerCertFile = sslServerCertFile
		
	def getContext(self):
		''' Create an SSL context. '''
		
		# Test if server certificate and key file exist.
		if not os.path.isfile(self._sslServerKeyFile):
			raise Exception(u"Server key file '%s' does not exist!" % self._sslServerKeyFile)
			
		if not os.path.isfile(self._sslServerCertFile):
			raise Exception(u"Server certificate file '%s' does not exist!" % self._sslServerCertFile)
		
		context = SSL.Context(SSL.SSLv23_METHOD)
		context.use_privatekey_file(self._sslServerKeyFile)
		context.use_certificate_file(self._sslServerCertFile)
		return context

	
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
# =                                         CLASS SESSION                                             =
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
class Session:
	def __init__(self, sessionHandler, name = u'OPSISID', sessionMaxInactiveInterval = 120):
		self.sessionHandler = sessionHandler
		self.name = forceUnicode(name)
		self.sessionMaxInactiveInterval = forceInt(sessionMaxInactiveInterval)
		self.created = time.time()
		self.lastModified = time.time()
		self.sessionTimer = None
		self.uid = randomString(32)
		self.ip = ''
		self.userAgent = ''
		self.isHost = False
		self.isAdmin = False
		self.hostname = ''
		self.user = ''
		self.password = ''
		self.authenticated = False
		self.postpath = []
		self.backend = None
		self.interface = None
		self.lastRpcSuccessfullyDecoded = False
		self.lastRpcMethod = u''
		self.usageCount = 0
		self.usageCountLock = threading.Lock()
		self.markedForDeletion = False
		self.deleted = False
		self.touch()
		
	def decreaseUsageCount(self):
		if self.deleted:
			return
		self.usageCountLock.acquire()
		self.usageCount -= 1
		self.usageCountLock.release()
		
	def increaseUsageCount(self):
		if self.deleted:
			return
		self.usageCountLock.acquire()
		self.usageCount += 1
		self.touch()
		self.usageCountLock.release()
	
	def touch(self):
		if self.deleted:
			return
		self.lastModified = time.time()
		if self.sessionTimer:
			self.sessionTimer.cancel()
			self.sessionTimer.join(1)
		self.sessionTimer = threading.Timer(self.sessionMaxInactiveInterval, self.expire)
		self.sessionTimer.start()
	
	def setLastRpcSuccessfullyDecoded(self, successfullyDecoded):
		self.lastRpcSuccessfullyDecoded = forceBool(successfullyDecoded)
		
	def setLastRpcMethod(self, methodName):
		self.lastRpcMethod = forceUnicode(methodName)
	
	def setMarkedForDeletion(self):
		self.markedForDeletion = True
	
	def getMarkedForDeletion(self):
		return self.markedForDeletion
	
	def getValidity(self):
		if self.deleted:
			return 0
		return int(self.lastModified - time.time() + self.sessionMaxInactiveInterval)
	
	def expire(self):
		self.sessionHandler.sessionExpired(self)
	
	def delete(self):
		if self.deleted:
			return
		self.deleted = True
		if (self.usageCount > 0):
			logger.warning(u"Deleting session in use: %s" % self)
		if self.sessionTimer:
			try:
				self.sessionTimer.cancel()
				try:
					self.sessionTimer.join(1)
				except:
					pass
				logger.info(u"Session timer %s canceled" % self.sessionTimer)
			except Exception, e:
				logger.error(u"Failed to cancel session timer: %s" % e)
		if self.backend:
			logger.debug(u"Calling backend_exit() on backend %s" % self.backend)
			self.backend.backend_exit()
	
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
# =                                    CLASS SESSION HANDLER                                          =
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
class SessionHandler:
	def __init__(self, opsiconfd):
		self.opsiconfd = opsiconfd
		self.sessions = {}
	
	def cleanup(self):
		self.deleteAllSessions()
	
	def getSessions(self, ip=None):
		if not ip:
			return self.sessions
		sessions = []
		for session in self.sessions.values():
			if (session.ip == ip):
				sessions.append(session)
		return sessions
		
	def getSession(self, uid=None, ip=None):
		if uid:
			session = self.sessions.get(uid)
			if session:
				if session.getMarkedForDeletion():
					logger.info(u'Session found but marked for deletion')
				else:
					# Set last modified to current time
					session.increaseUsageCount()
					logger.confidential(u"Returning session: %s (count: %d)" % (session.uid, session.usageCount))
					return session
			else:
				logger.info(u'Failed to get session: session id %s not found' % uid)
		if ip and (self.opsiconfd.config['maxSessionsPerIp'] > 0):
			sessions = self.getSessions(ip)
			if (len(sessions) >= self.opsiconfd.config['maxSessionsPerIp']):
				logger.error(u"Session limit for ip '%s' reached" % ip)
				for session in sessions:
					if (session.usageCount > 0):
						continue
					logger.info(u"Deleting unused session")
					self.deleteSession(session.uid)
				if (len(self.getSessions(ip)) >= self.opsiconfd.config['maxSessionsPerIp']):
					raise OpsiAuthenticationError(u"Session limit for ip '%s' reached" % ip)
		
		session = self.createSession()
		session.increaseUsageCount()
		return session
		
	def createSession(self):
		session = Session(self, self.opsiconfd.config['sessionName'], self.opsiconfd.config['sessionMaxInactiveInterval'])
		self.sessions[session.uid] = session
		logger.notice(u"New session created")
		self.opsiconfd.statistics().addSession(session)
		return session
	
	def sessionExpired(self, session):
		logger.notice(u"Session '%s' from ip '%s', application '%s' expired after %d seconds" \
				% (session.uid, session.ip, session.userAgent, (time.time()-session.lastModified)))
		if (session.usageCount > 0):
			logger.notice(u"Session currently in use, waiting before deletion")
		session.setMarkedForDeletion()
		timeout = 60
		if session.lastRpcSuccessfullyDecoded:
			timeout = 3600
		while (session.usageCount > 0) and (timeout > 0):
			time.sleep(1)
			timeout -= 1
		if (timeout == 0):
			logger.warning(u"Session '%s': timeout occured while waiting for session to get free for deletion" % session.uid)
		self.deleteSession(session.uid)
		
	def deleteSession(self, uid):
		session = self.sessions.get(uid)
		if not session:
			logger.warning(u'No such session id: %s' % uid)
			return
		self.opsiconfd.statistics().removeSession(session)
		try:
			session.delete()
		except:
			pass
		
		try:
			del self.sessions[uid]
			logger.notice(u"Session '%s' from ip '%s', application '%s' deleted" % (session.uid, session.ip, session.userAgent))
			del session
		except KeyError:
			pass
	
	def deleteAllSessions(self):
		logger.notice(u"Deleting all sessions")
		class SessionDeletionThread(threading.Thread):
			def __init__(self, sessionHandler, uid):
				threading.Thread.__init__(self)
				self._sessionHandler = sessionHandler
				self._uid = uid
			
			def run(self):
				self._sessionHandler.deleteSession(self._uid)
		
		dts = []
		for (uid, session) in self.sessions.items():
			logger.debug(u"Deleting session '%s'" % uid)
			dts.append(SessionDeletionThread(self, uid))
			dts[-1].start()
		for dt in dts:
			dt.join(2)
		self.sessions = {}

# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
# =                                       CLASS STATISTICS                                            =
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
class Statistics(object):
	def __init__(self, opsiconfd):
		self.opsiconfd = opsiconfd
		self._rpcs = []
		self._encodingErrors = []
		self._utime = 0.0
		self._stime = 0.0
		self._last = time.time()
		self._rrdConfig = {
			'step':              60,
			'heartbeat':        120,
			'xPoints':          800,
			'yPoints':          160,
			'rrdFile':          os.path.join(self.opsiconfd.config['rrdDir'], 'opsiconfd.rrd')
		}
		self._rrdCache = { 'requests': 0, 'sessions': 0, 'davrequests': 0, 'rpcs': 0, 'rpcerrors': 0 }
		
		if not os.path.exists(self._rrdConfig['rrdFile']):
			self.createRrd()
		loop = LoopingCall(self.updateRrd)
		loop.start(int(self._rrdConfig['step']), now=False)
		
	def createRrd(self):
		if not rrdtool:
			return
		if os.path.exists(self._rrdConfig['rrdFile']):
			os.unlink(self._rrdConfig['rrdFile'])
		
		start = int(time.time())
		logger.notice(u"Creating rrd '%s', start: %s" % (self._rrdConfig['rrdFile'], start))
		
		rrdtool.create(str(self._rrdConfig['rrdFile']), '--start', str(start), '--step', str(self._rrdConfig['step']),
			'DS:requests:ABSOLUTE:%d:0:U'    % self._rrdConfig['heartbeat'],
			'DS:sessions:DERIVE:%d:0:U'      % self._rrdConfig['heartbeat'],
			'DS:davrequests:ABSOLUTE:%d:0:U' % self._rrdConfig['heartbeat'],
			'DS:rpcs:ABSOLUTE:%d:0:U'        % self._rrdConfig['heartbeat'],
			'DS:rpcerrors:ABSOLUTE:%d:0:U'   % self._rrdConfig['heartbeat'],
			'DS:cpu:GAUGE:%d:0:U'            % self._rrdConfig['heartbeat'],
			'DS:mem:GAUGE:%d:0:U'            % self._rrdConfig['heartbeat'],
			'DS:threads:GAUGE:%d:0:U'        % self._rrdConfig['heartbeat'],
			'RRA:AVERAGE:0.5:%d:%d' % (1,   (3600/self._rrdConfig['step'])),    # hour
			'RRA:AVERAGE:0.5:%d:%d' % (1,   (3600/self._rrdConfig['step'])*24), # day
			'RRA:AVERAGE:0.5:%d:%d' % (7,   (3600/self._rrdConfig['step'])*24), # week
			'RRA:AVERAGE:0.5:%d:%d' % (31,  (3600/self._rrdConfig['step'])*24), # month
			'RRA:AVERAGE:0.5:%d:%d' % (365, (3600/self._rrdConfig['step'])*24), # year
			'RRA:MAX:0.5:%d:%d'     % (1,   (3600/self._rrdConfig['step'])),    # hour
			'RRA:MAX:0.5:%d:%d'     % (1,   (3600/self._rrdConfig['step'])*24), # day
			'RRA:MAX:0.5:%d:%d'     % (7,   (3600/self._rrdConfig['step'])*24), # week
			'RRA:MAX:0.5:%d:%d'     % (31,  (3600/self._rrdConfig['step'])*24), # month
			'RRA:MAX:0.5:%d:%d'     % (365, (3600/self._rrdConfig['step'])*24), # year
		)
	
	def getStatistics(self):
		result = {}
	
		try:
			now = int(time.time())
			last = self._last
			self._last = now
			(utime, stime, maxrss) = pyresource.getrusage(pyresource.RUSAGE_SELF)[0:3]
			usr = (utime - self._utime)/(now - last)
			sys = (stime - self._stime)/(now - last)
			(self._utime, self._stime) = (utime, stime)
			#mem = int("%0.0f" % (float(maxrss * pyresource.getpagesize())/(1024*1024))) # Mbyte
			f = open('/proc/%s/stat' % os.getpid())
			data = f.read().split()
			f.close()
			virtMem = int("%0.0f" % (float(data[22])/(1024*1024)))
			
			#cpu
			cpu = int("%0.0f" % ((usr + sys) * 100))
			if (cpu > 100): cpu = 100
			
			#threads
			threads = []
			for thread in threading.enumerate():
				threads.append(thread)
			#build result-Hash
			result["requests"] = self._rrdCache['requests']
			result["sessions"] = self._rrdCache['sessions']
			result["davrequests"] = self._rrdCache['davrequests']
			result["rpcs"] = self._rrdCache['rpcs']
			result["rpcerrors"] = self._rrdCache['rpcerrors']
			result["cpu"] = cpu
			result["virtmem"] = virtMem
			result["threads"] = len(threads)
			
			return result
			
		except Exception, e:
			logger.error(u"Failed to get Statistics: %s" % e)
			return result
	
	def updateRrd(self):
		if not rrdtool:
			return
		try:
			now = int(time.time())
			last = self._last
			self._last = now
			(utime, stime, maxrss) = pyresource.getrusage(pyresource.RUSAGE_SELF)[0:3]
			usr = (utime - self._utime)/(now - last)
			sys = (stime - self._stime)/(now - last)
			(self._utime, self._stime) = (utime, stime)
			#mem = int("%0.0f" % (float(maxrss * pyresource.getpagesize())/(1024*1024))) # Mbyte
			f = open('/proc/%s/stat' % os.getpid())
			data = f.read().split()
			f.close()
			virtMem = int("%0.0f" % (float(data[22])/(1024*1024)))
			cpu = int("%0.0f" % ((usr + sys) * 100))
			if (cpu > 100): cpu = 100
			threads = []
			for thread in threading.enumerate():
				threads.append(thread)
			logger.debug(u'Updating rrd: %d:%d:%d:%d:%d:%d:%d:%d:%d' \
				% (now, self._rrdCache['requests'], self._rrdCache['sessions'], self._rrdCache['davrequests'], self._rrdCache['rpcs'], self._rrdCache['rpcerrors'], cpu, virtMem, len(threads)))
			rrdtool.update(str(self._rrdConfig['rrdFile']), '%d:%d:%d:%d:%d:%d:%d:%d:%d' \
				% (now, self._rrdCache['requests'], self._rrdCache['sessions'], self._rrdCache['davrequests'], self._rrdCache['rpcs'], self._rrdCache['rpcerrors'], cpu, virtMem, len(threads)))
			self._rrdCache['requests'] = 0
			self._rrdCache['davrequests'] = 0
			self._rrdCache['rpcs'] = 0
			self._rrdCache['rpcerrors'] = 0
		except Exception, e:
			logger.error(u"Failed to update rrd: %s" % e)
	
	def getRrdGraphImage(self, type, range):
		if not rrdtool:
			return None
		
		if (type == 1):
			graphImage = os.path.join(self.opsiconfd.config['rrdDir'], '1_%s.png' % range)
		else:
			graphImage = os.path.join(self.opsiconfd.config['rrdDir'], '2_%s.png' % range)
		
		date = time.strftime("%a, %d %b %Y %H\:%M\:%S", time.localtime())
		end = int(time.time())
		start = end - range
		
		
		logger.debug(u"Creating rrd graph image '%s', start: %s, end: %s" % (graphImage, start, end))
		
		if os.path.exists(graphImage):
			os.unlink(graphImage)
		
		if (type == 1):
			rrdtool.graph(str(graphImage),
				'--imgformat',      'PNG',
				'--width',          str(self._rrdConfig['xPoints']),
				'--height',         str(self._rrdConfig['yPoints']),
				'--start',          str(start),
				'--end',            str(end),
				'--vertical-label', 'avg per minute',
				'--lower-limit',    str(0),
				'--units-exponent', str(0), # don't show milli-messages/s
				'--slope-mode',
				'--color',          'SHADEA#ffffff',
				'--color',          'SHADEB#ffffff',
				'--color',          'BACK#ffffff',
				
				'DEF:avg_requ=%s:requests:AVERAGE' % str(self._rrdConfig['rrdFile']),
				'DEF:max_requ=%s:requests:MAX'     % str(self._rrdConfig['rrdFile']),
				'CDEF:avg_requ_permin=avg_requ,60,*',
				'CDEF:max_requ_permin=max_requ,60,*',
				'VDEF:total_requ=avg_requ,TOTAL',
				'LINE2:avg_requ_permin#0000dd:Requests     ',
				'GPRINT:total_requ:total\: %8.0lf requests     ',
				'GPRINT:avg_requ_permin:AVERAGE:avg\: %5.2lf requests/min     ',
				'GPRINT:max_requ_permin:MAX:max\: %4.0lf requests/min\\l',
				
				'DEF:avg_davrequ=%s:davrequests:AVERAGE' % str(self._rrdConfig['rrdFile']),
				'DEF:max_davrequ=%s:davrequests:MAX'     % str(self._rrdConfig['rrdFile']),
				'CDEF:avg_davrequ_permin=avg_davrequ,60,*',
				'CDEF:max_davrequ_permin=max_davrequ,60,*',
				'VDEF:total_davrequ=avg_davrequ,TOTAL',
				'LINE2:avg_davrequ_permin#ff8000:DAV requests ',
				'GPRINT:total_davrequ:total\: %8.0lf dav requests ',
				'GPRINT:avg_davrequ_permin:AVERAGE:avg\: %5.2lf dav requests/min ',
				'GPRINT:max_davrequ_permin:MAX:max\: %4.0lf dav requests/min\\l',
				
				'DEF:avg_rpc=%s:rpcs:AVERAGE' % str(self._rrdConfig['rrdFile']),
				'DEF:max_rpc=%s:rpcs:MAX'     % str(self._rrdConfig['rrdFile']),
				'CDEF:avg_rpc_permin=avg_rpc,60,*',
				'CDEF:max_rpc_permin=max_rpc,60,*',
				'VDEF:total_rpc=avg_rpc,TOTAL',
				'LINE2:avg_rpc_permin#00dd00:RPCs         ',
				'GPRINT:total_rpc:total\: %8.0lf rpcs         ',
				'GPRINT:avg_rpc_permin:AVERAGE:avg\: %5.2lf rpcs/min         ',
				'GPRINT:max_rpc_permin:MAX:max\: %4.0lf rpcs/min\\l',
				
				'DEF:avg_rpcerror=%s:rpcerrors:AVERAGE' % str(self._rrdConfig['rrdFile']),
				'DEF:max_rpcerror=%s:rpcerrors:MAX'     % str(self._rrdConfig['rrdFile']),
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
				'--imgformat',        'PNG',
				'--width',            str(self._rrdConfig['xPoints']),
				'--height',           str(self._rrdConfig['yPoints']),
				'--start',            str(start),
				'--end',              str(end),
				'--vertical-label',   '% / num / MByte*0.1',
				'--lower-limit',      str(0),
				'--units-exponent',   str(0), # don't show milli-messages/s
				'--slope-mode',
				'--color',            'SHADEA#ffffff',
				'--color',            'SHADEB#ffffff',
				'--color',            'BACK#ffffff',
				
				'DEF:avg_threads=%s:threads:AVERAGE' % str(self._rrdConfig['rrdFile']),
				'DEF:max_threads=%s:threads:MAX'     % str(self._rrdConfig['rrdFile']),
				'LINE2:avg_threads#00dd00:Threads      ',
				'GPRINT:max_threads:LAST:cur\: %8.0lf threads      ',
				'GPRINT:avg_threads:AVERAGE:avg\: %8.2lf threads          ',
				'GPRINT:max_threads:MAX:max\: %8.0lf threads\\l',
				
				'DEF:avg_sess=%s:sessions:AVERAGE' % str(self._rrdConfig['rrdFile']),
				'DEF:max_sess=%s:sessions:MAX'     % str(self._rrdConfig['rrdFile']),
				'CDEF:avg_sess_permin=avg_sess,60,*',
				'CDEF:max_sess_permin=max_sess,60,*',
				'VDEF:total_sess=avg_sess,TOTAL',
				'LINE2:avg_sess_permin#ff8000:Sessions     ',
				'GPRINT:max_sess:LAST:cur\: %8.0lf sessions     ',
				'GPRINT:avg_sess_permin:AVERAGE:avg\: %8.2lf sessions/min     ',
				'GPRINT:max_sess_permin:MAX:max\: %8.0lf sessions/min\\l',
				
				'DEF:avg_cpu=%s:cpu:AVERAGE' % str(self._rrdConfig['rrdFile']),
				'DEF:max_cpu=%s:cpu:MAX'     % str(self._rrdConfig['rrdFile']),
				'LINE2:avg_cpu#dd0000:CPU usage    ',
				'GPRINT:max_cpu:LAST:cur\: %8.2lf %%            ',
				'GPRINT:avg_cpu:AVERAGE:avg\: %8.2lf %%                ',
				'GPRINT:max_cpu:MAX:max\: %8.2lf %%\\l',
				
				'DEF:avg_mem=%s:mem:AVERAGE' % str(self._rrdConfig['rrdFile']),
				'DEF:max_mem=%s:mem:MAX'     % str(self._rrdConfig['rrdFile']),
				'CDEF:avg_mem_scaled=avg_mem,10,/',
				'LINE2:avg_mem_scaled#0000dd:MEM usage    ',
				'GPRINT:max_mem:LAST:cur\: %8.2lf MByte        ',
				'GPRINT:avg_mem:AVERAGE:avg\: %8.2lf MByte            ',
				'GPRINT:max_mem:MAX:max\: %8.2lf MByte\\l',
				
				'COMMENT:[%s]\\r' % date,
			)
		
		return graphImage
	
	def addSession(self, session):
		self._rrdCache['sessions'] += 1
	
	def removeSession(self, session):
		if (self._rrdCache['sessions'] > 0):
			self._rrdCache['sessions'] -= 1
		
	def addRequest(self, request):
		self._rrdCache['requests'] += 1
	
	def addWebDAVRequest(self, request):
		self._rrdCache['davrequests'] += 1
	
	def addRpc(self, jsonrpc):
		results = 0
		if not jsonrpc.exception:
			results = 0
			if type(jsonrpc.result) is list:
				results = len(jsonrpc.result)
		
		self._rpcs.append({
			'started':  jsonrpc.started,
			'duration': jsonrpc.ended - jsonrpc.started,
			'method':   jsonrpc.getMethodName(),
			'failed':   bool(jsonrpc.exception),
			'params':   len(jsonrpc.params),
			'results':  results,
		})
		if (len(self._rpcs) > self.opsiconfd.config['maxExecutionStatisticValues']):
			self._rpcs = self._rpcs[1:]
		self._rrdCache['rpcs'] += 1
		if jsonrpc.exception:
			self._rrdCache['rpcerrors'] += 1
		
	def getRpcs(self):
		return self._rpcs
	
	def addEncodingError(self, what, client, application, error):
		self._encodingErrors.append({
			'what':        forceUnicode(what),
			'client':      forceUnicode(client),
			'application': forceUnicode(application),
			'error':       forceUnicode(error)
		})
		
	def getEncodingErrors(self):
		return self._encodingErrors



# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
# =                                    CLASS ZEROCONFSERVICE                                          =
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
class ZeroconfService(object):

	def __init__(self, name, port, serviceType="_opsiconfd._tcp", domain="", host="", text=""):
		self._name = name
		self._port = port
		self._serviceType = serviceType
		self._domain = domain
		self._host = host
		self._text = text
		self._group = None
		
	def publish(self):
		if not dbus or not avahi:
			logger.warning(u"Failed to publish ZeroconfService: avahi/dbus module missing")
			return
		
		bus = dbus.SystemBus()
		server = dbus.Interface(
			bus.get_object(
				avahi.DBUS_NAME,
				avahi.DBUS_PATH_SERVER
			),
			avahi.DBUS_INTERFACE_SERVER
		)
		
		g = dbus.Interface(
			bus.get_object(
				avahi.DBUS_NAME,
				server.EntryGroupNew()
			),
			avahi.DBUS_INTERFACE_ENTRY_GROUP
		)
		
		g.AddService(avahi.IF_UNSPEC, avahi.PROTO_UNSPEC,dbus.UInt32(0),
				self._name, self._serviceType, self._domain, self._host,
				dbus.UInt16(self._port), self._text)
		
		g.Commit()
		self._group = g
	
	def unpublish(self):
		if self._group:
			self._group.Reset()

# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
# =                                       CLASS OPSICONFD                                             =
# = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
class Opsiconfd(threading.Thread):
	def __init__(self, config):
		threading.Thread.__init__(self)
		
		self.config           = config
		self._running         = False
		
		self._backend         = None
		self._root            = None
		self._site            = None
		self._httpPort        = None
		self._httpsPort       = None
		self._sessionHandler  = None
		self._statistics      = None
		self._zeroconfService = None
		
		self.authFailureCount = {}
		
		self._setOpsiLogging()
		self._setTwistedLogging()
		logger.comment(	"\n==================================================================\n" \
				+ "=             opsi configuration service starting                =\n" \
				+ "==================================================================\n")
		
	def setConfig(self, config):
		logger.notice(u"Got new config")
		self.config = config
		
	def isRunning(self):
		return self._running
	
	def getBackend(self):
		return self._backend
	
	def statistics(self):
		return self._statistics
		
	def getSessionHandler(self):
		return self._sessionHandler
	
	def stop(self):
		logger.notice(u"Stopping opsiconfd main thread")
		if self._zeroconfService:
			self._zeroconfService.unpublish()
		if self._httpPort:
			self._httpPort.stopListening()
		if self._httpsPort:
			self._httpsPort.stopListening()
		if self._sessionHandler:
			self._sessionHandler.cleanup()
		if self._backend:
			try:
				self._backend.backend_exit()
			except:
				pass
		if reactor.running:
			try:
				logger.notice(u"Stopping reactor")
				reactor.stop()
			except Exception, e:
				logger.error(u"Failed to stop reactor: %s" % e)
		self._running = False
	
	def reload(self):
		logger.notice(u"Reloading opsiconfd")
		self.authFailureCount = {}
		
		self._setOpsiLogging()
		self._createBackendInstance()
		if self._sessionHandler:
			self._sessionHandler.cleanup()
		self._createSessionHandler()
		self._createStatistics()
		self._createSite()
		
		if self._httpPort:
			deferred = self._httpPort.stopListening()
			if deferred:
				deferred.addCallback(self._startListeningHTTP)
		else:
			self._startListeningHTTP()
		
		if self._httpsPort:
			deferred = self._httpsPort.stopListening()
			if deferred:
				deferred.addCallback(self._startListeningHTTPS)
		else:
			self._startListeningHTTPS()
		
	def _createStatistics(self):
		self._statistics = Statistics(self)
		
	def _createSessionHandler(self):
		self._sessionHandler = SessionHandler(self)
	
	def _setOpsiLogging(self):
		# Set logging options
		self.config['machineLogs'] = False
		if self.config['logFile']:
			if (self.config['logFile'].find('%m') != -1):
				self.config['machineLogs'] = True
			logger.setLogFile( self.config['logFile'].replace('%m', 'opsiconfd') )
		
		if self.config['logFormat']:
			logger.setLogFormat(self.config['logFormat'])
		logger.setFileLevel(self.config['logLevel'])
		
	def _setTwistedLogging(self):
		def twistedLogObserver(eventDict):
			if eventDict.get('isError'):
				if eventDict.get('failure'):
					logger.logTraceback(eventDict['failure'].getTracebackObject())
					logger.critical(u"     ==>>> %s" % eventDict['failure'].getErrorMessage())
				for line in eventDict.get('message', ()):
					if line.find("Can't find property" != -1):
						# Dav property errors
						logger.debug(line)
					else:
						logger.error(line)
			else:
				for line in eventDict.get('message', ()):
					logger.debug(u"[twisted] %s" % line)
		
		log.startLoggingWithObserver(twistedLogObserver, setStdout=0)
	
	def _createBackendInstance(self):
		logger.info(u"Creating backend instance")
		self._backend = BackendManager(
			dispatchConfigFile = self.config['dispatchConfigFile'],
			backendConfigDir   = self.config['backendConfigDir'],
			extensionConfigDir = self.config['extensionConfigDir'],
			depotBackend       = bool(self.config['depotId'])
		)
	
	def _createSite(self):
		logger.info(u"Creating site")
		del self._site
		del self._root
		
		if self.config['staticDirectories'].get('/'):
			if not os.path.isdir(self.config['staticDirectories']['/']):
				logger.error(u"Cannot add static content '/': directory '%s' does not exist." \
					% self.config['staticDirectories']['/'])
			else:
				self._root = ResourceOpsiDAV(self, path = self.config['staticDirectories']['/'], readOnly = True)
				logger.notice(u"Added static content '/' which points to directory '%s'" \
					% self.config['staticDirectories']['/'])
		
		if not hasattr(self, '_root'):
			self._root = ResourceRoot()
		
		self._root.putChild('rrd',             ResourceOpsiDAV(self, path = self.config['rrdDir'], readOnly = True))
		self._root.putChild('rpc',             ResourceOpsiJsonRpc(self))
		self._root.putChild('interface',       ResourceOpsiJsonInterface(self))
		self._root.putChild('info',            ResourceOpsiconfdInfo(self))
		self._root.putChild('statistics',      ResourceOpsiconfdStatistics(self))
		
		hosts = self._backend.host_getObjects(type = 'OpsiDepotserver', id = self.config['fqdn'])
		if hosts:
			depot = hosts[0]
			self.config['depotId'] = depot.getId()
			logger.notice(u"Running on depot server '%s', exporting repository directory" % self.config['depotId'])
			if not depot.getRepositoryLocalUrl():
				raise Exception(u"Repository local url for depot '%s' not found" % self.config['depotId'])
			if not depot.getRepositoryLocalUrl().startswith('file:///'):
				raise Exception(u"Repository local url '%s' not allowed" % depot.getRepositoryLocalUrl())
			path = depot.getRepositoryLocalUrl()[7:]
			if not os.path.isdir(path):
				raise Exception(u"Cannot add webdav content 'repository': directory '%s' does not exist." % path)
			if not os.access(path, os.R_OK | os.W_OK | os.X_OK):
				raise Exception(u"Cannot add webdav content 'repository': permissions on directory '%s' not sufficient." % path)
			
			self.config['staticDirectories']['repository'] = path
			
			logger.notice(u"Running on depot server '%s', exporting depot directory" % self.config['depotId'])
			if not depot.getDepotLocalUrl():
				raise Exception(u"Repository local url for depot '%s' not found" % self.config['depotId'])
			if not depot.getDepotLocalUrl().startswith('file:///'):
				raise Exception(u"Repository local url '%s' not allowed" % depot.getDepotLocalUrl())
			path = depot.getDepotLocalUrl()[7:]
			if not os.path.isdir(path):
				raise Exception(u"Cannot add webdav content 'depot': directory '%s' does not exist." % path)
			if not os.access(path, os.R_OK | os.W_OK | os.X_OK):
				raise Exception(u"Cannot add webdav content 'depot': permissions on directory '%s' not sufficient." % path)
			
			self.config['staticDirectories']['depot'] = path
		
		for (name, path) in self.config['staticDirectories'].items():
			if (name == '/'):
				continue
			
			if name in ('rpc', 'interface', 'info'):
				logger.error(u"Cannot add static content '%s', already in use!" % name)
				continue
			
			if not os.path.isdir(path):
				logger.error(u"Cannot add static content '%s': directory '%s' does not exist." % (name, path))
				continue
			
			readOnly = True
			if name in ('repository', 'depot'):
				readOnly = False
			
			self._root.putChild(name, ResourceOpsiDAV(self, path, readOnly = readOnly))
			logger.notice(u"Added webdav content '%s' which points to directory '%s'" % (name, path))
		
		self._site = server.Site(self._root)
	
	def _startListening(self):
		logger.info(u"Creating ports")
		self._startListeningHTTP()
		self._startListeningHTTPS()
		
	def _startListeningHTTP(self, dontcare=None):
		if (self.config['httpPort'] <= 0):
			self._httpPort = None
			return
		
		if (self.config['interface'] == '0.0.0.0'):
			self._httpPort = reactor.listenTCP(
				self.config['httpPort'],
				HTTPFactory(self._site)
			)
		else:
			self._httpPort = reactor.listenTCP(
				self.config['httpPort'],
				HTTPFactory(self._site),
				interface = self.config['interface']
			)
		
		logger.notice(u"Accepting HTTP requests on %s:%s" % (self.config['interface'], self.config['httpPort']))
	
	def _startListeningHTTPS(self, dontcare=None):
		if (self.config['httpsPort'] <= 0):
			self._httpsPort = None
			return
	
		if (self.config['interface'] == '0.0.0.0'):
			self._httpsPort = reactor.listenSSL(
				self.config['httpsPort'],
				HTTPFactory(self._site),
				SSLContext(self.config['sslServerKeyFile'], self.config['sslServerCertFile'])
			)
		else:
			self._httpsPort = reactor.listenSSL(
				self.config['httpsPort'],
				HTTPFactory(self._site),
				SSLContext(self.config['sslServerKeyFile'], self.config['sslServerCertFile']),
				interface = self.config['interface']
			)
		
		logger.notice(u"Accepting HTTPS requests on %s:%s" % (self.config['interface'], self.config['httpsPort']))
	
	def _publish(self):
		port = 0
		name = "opsi configuration daemon"
	
		if self._httpsPort is not None:
			port = self.config['httpsPort']
		elif self._httpPort is not None:
			port = self.config['httpPort']
		else:
			logger.notice(u"No open port found, there is nothing to publish")
			return
	
		logger.notice(u"Publishing opsiconfd over zeroconf as '%s' on '%s'" % (name, port))
		try:
			self._zeroconfService = ZeroconfService(name = name, port = port)
			self._zeroconfService.publish()
		except Exception, e:
			logger.error(u"Failed to publish opsiconfd over zeroconf: %s" % e)
		
	def run(self):
		self._running = True
		logger.notice(u"Starting opsiconfd main thread")
		try:
			self._createBackendInstance()
			self._createSessionHandler()
			self._createStatistics()
			self._createSite()
			self._startListening()
			self._publish()
			
			if not reactor.running:
				reactor.run(installSignalHandlers=0)
			
			logger.notice(u"Opsiconfd main thread exiting...")
		except Exception, e:
			logger.logException(e)
		self._running = False
	
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# -                                           OPSICONFD INIT                                          -
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
class OpsiconfdInit(object):
	def __init__(self):
		logger.debug(u"OpsiconfdInit")
		# Set umask
		os.umask(0077)
		self._pid = 0
		
		try:
			(self.opts, self.args) = getopt.getopt(sys.argv[1:], "vc:f:l:p:P:i:D")
		except getopt.GetoptError:
			self.usage()
			sys.exit(1)
		
		self.setDefaultConfig()
		# Process command line arguments
		for (opt, arg) in self.opts:
			if (opt == "-c"):
				self.config['configFile'] = forceFilename(arg)
			if   (opt == "-v"):
				print u"opsiconfd version %s" % __version__
				sys.exit(0)
		self.readConfigFile()
		self.setCommandlineConfig()
		
		# Call signalHandler on signal SIGHUP, SIGTERM, SIGINT
		signal(SIGHUP,  self.signalHandler)
		signal(SIGTERM, self.signalHandler)
		signal(SIGINT,  self.signalHandler)
		
		if self.config['daemon']:
			logger.setConsoleLevel(LOG_NONE)
			self.daemonize()
		else:
			logger.setConsoleLevel(self.config['logLevel'])
			logger.setConsoleColor(True)
		
		self.createPidFile()
		try:
			# Start opsiconfd
			self._opsiconfd = Opsiconfd(self.config)
			self._opsiconfd.start()
			
			# fix the process name on linux systems
			# this works for killall/pkill/top/ps -A, not for ps a
			libc = CDLL("libc.so.6")
			libc.prctl( 15, 'opsiconfd', 0, 0, 0)
			
			time.sleep(3)
			while self._opsiconfd.isRunning():
				time.sleep(1)
			self._opsiconfd.join(30)
		finally:
			self.removePidFile()
	
	def setDefaultConfig(self):
		self.config = {
			'pidFile'                      : u'/var/run/opsiconfd/opsiconfd.pid',
			'configFile'                   : u'/etc/opsi/opsiconfd.conf',
			'daemon'                       : False,
			'logLevel'                     : LOG_NOTICE,
			'logFile'                      : u'/var/log/opsi/opsiconfd/opsiconfd.log',
			'logFormat'                    : u'[%l] [%D] %M (%F|%N)',
			'symlinkLogs'                  : False,
			'httpPort'                     : 0,
			'httpsPort'                    : 4447,
			'interface'                    : u'0.0.0.0',
			'maxExecutionStatisticValues'  : 250,
			'sslServerCertFile'            : u'/etc/opsi/opsiconfd.pem',
			'sslServerKeyFile'             : u'/etc/opsi/opsiconfd.pem',
			'sessionName'                  : u'OPSISID',
			'maxSessionsPerIp'             : 25,
			'maxAuthenticationFailures'    : 3,
			'resolveVerifyIp'              : False,
			'sessionMaxInactiveInterval'   : 120,
			'updateIpAddress'              : False,
			'staticDirectories'            : {},
			'depotId'                      : None,
			'fqdn'                         : socket.getfqdn(),
			'ipAddress'                    : socket.gethostbyname(socket.gethostname()),
			'rrdDir'                       : u'/var/lib/opsiconfd/rrd',
			'backendConfigDir'             : u'/etc/opsi/backends',
			'dispatchConfigFile'           : u'/etc/opsi/backendManager/dispatch.conf',
			'extensionConfigDir'           : u'/etc/opsi/backendManager/extend.d',
			'aclFile'                      : u'/etc/opsi/backendManager/acl.conf'
		}
	
	def setCommandlineConfig(self):
		for (opt, arg) in self.opts:
			if   (opt == "-D"):
				self.config['daemon'] = True
			elif (opt == "-l"):
				self.config['logLevel'] = forceInt(arg)
			elif (opt == "-f"):
				self.config['logFile'] = forceFilename(arg)
			elif (opt == "-p"):
				self.config['httpPort'] = forceInt(arg)
			elif (opt == "-P"):
				self.config['httpsPort'] = forceInt(arg)
			elif (opt == "-i"):
				self.config['interface'] = forceUnicode(arg)
		
	def createPidFile(self):
		logger.info(u"Creating pid file '%s'" % self.config['pidFile'])
		if not os.path.exists(os.path.dirname(self.config['pidFile'])):
			os.makedirs(os.path.dirname(self.config['pidFile']))
		elif os.path.exists(self.config['pidFile']) and os.access(self.config['pidFile'], os.R_OK | os.W_OK):
			pf = open(self.config['pidFile'], 'r')
			p = pf.readline().strip()
			pf.close()
			if p:
				running = False
				try:
					for i in execute("%s -x opsiconfd" % which("pidof"))[0].strip().split():
						if (i == p):
							running = True
							break
				except Exception, e:
					logger.error(e)
				if running:
					raise Exception(u"Another opsiconfd process is running (pid: %s), stop process first or change pidfile." % p )
				
		pid = os.getpid()
		pf = open (self.config['pidFile'], "w")
		print >> pf, str(pid)
		pf.close()
	
	def removePidFile(self):
		try:
			# if (self._pid == os.getpid())
			if os.path.exists(self.config['pidFile']):
				logger.info(u"Removing pid file '%s'" % self.config['pidFile'])
				os.unlink(self.config['pidFile'])
		except Exception, e:
			logger.error(u"Failed to remove pid file '%s': %s" % (self.config['pidFile'], e))
		
	def signalHandler(self, signo, stackFrame):
		for thread in threading.enumerate():
			logger.debug(u"Running thread before signal: %s" % thread)
		
		if (signo == SIGHUP):
			if reactor and reactor.running and self._opsiconfd:
				self.setDefaultConfig()
				self.readConfigFile()
				self.setCommandlineConfig()
				self._opsiconfd.setConfig(self.config)
				reactor.callFromThread(self._opsiconfd.reload)
		
		if (signo == SIGTERM or signo == SIGINT):
			if reactor and reactor.running and self._opsiconfd:
				reactor.callFromThread(self._opsiconfd.stop)
				
		for thread in threading.enumerate():
			logger.debug(u"Running thread after signal: %s" % thread)
		
	def readConfigFile(self):
		''' Get settings from config file '''
		logger.notice(u"Trying to read config from file: '%s'" % self.config['configFile'])
		
		try:
			iniFile = IniFile(filename = self.config['configFile'], raw = True)
			config = iniFile.parse()
			
			for section in config.sections():
				logger.debug(u"Processing section '%s' in config file: '%s'" % (section, self.config['configFile']))
				if (section.lower() == 'global'):
					# Global settings
					for (option, value) in config.items(section):
						if (option == 'pid file'):
							self.config['pidFile'] = forceFilename(value)
						elif (option == 'log level'):
							self.config['logLevel'] = forceInt(value)
						elif (option == 'log file'):
							self.config['logFile'] = forceFilename(value)
						elif (option == 'log format'):
							self.config['logFormat'] = forceUnicode(value)
						elif (option == 'symlink logs'):
							self.config['symlinkLogs'] = forceBool(value)
						elif (option == 'backend config dir'):
							self.config['backendConfigDir'] = forceFilename(value)
						elif (option == 'dispatch config file'):
							self.config['dispatchConfigFile'] = forceFilename(value)
						elif (option == 'extension config dir'):
							self.config['extensionConfigDir'] = forceFilename(value)
						elif (option == 'acl file'):
							self.config['aclFile'] = forceFilename(value)
						elif (option == 'max execution statistics'):
							self.config['maxExecutionStatisticValues'] = forceInt(value)
						else:
							logger.warning(u"Ignoring unknown option '%s' in config file: '%s'" % (option, self.config['configFile']))
				
				elif (section.lower() == 'service'):
					# Service settings
					for (option, value) in config.items(section):
						if   (option == 'http port'):
							self.config['httpPort'] = forceInt(value)
						elif (option == 'https port'):
							self.config['httpsPort'] = forceInt(value)
						elif (option == 'interface'):
							self.config['interface'] = forceUnicode(value)
						elif (option == 'ssl server cert'):
							self.config['sslServerCertFile'] = forceFilename(value)
						elif (option == 'ssl server key'):
							self.config['sslServerKeyFile'] = forceFilename(value)
						else:
							logger.warning(u"Ignoring unknown option '%s' in config file: '%s'" % (option, self.config['configFile']))
				
				elif (section.lower() == 'session'):
					# Session settings
					for (option, value) in config.items(section):
						if   (option == 'session name'):
							self.config['sessionName'] = forceUnicode(value)
						elif (option == 'verify ip'):
							self.config['resolveVerifyIp'] = forceBool(value)
						elif (option == 'update ip'):
							self.config['updateIpAddress'] = forceBool(value)
						elif (option == 'max inactive interval'):
							self.config['sessionMaxInactiveInterval'] = forceInt(value)
						elif (option == 'max sessions per ip'):
							self.config['maxSessionsPerIp'] = forceInt(value)
						elif (option == 'max authentication failures'):
							self.config['maxAuthenticationFailures'] = forceInt(value)
						else:
							logger.warning(u"Ignoring unknown option '%s' in config file: '%s'" % (option, self.config['configFile']))
				
				elif (section.lower() == 'directories'):
					# Static directories
					self.config['staticDirectories'] = {}
					for (option, value) in config.items(section):
						self.config['staticDirectories'][option] = forceFilename(value)
				else:
					logger.warning(u"Ignoring unknown section '%s' in config file: '%s'" % (section, self.config['configFile']))
		
		except Exception, e:
			# An error occured while trying to read the config file
			logger.error(u"Failed to read config file '%s': %s" % (self.config['configFile'], e))
			logger.logException(e)
			raise
		logger.notice(u"Config read")
		
	def usage(self):
		print u"\nUsage: %s [-D] [-c <filename>] [-f <filename>] [-l <log level>] [-i <ipaddress>] [-p <http port>] [-P <https port>]" % os.path.basename(sys.argv[0])
		print u"Options:"
		print u"  -v    Show version information and exit"
		print u"  -D    Causes the server to operate as a daemon"
		print u"  -p    HTTP Port to listen on (0 to disable)"
		print u"  -P    HTTPS Port to listen on (0 to disable)"
		print u"  -i    IP address of interface to listen on (default: 0.0.0.0)"
		print u"  -f    Log to given file instead of syslog"
		print u"  -c    Location of config file"
		print u"  -l    Set log level (default: 4)"
		print u"        0=nothing, 1=essential, 2=critical, 3=error, 4=warning"
		print u"        5=notice, 6=info, 7=debug, 8=debug2, 9=confidential"
		print u""
	
	def daemonize(self):
		# Fork to allow the shell to return and to call setsid
		try:
			self._pid = os.fork()
			if (self._pid > 0):
				# Parent exits
				sys.exit(0)
		except OSError, e:
			raise Exception(u"First fork failed: %e" % e)
		
		# Do not hinder umounts
		os.chdir("/")
		# Create a new session
		os.setsid()
		
		# Fork a second time to not remain session leader
		try:
			self._pid = os.fork()
			if (self._pid > 0):
				sys.exit(0)
		except OSError, e:
			raise Exception(u"Second fork failed: %e" % e)
		
		logger.setConsoleLevel(LOG_NONE)
		
		# Close standard output and standard error.
		os.close(0)
		os.close(1)
		os.close(2)
		
		# Open standard input (0)
		if (hasattr(os, "devnull")):
			os.open(os.devnull, os.O_RDWR)
		else:
			os.open("/dev/null", os.O_RDWR)
		
		# Duplicate standard input to standard output and standard error.
		os.dup2(0, 1)
		os.dup2(0, 2)
		sys.stdout = logger.getStdout()
		sys.stderr = logger.getStderr()

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# -                                               MAIN                                                -
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
def main():
	logger.setConsoleLevel(LOG_WARNING)
	exception = None
	
	try:
		OpsiconfdInit()
		
	except SystemExit, e:
		pass
		
	except Exception, e:
		exception = e
	
	if exception:
		logger.logException(exception)
		print >> sys.stderr, u"ERROR:", unicode(exception)
		return(1)
	return(0)
	
if __name__=="__main__":
	sys.exit(main())


