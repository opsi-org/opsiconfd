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

from twisted.internet import defer, threads

from OPSI.web2 import responsecode, http, stream

from OPSI.Service.Worker import WorkerOpsi, WorkerOpsiJsonRpc, WorkerOpsiJsonInterface, WorkerOpsiDAV, interfacePage
from OPSI.Types import *
from OPSI.Util import timestamp, objectToHtml, toJson, fromJson
from OPSI.Object import serialize, deserialize
from OPSI.Backend.BackendManager import BackendManager, BackendAccessControl
from OPSI.Logger import *

logger = Logger()

class WorkerOpsiconfd(WorkerOpsi):
	def __init__(self, service, request, resource):
		WorkerOpsi.__init__(self, service, request, resource)
		self._setLogFile(self)
	
	def process(self):
		logger.info(u"Worker %s started processing" % self)
		deferred = defer.Deferred()
		deferred.addCallback(self._getSession)
		deferred.addCallback(self._linkLogFile)
		deferred.addCallback(self._authenticate)
		deferred.addCallback(self._getQuery)
		deferred.addCallback(self._decodeQuery)
		deferred.addCallback(self._setResponse)
		deferred.addCallback(self._setCookie)
		deferred.addCallback(self._freeSession)
		deferred.addErrback(self._errback)
		deferred.callback(None)
		return deferred
	
	def _setLogFile(self, obj):
		if self.service.config['machineLogs'] and self.service.config['logFile']:
			logger.setLogFile( self.service.config['logFile'].replace('%m', self.request.remoteAddr.host), object = obj )
	
	def _linkLogFile(self, result):
		if self.session.hostname and self.service.config['machineLogs'] and self.service.config['logFile']:
			logger.linkLogFile( self.service.config['logFile'].replace('%m', self.session.hostname), object = self )
		return result
	
	def _errback(self, failure):
		result = WorkerOpsi._errback(self, failure)
		if (result.code == responsecode.UNAUTHORIZED) and self.request.remoteAddr.host not in (self.service.config['ipAddress'], '127.0.0.1'):
			if (self.service.config['maxAuthenticationFailures'] > 0):
				if not self.service.authFailureCount.has_key(self.request.remoteAddr.host):
					self.service.authFailureCount[self.request.remoteAddr.host] = 0
				self.service.authFailureCount[self.request.remoteAddr.host] += 1
				if (self.service.authFailureCount[self.request.remoteAddr.host] > self.service.config['maxAuthenticationFailures']):
					logger.error(u"%s authentication failures from '%s' in a row, waiting 60 seconds to prevent flooding" \
							% (self.service.authFailureCount[self.request.remoteAddr.host], self.request.remoteAddr.host))
					return self._delayResult(60, result)
		return result
	
	def _getCredentials(self):
		(user, password) = self._getAuthorization()
		isHost = False
		if not user:
			logger.warning(u"No username from %s (application: %s)" % (self.session.ip, self.session.userAgent))
			try:
				(hostname, aliaslist, ipaddrlist) = socket.gethostbyaddr(self.session.ip)
				user = forceHostId(hostname)
			except Exception, e:
				raise Exception(u"No username given and resolve failed: %s" % e)
		
		if (user.count('.') >= 2):
			isHost = True
			if (user.find('_') != -1):
				user = user.replace('_', '-')
		elif re.search('^([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})$', user):
			isHost = True
			mac = forceHardwareAddress(user)
			logger.info(u"Found hardware address '%s' as username, searching host in backend" % mac)
			hosts = self.service._backend.host_getObjects(hardwareAddress = mac)
			if not hosts:
				raise Exception(u"Host with hardware address '%s' not found in backend" % mac)
			user = hosts[0].id
			logger.info(u"Hardware address '%s' found in backend, using '%s' as username" % (mac, user))
		
		if isHost:
			hosts = None
			try:
				hosts = self.service._backend.host_getObjects(type = 'OpsiClient', id = forceHostId(user))
			except Exception, e:
				logger.debug(u"Host not found: %s" % e)
			
			if hosts:
				if password and hosts[0].getOneTimePassword() and (password == hosts[0].getOneTimePassword()):
					logger.info(u"Client '%s' supplied one-time password" % user)
					password = hosts[0].getOpsiHostKey()
					hosts[0].oneTimePassword = None
					self.service._backend.host_createObjects(hosts[0])
		return (user, password)
	
	def _getSession(self, result):
		WorkerOpsi._getSession(self, result)
		if self.session.user and (self.session.user.count('.') >= 2):
			self.session.isHost = True
		if self.session.isHost and not self.session.hostname:
			logger.info(u"Storing hostname '%s' in session" % self.session.user)
			self.session.hostname = self.session.user
		
	def _authenticate(self, result):
		''' This function tries to authenticate a user.
		    Raises an exception on authentication failure. '''
		if self.session.authenticated:
			return result
		
		try:
			# Get authorization
			(self.session.user, self.session.password) = self._getCredentials()
			
			logger.notice(u"Authorization request from %s@%s (application: %s)" % (self.session.user, self.session.ip, self.session.userAgent))
			
			if not self.session.user:
				raise Exception(u"No username from %s (application: %s)" % (self.session.ip, self.session.userAgent))
				
			if not self.session.password:
				raise Exception(u"No password from %s (application: %s)" % (self.session.ip, self.session.userAgent))
				
			if self.session.hostname and self.service.config['resolveVerifyIp'] and (self.session.user != self.service.config['fqdn']):
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
			
			self._getBackend(result)
			
			self.session.authenticated = True
			if self.service.authFailureCount.has_key(self.request.remoteAddr.host):
				del self.service.authFailureCount[self.request.remoteAddr.host]
		except Exception, e:
			logger.logException(e, LOG_INFO)
			self._freeSession(result)
			self._getSessionHandler().deleteSession(self.session.uid)
			raise OpsiAuthenticationError(u"Forbidden: %s" % e)
		return result
	
	def _getBackend(self, result):
		if self.session.callInstance and self.session.callInterface:
			if (len(self.session.postpath) == len(self.request.postpath)):
				postpathMatch = True
				for i in range(len(self.request.postpath)):
					if (self.request.postpath[i] != self.session.postpath[i]):
						postpathMatch = False
				if postpathMatch:
					return result
			self.session.interface = None
			self.session.callInstance.backend_exit()
		
		self.session.postpath = self.request.postpath
		if   (len(self.request.postpath) == 2) and (self.request.postpath[0] == 'backend'):
			self.session.callInstance = BackendManager(
				backend              = self.request.postpath[1],
				accessControlContext = self.service._backend,
				backendConfigDir     = self.service.config['backendConfigDir'],
				aclFile              = self.service.config['aclFile'],
				username             = self.session.user,
				password             = self.session.password
			)
		elif (len(self.request.postpath) == 2) and (self.request.postpath[0] == 'extend'):
			extendPath = self.request.postpath[1]
			if not re.search('^[a-zA-Z0-9\_\-]+$', extendPath):
				raise ValueError(u"Extension config path '%s' refused" % extendPath)
			self.session.callInstance = BackendManager(
				dispatchConfigFile   = self.service.config['dispatchConfigFile'],
				backendConfigDir     = self.service.config['backendConfigDir'],
				extensionConfigDir   = os.path.join(self.service.config['extensionConfigDir'], extendPath),
				aclFile              = self.service.config['aclFile'],
				accessControlContext = self.service._backend,
				depotBackend         = bool(self.service.config['depotId']),
				hostControlBackend   = True,
				username             = self.session.user,
				password             = self.session.password
			)
		else:
			self.session.callInstance = BackendManager(
				dispatchConfigFile   = self.service.config['dispatchConfigFile'],
				backendConfigDir     = self.service.config['backendConfigDir'],
				extensionConfigDir   = self.service.config['extensionConfigDir'],
				aclFile              = self.service.config['aclFile'],
				accessControlContext = self.service._backend,
				depotBackend         = bool(self.service.config['depotId']),
				hostControlBackend   = True,
				username             = self.session.user,
				password             = self.session.password
			)
		logger.notice(u'Backend created: %s' % self.session.callInstance)
		
		self.session.callInterface = self.session.callInstance.backend_getInterface()
		self.session.isAdmin = self.session.callInstance.accessControl_userIsAdmin()
		
		if self.session.isHost:
			hosts = self.service._backend.host_getObjects(['ipAddress', 'lastSeen'], id = self.session.user)
			if not hosts:
				raise Exception(u"Host '%s' not found in backend" % self.session.user)
			host = hosts[0]
			if (host.getType() == 'OpsiClient'):
				host.setLastSeen(timestamp())
				if self.service.config['updateIpAddress'] and (host.ipAddress != self.session.ip) and (self.session.ip != '127.0.0.1'):
					host.setIpAddress(self.session.ip)
				else:
					# Value None on update means no change!
					host.ipAddress = None
				self.service._backend.host_updateObjects(host)
		return result
	
	def _setResponse(self, result):
		deferred = threads.deferToThread(self._generateResponse, result)
		return deferred


class WorkerOpsiconfdJsonRpc(WorkerOpsiconfd, WorkerOpsiJsonRpc):
	def __init__(self, service, request, resource):
		WorkerOpsiconfd.__init__(self, service, request, resource)
		WorkerOpsiJsonRpc.__init__(self, service, request, resource)
		
	def process(self):
		logger.info("Worker %s started processing" % self)
		deferred = defer.Deferred()
		deferred.addCallback(self._getSession)
		deferred.addCallback(self._linkLogFile)
		deferred.addCallback(self._authenticate)
		deferred.addCallback(self._getCallInstance)
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
	
	def _getCallInstance(self, result):
		self._getBackend(result)
		self._callInstance = self.session.callInstance
		self._callInterface = self.session.callInterface
	
	def _getRpcs(self, result):
		if not self.query:
			return result
		
		self.session.setLastRpcSuccessfullyDecoded(False)
		result = WorkerOpsiJsonRpc._getRpcs(self, result)
		self.session.setLastRpcSuccessfullyDecoded(True)
		return result
	
	def _addRpcToStatistics(self, result, rpc):
		self.service.statistics().addRpc(rpc)
		return result
		
	def _executeRpc(self, result, rpc):
		self._setLogFile(rpc)
		self.session.setLastRpcMethod(rpc.getMethodName())
		if (rpc.getMethodName() == 'backend_exit'):
			logger.notice(u"User '%s' asked to close the session" % self.session.user)
			self._freeSession(result)
			self.service.getSessionHandler().deleteSession(self.session.uid)
			return result
		result = WorkerOpsiJsonRpc._executeRpc(self, result, rpc)
		result.addCallback(self._addRpcToStatistics, rpc)
		return result
	
	def _generateResponse(self, result):
		return WorkerOpsiJsonRpc._generateResponse(self, result)
	
class WorkerOpsiconfdJsonInterface(WorkerOpsiconfdJsonRpc, WorkerOpsiJsonInterface):
	def __init__(self, service, request, resource):
		WorkerOpsiconfdJsonRpc.__init__(self, service, request, resource)
		WorkerOpsiJsonInterface.__init__(self, service, request, resource)
	
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
		for name in self.service.getBackend().dispatcher_getBackendNames():
			selected = u''
			path = u'interface/backend/%s' % name
			if (path == currentPath):
				selected = u' selected="selected"'
			selectPath += '<option%s>%s</option>' % (selected, path)
		
		for name in os.listdir(self.service.config['extensionConfigDir']):
			if not os.path.isdir(os.path.join(self.service.config['extensionConfigDir'], name)):
				continue
			selected = u''
			path = u'interface/extend/%s' % name
			if (path == currentPath):
				selected = u' selected="selected"'
			selectPath += '<option%s>%s</option>' % (selected, path)
		
		selectMethod = u''
		for method in self.session.callInterface:
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
	

class WorkerOpsiconfdDAV(WorkerOpsiDAV):
	def __init__(self, service, request, resource):
		WorkerOpsiDAV.__init__(self, service, request, resource)
	
	def _authenticate(self, result):
		''' This function tries to authenticate a user.
		    Raises an exception on authentication failure. '''
		
		if self.session.authenticated:
			return result
		try:
			(self.session.user, self.session.password) = self._getCredentials()
			
			logger.notice(u"Authorization request from %s@%s (application: %s)" % (self.session.user, self.session.ip, self.session.userAgent))
			
			if not self.session.user:
				raise Exception(u"No username from %s (application: %s)" % (self.session.ip, self.session.userAgent))
				
			if not self.session.password:
				raise Exception(u"No password from %s (application: %s)" % (self.session.ip, self.session.userAgent))
			
			bac = BackendAccessControl(
				backend  = self.service._backend,
				username = self.session.user,
				password = self.session.password
			)
			if not bac.accessControl_authenticated():
				raise Exception(u"Bad user or password")
			
			self.session.isAdmin = bac.accessControl_userIsAdmin()
			
			if not self.session.isHost and not self.session.isAdmin:
				raise Exception(u"Neither host nor admin user")
			
			self.session.authenticated = True
			if self.service.authFailureCount.has_key(self.request.remoteAddr.host):
				del self.service.authFailureCount[self.request.remoteAddr.host]
		except Exception, e:
			logger.logException(e, LOG_INFO)
			self._freeSession(result)
			self.service.getSessionHandler().deleteSession(self.session.uid)
			raise OpsiAuthenticationError(u"Forbidden: %s" % e)
		return result
	













