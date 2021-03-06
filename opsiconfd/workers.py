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
opsi configuration daemon - workers

:copyright: uib GmbH <info@uib.de>
:author: Jan Schneider <j.schneider@uib.de>
:author: Niko Wenselowski <n.wenselowski@uib.de>
:license: GNU Affero General Public License version 3
"""

import base64
import os
import re
import socket

from twisted.internet import defer, threads
from twisted.python import failure

from OPSI.Backend.BackendManager import BackendAccessControl, backendManagerFactory
from OPSI.Exceptions import BackendMissingDataError, OpsiAuthenticationError
from OPSI.Logger import Logger, LOG_INFO
from OPSI.Service.Worker import (
	WorkerOpsi, WorkerOpsiJsonRpc, WorkerOpsiJsonInterface, WorkerOpsiDAV,
	interfacePage, MultiprocessWorkerOpsiJsonRpc)
from OPSI.Types import forceHostId, forceHardwareAddress
from OPSI.Util import (
	timestamp, objectToHtml, toJson, decryptWithPrivateKeyFromPEMFile,
	ipAddressInNetwork, serialize)
from OPSI.Util.HTTP import deflateDecode, gzipDecode
from OPSI.web2 import responsecode, http, stream


logger = Logger()


class WorkerOpsiconfd(WorkerOpsi):
	def __init__(self, service, request, resource):
		WorkerOpsi.__init__(self, service, request, resource)
		self._setLogFile(self)

		self.authRealm = 'OPSI Configuration Service'

	def _setLogFile(self, obj):
		if self.service.config['machineLogs'] and self.service.config['logFile']:
			machineName = self.request.remoteAddr.host
			if not self.service.config['symlinkLogs']:
				try:
					machineName = self.session.hostname
				except AttributeError:
					# With a fresh session there may not yet be an
					# hostname assigned to the session so this may fail.
					pass

			logger.setLogFile(self.service.config['logFile'].replace('%m', machineName), object=obj)

	def _linkLogFile(self, result):
		def linkingRequired(config):
			return config['machineLogs'] and config['logFile'] and config['symlinkLogs']

		if self.session.hostname and linkingRequired(self.service.config):
			logger.linkLogFile(self.service.config['logFile'].replace('%m', self.session.hostname), object=self)

		return result

	def _errback(self, failure):
		result = WorkerOpsi._errback(self, failure)
		if result.code == responsecode.UNAUTHORIZED and self.request.remoteAddr.host not in (self.service.config['ipAddress'], '127.0.0.1'):
			if self.service.config['maxAuthenticationFailures'] > 0:
				try:
					self.service.authFailureCount[self.request.remoteAddr.host] += 1
				except KeyError:
					self.service.authFailureCount[self.request.remoteAddr.host] = 1

				if self.service.authFailureCount[self.request.remoteAddr.host] > self.service.config['maxAuthenticationFailures']:
					logger.error(
						u"%s authentication failures from '%s' in a row, waiting 60 seconds to prevent flooding"
						% (self.service.authFailureCount[self.request.remoteAddr.host], self.request.remoteAddr.host)
					)
					# Will prevent flooding, before block for prevention,
					# delete actual remoteAddr to reset the
					# maxAuthenticationFailure marker
					del self.service.authFailureCount[self.request.remoteAddr.host]
					return self._delayResult(60, result)
		return result

	def _getAuthorization(self):
		user = password = u''
		logger.debug(u"Trying to get username and password from Authorization header")
		auth = self.request.headers.getHeader('Authorization')
		if auth:
			try:
				logger.debug(u"Authorization header found (type: %s)" % auth[0])
				logger.confidential(u"Auth encoded: %s" % auth[1])
				authString = None
				if auth[0].lower() == 'opsi':
					try:
						authString = unicode(
							decryptWithPrivateKeyFromPEMFile(
								base64.decodestring(auth[1]),
								self.service.config['sslServerKeyFile']), 'latin-1').strip()
					except Exception as error:
						logger.logException(error)
						raise
				else:
					authString = unicode(base64.decodestring(auth[1]), 'latin-1').strip()

				parts = authString.split(':')
				if len(parts) > 6:
					user = u':'.join(parts[:6])
					password = u':'.join(parts[6:])
				else:
					user = parts[0]
					password = u':'.join(parts[1:])
				user = user.strip()
				logger.confidential(u"Client supplied username '%s' and password '%s'" % (user, password))
			except Exception as error:
				logger.error(u"Bad Authorization header from '%s': %s" % (self.request.remoteAddr.host, error))
		return (user, password)

	def _getCredentials(self):
		(user, password) = self._getAuthorization()
		self.session.isHost = False
		if not user:
			logger.warning(u"No username from %s (application: %s)" % (self.session.ip, self.session.userAgent))
			try:
				(hostname, aliaslist, ipaddrlist) = socket.gethostbyaddr(self.session.ip)
				user = forceHostId(hostname)
			except Exception as error:
				raise Exception(u"No username given and resolve failed: %s" % error)

		if user.count('.') >= 2:
			self.session.isHost = True
			if '_' in user:
				user = forceHostId(user.replace('_', '-'))
		elif re.search('^([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})$', user):
			self.session.isHost = True
			mac = forceHardwareAddress(user)
			logger.info(u"Found hardware address '%s' as username, searching host in backend" % mac)
			hosts = self.service._backend.host_getObjects(hardwareAddress=mac)
			if not hosts:
				raise Exception(u"Host with hardware address '%s' not found in backend" % mac)
			user = hosts[0].id
			logger.info(u"Hardware address '%s' found in backend, using '%s' as username" % (mac, user))

		if self.session.isHost:
			if not self.session.hostname:
				logger.debug(u"Storing hostname {0!r} in session", user)
				self.session.hostname = user

			hosts = None
			try:
				hosts = self.service._backend.host_getObjects(type='OpsiClient', id=user)
			except Exception as error:
				logger.debug(u"Host not found: %s" % error)

			if hosts:
				if password and hosts[0].getOneTimePassword() and password == hosts[0].getOneTimePassword():
					logger.info(u"Client '%s' supplied one-time password" % user)
					password = hosts[0].getOpsiHostKey()
					hosts[0].oneTimePassword = None
					self.service._backend.host_createObjects(hosts[0])

		return (user, password)

	def _getSessionId(self):
		sessionId = WorkerOpsi._getSessionId(self)
		if not sessionId:
			logger.notice(u"Application '%s' on client '%s' did not send cookie" % (self._getUserAgent(), self.request.remoteAddr.host))
			(user, password) = self._getAuthorization()
			if not password:
				raise OpsiAuthenticationError(u"Application '%s' on client '%s' did neither supply session id nor password" % (self._getUserAgent(), self.request.remoteAddr.host))

		return sessionId

	def _getSession(self, result):
		WorkerOpsi._getSession(self, result)
		if self.session.user and self.session.user.count('.') >= 2:
			self.session.isHost = True

		if self.session.isHost and not self.session.hostname:
			logger.info(u"Storing hostname '%s' in session" % self.session.user)
			self.session.hostname = self.session.user
		return self._linkLogFile(result)

	def _authenticate(self, result):
		'''
		This function tries to authenticate a user.
		Raises an exception on authentication failure.
		'''

		if self.session.authenticated:
			return result

		try:
			(self.session.user, self.session.password) = self._getCredentials()

			if self.session.isHost:
				logger.notice(u"Authorization request from host %s@%s (application: %s)" % (self.session.user, self.session.ip, self.session.userAgent))
			else:
				logger.notice(u"Authorization request from %s@%s (application: %s)" % (self.session.user, self.session.ip, self.session.userAgent))

			if not self.session.user:
				raise Exception(u"No username from %s (application: %s)" % (self.session.ip, self.session.userAgent))

			if not self.session.password:
				raise Exception(u"No password from %s (application: %s)" % (self.session.ip, self.session.userAgent))

			if self.session.hostname and self.service.config['resolveVerifyIp'] and (self.session.user != self.service.config['fqdn']):
				try:
					(_, _, addressList) = socket.gethostbyname_ex(self.session.hostname)
				except Exception as error:
					logger.warning(u"Failed to resolve hostname '%s': %s" % (self.session.hostname, error))
					addressList = []

				if self.session.ip not in addressList:
					# Username (FQDN) of peer does not resolve to peer's ip address
					logger.critical(
						u"Host login attempt with username '%s'"
						u" from ip '%s', but name resolves to '%s' "
						u"(access denied)" % (
							self.session.user,
							self.session.ip,
							addressList
						)
					)

					raise Exception(
						u"Access denied for username '%s' from '%s'" % (
							self.session.user, self.session.ip
						)
					)

			if len(self.service.config['adminNetworks']) == 1 and self.service.config['adminNetworks'][0] == u'0.0.0.0/0':
				adminNetwork = True
			else:
				adminNetwork = any(
					ipAddressInNetwork(self.session.ip, networkAddress)
					for networkAddress in self.service.config['adminNetworks']
				)

			if adminNetwork:
				logger.info(u"Connection from admin network")
				forceGroups = None
			else:
				forceGroups = []
				logger.info(u"Connection from non admin network")

			bac = BackendAccessControl(
				backend=self.service._backend,
				username=self.session.user,
				password=self.session.password,
				forceGroups=forceGroups
			)
			if not bac.accessControl_authenticated():
				raise Exception(u"Bad user or password")

			if adminNetwork:
				self.session.isAdmin = bac.accessControl_userIsAdmin()
			else:
				self.session.isAdmin = False

			self.session.isReadOnlyUser = bac.accessControl_userIsReadOnlyUser()

			self.session.authenticated = self._authorize()
			if not self.session.authenticated:
				raise Exception("Access denied: User or host is not authorized for this resource.")

			try:
				del self.service.authFailureCount[self.request.remoteAddr.host]
			except KeyError:
				pass  # May not be present
		except Exception as error:
			logger.logException(error, LOG_INFO)
			errorMessage = u"Authentication failure for '%s' from '%s': %s" % (self.session.user or '', self.session.ip or '', error)
			self._freeSession(result)
			self.service._getSessionHandler().deleteSession(self.session.uid)
			raise OpsiAuthenticationError(errorMessage)
		return result

	def _authorize(self):
		return True

	def _getBackend(self, result):
		if self.session.callInstance and self.session.callInterface:
			if len(self.session.postpath) == len(self.request.postpath):
				postpathMatch = True
				for i in range(len(self.request.postpath)):
					if self.request.postpath[i] != self.session.postpath[i]:
						postpathMatch = False

				if postpathMatch:
					return result

			self.session.interface = None
			self.session.callInstance.backend_exit()

		self.session.postpath = self.request.postpath

		forceGroups = []
		if len(self.service.config['adminNetworks']) == 1 and self.service.config['adminNetworks'][0] == u'0.0.0.0/0':
			forceGroups = None
		else:
			for networkAddress in self.service.config['adminNetworks']:
				if ipAddressInNetwork(self.session.ip, networkAddress):
					forceGroups = None
					break

		def _createBackend():
			self.session.postpath = self.request.postpath
			self.session.callInstance = backendManagerFactory(
				user=self.session.user,
				password=self.session.password,
				forceGroups=forceGroups,
				dispatchConfigFile=self.service.config['dispatchConfigFile'],
				backendConfigDir=self.service.config['backendConfigDir'],
				extensionConfigDir=self.service.config['extensionConfigDir'],
				aclFile=self.service.config['aclFile'],
				depotId=self.service.config['depotId'],
				postpath=self.request.postpath,
				context=self.service._backend,
				startReactor=False
			)

		d = defer.maybeDeferred(_createBackend)

		def finish(ignored):
			self.session.callInterface = None
			self.session.isAdmin = False

			def setInterface(interface):
				self.session.callInterface = interface

			def setCredentials(isAdmin):
				self.session.isAdmin = isAdmin

			df = defer.maybeDeferred(self.session.callInstance.backend_getInterface)
			df.addCallback(setInterface)
			df.addCallback(lambda x: defer.maybeDeferred(self.session.callInstance.accessControl_userIsAdmin))
			df.addCallback(setCredentials)

			def updateIPOfClient():
				if self.session.isHost:
					hosts = self.service._backend.host_getObjects(['ipAddress', 'lastSeen'], id=self.session.user)
					if not hosts:
						raise BackendMissingDataError(u"Host '%s' not found in backend" % self.session.user)
					host = hosts[0]
					if host.getType() == 'OpsiClient':
						host.setLastSeen(timestamp())
						if self.service.config['updateIpAddress'] and host.ipAddress != self.session.ip and self.session.ip != '127.0.0.1':
							host.setIpAddress(self.session.ip)
						else:
							# Value None on update means no change!
							host.ipAddress = None
						self.service._backend.host_updateObjects(host)

			df.addCallback(lambda x: updateIPOfClient())
			return df
		d.addCallback(finish)
		return d

	def _setResponse(self, result):
		deferred = threads.deferToThread(self._generateResponse, result)
		return deferred

	def _setCookie(self, result):
		result = WorkerOpsi._setCookie(self, result)
		return self._processOpsiServiceVerificationKey(result)

	def _processOpsiServiceVerificationKey(self, result):
		try:
			for key, value in self.request.headers.getAllRawHeaders():
				if key.lower() == 'x-opsi-service-verification-key':
					logger.debug(u"Adding header x-opsi-service-verification-key")

					verificationKey = decryptWithPrivateKeyFromPEMFile(
						base64.decodestring(value[0]),
						self.service.config['sslServerKeyFile']
					)

					if not isinstance(result, http.Response):
						result = http.Response()

					result.headers.setRawHeaders(
						'X-opsi-service-verification-key',
						[verificationKey]
					)

					break  # to avoid unnecessary further iteration
		except Exception as error:
			logger.logException(error)
			logger.error(u"Failed to process opsi service verification key: {0!r}", error)

		return result


class WorkerOpsiconfdJsonRpc(WorkerOpsiconfd, WorkerOpsiJsonRpc, MultiprocessWorkerOpsiJsonRpc):
	def __init__(self, service, request, resource):
		WorkerOpsiconfd.__init__(self, service, request, resource)
		WorkerOpsiJsonRpc.__init__(self, service, request, resource)

		modules = self.service._backend.backend_info()['modules']

	def _getCallInstance(self, result):
		d = defer.maybeDeferred(self._getBackend, result)

		def setInterface():
			self._callInstance = self.session.callInstance
			self._callInterface = self.session.callInterface

		d.addCallback(lambda x: setInterface())

		return d

	def _getSessionId(self):
		return WorkerOpsiconfd._getSessionId(self)

	def _getRpcs(self, result):
		if not self.query:
			return result

		self.session.setLastRpcSuccessfullyDecoded(False)
		result = WorkerOpsiJsonRpc._getRpcs(self, result)
		self.session.setLastRpcSuccessfullyDecoded(True)
		return result

	def _executeRpc(self, result, rpc):
		self._setLogFile(rpc)
		self.session.setLastRpcMethod(rpc.getMethodName())
		if rpc.getMethodName() == 'backend_exit':
			logger.notice(u"User '%s' asked to close the session" % self.session.user)
			self._freeSession(result)
			self.service._getSessionHandler().deleteSession(self.session.uid)
			return result

		result = WorkerOpsiJsonRpc._executeRpc(self, result, rpc)
		result.addCallback(self._addRpcToStatistics, rpc)
		result.addCallback(self._addUserAgentToStatistics)
		return result

	def _addRpcToStatistics(self, result, rpc):
		self.service.statistics().addRpc(rpc)
		return result

	def _addUserAgentToStatistics(self, result):
		self.service.statistics().addUserAgent(self.session.userAgent)
		return result

	def _decodeQuery(self, result):
		try:
			if self.request.method == 'POST':
				contentType = self.request.headers.getHeader('content-type')
				try:
					contentEncoding = self.request.headers.getHeader('content-encoding')[0].lower()
				except Exception:
					contentEncoding = None

				logger.debug(u"Content-Type: {0}, Content-Encoding: {1}", contentType, contentEncoding)
				if contentType and contentType.mediaType.startswith('gzip'):
					# Invalid MIME type.
					# Probably it is gzip-application/json-rpc and therefore
					# we need to behave like we did before.
					logger.debug(u"Expecting compressed data from client (backwards compatible)")
					self.query = deflateDecode(self.query)
				elif contentEncoding == 'gzip':
					logger.debug(u"Expecting gzip compressed data from client")
					self.query = gzipDecode(self.query)
				elif contentEncoding == 'deflate':
					logger.debug(u"Expecting deflate compressed data from client")
					self.query = deflateDecode(self.query)

			if not isinstance(self.query, unicode):
				self.query = unicode(self.query, 'utf-8')
		except (UnicodeError, UnicodeEncodeError) as error:
			logger.logException(error)
			self.service.statistics().addEncodingError('query', self.session.ip, self.session.userAgent, unicode(error))
			logger.debug(u"Failed at Decoding query (type {}): {!r}", type(self.query), self.query)
			if not isinstance(self.query, unicode):
				self.query = unicode(self.query, 'utf-8', 'replace')
				logger.debug(u"Fallback Decoded query: {!r}", self.query)
		except Exception as error:
			logger.logException(error)
			logger.warning("Unexpected error during decoding of query: {0}".format(error))
			raise error

		logger.debug2(u"query: {0}", self.query)
		return result

	def _processQuery(self, result):
		return WorkerOpsiJsonRpc._processQuery(self, result)

	def _generateResponse(self, result):
		return WorkerOpsiJsonRpc._generateResponse(self, result)

	def _setCookie(self, result):
		return WorkerOpsiconfd._setCookie(self, result)

	def _renderError(self, failure):
		return WorkerOpsiJsonRpc._renderError(self, failure)


class WorkerOpsiconfdJsonInterface(WorkerOpsiconfdJsonRpc, WorkerOpsiJsonInterface):
	def __init__(self, service, request, resource):
		WorkerOpsiJsonInterface.__init__(self, service, request, resource)
		WorkerOpsiconfdJsonRpc.__init__(self, service, request, resource)

	def _getSessionId(self):
		return WorkerOpsiconfd._getSessionId(self)

	def _generateResponse(self, result):
		logger.info(u"Creating opsiconfd interface page")

		javascript = [
			u"var currentParams = new Array();",
			u"var currentMethod = null;"
		]
		currentMethod = u''
		if self._rpcs:
			currentMethod = self._rpcs[0].getMethodName()
			javascript.append(u"currentMethod = '%s';" % currentMethod)
			for (i, param) in enumerate(self._rpcs[0].params):
				javascript.append(u"currentParams[%d] = '%s';" % (i, toJson(param)))

		currentPath = u'interface'
		selected = u' selected="selected"'
		for pp in self.request.postpath:
			currentPath = u'{0}/{1}'.format(currentPath, pp)
			selected = u''
		javascript.append(u"path = '%s';" % currentPath)

		selectPath = [u'<option%s>interface</option>' % selected]
		for name in self.service.getBackend().dispatcher_getBackendNames():
			selected = u''
			path = u'interface/backend/%s' % name
			if path == currentPath:
				selected = u' selected="selected"'
			selectPath.append('<option%s>%s</option>' % (selected, path))

		for name in os.listdir(self.service.config['extensionConfigDir']):
			if not os.path.isdir(os.path.join(self.service.config['extensionConfigDir'], name)):
				continue
			selected = u''
			path = u'interface/extend/%s' % name
			if path == currentPath:
				selected = u' selected="selected"'
			selectPath.append('<option%s>%s</option>' % (selected, path))

		selectMethod = []
		if self._callInterface:
			for method in self._callInterface:
				methodName = method['name']
				javascript.append(u"parameters['%s'] = new Array();" % methodName)
				for (index, param) in enumerate(method['params']):
					javascript.append(u"parameters['%s'][%s]='%s';" % (methodName, index, param))
				selected = u''
				if methodName == currentMethod:
					selected = u' selected="selected"'
				selectMethod.append(u'<option%s>%s</option>' % (selected, methodName))

		def wrapInDiv(obj):
			return u'<div class="json">{0}</div>'.format(obj)

		resultDiv = [u'<div id="result">']
		if isinstance(result, failure.Failure):
			error = u'Unknown error'
			try:
				result.raiseException()
			except Exception as err:
				error = {'class': err.__class__.__name__, 'message': unicode(err)}
				error = toJson({"id": None, "result": None, "error": error})
			resultDiv.append(wrapInDiv(objectToHtml(error)))
		else:
			for rpc in self._rpcs:
				resultDiv.append(wrapInDiv(objectToHtml(serialize(rpc.getResponse()))))
		resultDiv.append(u'</div>')

		html = interfacePage % {
			'path': currentPath,
			'title': u'opsiconfd interface page',
			'javascript': u'\n'.join(javascript),
			'select_path': u''.join(selectPath),
			'select_method': u''.join(selectMethod),
			'result': u''.join(resultDiv)
		}

		if not isinstance(result, http.Response):
			result = http.Response()
		result.code = responsecode.OK
		result.stream = stream.IByteStream(html.encode('utf-8').strip())

		return result

	def _authorize(self):
		if not self.session.isAdmin:
			logger.error(u"Authentication Error: No admin user.")
			return False
		logger.debug(u"User is authorized.")
		return True

	def _renderError(self, failure):
		return WorkerOpsiJsonInterface._renderError(self, failure)


class WorkerOpsiconfdDAV(WorkerOpsiDAV, WorkerOpsiconfd):
	def __init__(self, service, request, resource):
		WorkerOpsiDAV.__init__(self, service, request, resource)
		WorkerOpsiconfd.__init__(self, service, request, resource)

	def _setResponse(self, result):
		logger.debug(u"Client requests opsiconfd DAV operation: %s" % self.request)

		if (not self.resource._authRequired or not self.session.isAdmin) and self.request.method not in ('GET', 'PROPFIND', 'OPTIONS', 'USERINFO', 'HEAD'):
			logger.critical(u"Method '%s' not allowed (read only)" % self.request.method)
			return http.Response(code=responsecode.FORBIDDEN, stream="Readonly!")

		return self.resource.renderHTTP_super(self.request, self)

	def _getCredentials(self):
		return WorkerOpsiconfd._getCredentials(self)

	def _authenticate(self, result):
		logger.debug("WorkerOpsiconfdDAV._authenticate")
		return WorkerOpsiconfd._authenticate(self, result)

	def _authorize(self):
		if not self.session.isHost and not self.session.isAdmin:
			logger.error(u"Authentication Error: Neither host nor admin user.")
			return False
		return True

	def _setCookie(self, result):
		return WorkerOpsiconfd._setCookie(self, result)
