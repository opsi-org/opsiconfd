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

from twisted.internet import defer
import resource as pyresource

import simplejson as json


from OPSI.web2 import http, resource, stream
from OPSI.Backend.BackendManager import BackendManager
from OPSI.Service.Worker import WorkerOpsi
from OPSI.Object import *

from OPSI.Service.Resource import ResourceOpsi
from OPSI.Logger import *
from cgi import escape
from pprint import pprint

logger = Logger()

class WorkerOpsiconfdMonitoring(WorkerOpsi):
	def __init__(self, opsiconfd, request, resource):
		moduleName = u' %-30s' % (u'monitoring')
		logger.setLogFormat(u'[%l] [%D] [' + moduleName + u'] %M   (%F|%N)', object=self)
		WorkerOpsi.__init__(self, opsiconfd, request, resource)
		self.opsiconfd = opsiconfd
		
		self._backend = BackendManager (
			dispatchConfigFile = self.opsiconfd.config['dispatchConfigFile'],
			backendConfigDir   = self.opsiconfd.config['backendConfigDir'],
			extensionConfigDir = self.opsiconfd.config['extensionConfigDir'],
			depotBackend       = bool(self.opsiconfd.config['depotId'])	
		)
		
		self.monitoring = Monitoring(self._backend)
		
	def process(self):
		logger.info(u"Worker %s started processing" % self)
		deferred = defer.Deferred()
		#deferred.addCallback(self._getSession)
		#deferred.addCallback(self._authenticate)
		deferred.addCallback(self._getQuery)
		deferred.addCallback(self._processQuery)
		deferred.addCallback(self._setResponse)
		#deferred.addCallback(self._setCookie)
		#deferred.addCallback(self._freeSession)
		deferred.addErrback(self._errback)
		deferred.callback(None)
		return deferred
	
	def _processQuery(self, result):
		self._decodeQuery(result)
		
	def _executeQuery(self, param, od_productIds, clientId):
		pass
	
	def _generateResponse(self, result):
		if not isinstance(result, http.Response):
			result = http.Response()
		
		if self.query:
			logger.notice(u"QUERY: '%s'" % self.query)
			
			query = json.loads(self.query)
			if not query.has_key("task"):
				raise Exception("No task set, nothing to do") 
			print ">>>>>>>>>>>>>",query["task"]
			if query["task"] == "checkClientStatus":
				
				if query["param"]:
					if query["param"].has_key("exclude"):
						res = self.monitoring.checkClientStatus(query["param"]["clientId"], query["param"]["exclude"])
					else:
						res = self.monitoring.checkClientStatus(query["param"]["clientId"])
					result.stream = stream.IByteStream(res.encode('utf-8'))
					return result
				else:
					raise Exception(u"Failure: Parameterlist for task not complete, clientId needed for these check.")
			elif query["task"] == "getOpsiClientsForGroup":
				if query["param"]:
					if query["param"].has_key("groups"):
						res = self.monitoring.getOpsiClientsForGroup(query["param"]["groups"])
						result.stream = stream.IByteStream(res.encode('utf-8'))
						return result
			else:
				raise Exception(u"Failure: unknown task!")
				
		
		
class ResourceOpsiconfdMonitoring(ResourceOpsi):
	WorkerClass = WorkerOpsiconfdMonitoring
		

class Monitoring(object):
	def __init__(self, backend):
		self.backend = backend

		self._OK = 0
		self._WARNING = 1
		self._CRITICAL = 2
		self._UNKNOWN = 3
	
	def _generateResponse(self, state, message, perfdata=None):
		response = {}
		response["state"] = str(state)
		if perfdata:
			response["message"] = "%s | %s" % (message, perfdata)
		else:
			response["message"] = message
		print ">>>>>>>>>>>>>>>>>>>>>>>",json.dumps(response)
		return json.dumps(response)
	
	def checkClientStatus(self, clientId, excludeProductList=None):
		state = self._OK
		if not clientId:
			raise Exception(u"Failed: ClientId is needed for checkClientStatus")
		clientObj = self.backend.host_getObjects(id = clientId)
		if not clientObj:
			state = self._UNKNOWN
			return self._generateResponse(state, u"UNKNOWN: opsi-client: '%s' not found" % clientId)
		failedProducts = self.backend.productOnClient_getObjects(clientId = clientId, installationStatus = 'failed')
		if failedProducts:
			state = self._CRITICAL
			products = []
			for product in failedProducts:
				products.append(product.productId)
				return self._generateResponse(state, u"CRITICAL: Products: '%s' are in failed state." % (",".join(products)))
		actionProducts = self.backend.productOnClient_getObjects(clientId = clientId, installationStatus = ['setup','update','uninstall'])
		if actionProducts:
			state = self._WARNING
			products = []
			for product in actionProducts:
				products.append("%s (%s)" % (product.productId, product.actionRequest))
				return self._generateResponse(state, u"WARNING: Actions set for products: '%s'." % (",".join(products)))
		return self._generateResponse(state,u"OK: No failed products and no actions set for client")
	def getOpsiClientsForGroup(self, groups):
		clients = []
		result = {}
		objectToGroups = self.backend.objectToGroup_getObjects(groupId=groups)
		if objectToGroups:
			for objectToGroup in objectToGroups:
				clients.append(objectToGroup.objectId)
			if clients:
				hosts = self.backend.host_getObjects(id=clients)
				if hosts:
					for host in hosts:
						result[host.id] = {
							"description" : host.description,
							"inventoryNumber" : host.inventoryNumber,
							"ipAddress" : host.ipAddress
						}
		return json.dumps(result)


