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
						
			elif query["task"] == "checkProductStatus":
				if query["param"]:
					productIds = []
					groupIds = [] 
					depotIds = [] 
					exclude=[]
					verbose = False
					if query["param"].has_key("productIds"):
						productIds = query["param"]["productIds"]
					if query["param"].has_key("groupIds"):
						groupIds = query["param"]["groupIds"]
					if query["param"].has_key("depotIds"):
						depotIds = query["param"]["depotIds"]
					if query["param"].has_key("exclude"):
						exclude = query["param"]["exclude"]
					if query["param"].has_key("verbose"):
						verbose = True
					res = self.monitoring.checkProductStatus(productIds, groupIds, depotIds, exclude, verbose)
					result.stream = stream.IByteStream(res.encode('utf-8'))
					return result
				else:
					raise Exception(u"Failure: Parameterlist for task not complete, clientId needed for these check.")
			elif query["task"] == "checkDepotSyncStatus":
				if query["param"]:
					depotIds = []
					productIds = []
					exclude = []
				if query["param"].has_key("productIds"):
					productIds = query["param"]["productIds"]
				if query["param"].has_key("depotIds"):
					depotIds = query["param"]["depotIds"]
				if query["param"].has_key("exclude"):
					exclude = query["param"]["exclude"]
				res = self.monitoring.checkDepotSyncStatus(depotIds, productIds, exclude)
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
		
		self._stateText = [u"OK",u"WARNING", u"CRITICAL", u"UNKNOWN"]
	
	def _generateResponse(self, state, message, perfdata=None):
		response = {}
		response["state"] = str(state)
		if perfdata:
			response["message"] = u"%s: %s | %s" % (self._stateText[int(state)], message, perfdata)
		else:
			response["message"] = u"%s: %s" % (self._stateText[int(state)],message)
		if len(response["message"]) > 3800:
			response["message"] = u"%s ..." % response["message"][:3800]	
		return json.dumps(response)
	
	def checkClientStatus(self, clientId, excludeProductList=None):
		state = self._OK
		if not clientId:
			raise Exception(u"Failed to check: ClientId is needed for checkClientStatus")
		clientObj = self.backend.host_getObjects(id = clientId)
		if not clientObj:
			state = self._UNKNOWN
			return self._generateResponse(state, u"opsi-client: '%s' not found" % clientId)
		failedProducts = self.backend.productOnClient_getObjects(clientId = clientId, actionResult = 'failed')
		if failedProducts:
			state = self._CRITICAL
			products = []
			for product in failedProducts:
				products.append(product.productId)
				return self._generateResponse(state, u"Products: '%s' are in failed state." % (",".join(products)))
		actionProducts = self.backend.productOnClient_getObjects(clientId = clientId, actionRequest = ['setup','update','uninstall'])
		if actionProducts:
			state = self._WARNING
			products = []
			for product in actionProducts:
				products.append("%s (%s)" % (product.productId, product.actionRequest))
				return self._generateResponse(state, u"Actions set for products: '%s'." % (",".join(products)))
		return self._generateResponse(state,u"No failed products and no actions set for client")
	
	def getOpsiClientsForGroup(self, groups):
		clients = []
		result = {}
		objectToGroups = self.backend.objectToGroup_getObjects(groupId=groups, type="HostGroup")
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
	
	def checkProductStatus(self, productIds = [], productGroups = [], depotIds = [], exclude=[], verbose = False):
		state = self._OK
		clientsOnDepot = {}
		
		actionRequestOnClient = {}
		productProblemsOnClient = {}
		productProblemsOnDepot = {}
		productVersionProblemsOnClient = {}
		
		if not productIds:
			productIds = []
			for product in self.backend.objectToGroup_getIdents(groupType='ProductGroup',groupId=productGroups).split(";")[2]:
				if not product in productIds:
					productIds.append(product)
		if not depotIds or 'all' in depotIds:
			depotIds = []
			depots = self.backend.host_getObjects(type="OpsiDepotserver")
			for depot in depots:
				depotIds.append(depot.id)
		
		clientIds = self.backend.host_getIdents(type="OpsiClient")
		addConfigStateDefaults = self.backend.backend_getOptions().get('addConfigStateDefaults', False)
		try:
			logger.debug("Calling backend_setOptions on %s" % self)
			self.backend.backend_setOptions({'addConfigStateDefaults': True})
			
			for configState in self.backend.configState_getObjects(configId = u'clientconfig.depot.id', objectId = clientIds):
				if not configState.values or not configState.values[0]:
					logger.error(u"No depot server configured for client '%s'" % configState.objectId)
					continue
				depotId = configState.values[0]
				if not depotId in depotIds:
					continue
				if not clientsOnDepot.has_key(depotId):
					clientsOnDepot[depotId] = []
				clientsOnDepot[depotId].append(configState.objectId)
					
		finally:
			self.backend.backend_setOptions({'addConfigStateDefaults': addConfigStateDefaults})
		
		
		
		productOnDepotInfo = {}
		for pod in self.backend.productOnDepot_getObjects(depotId = depotIds, productId = productIds):
			if not productOnDepotInfo.has_key(pod.depotId):
				productOnDepotInfo[pod.depotId] = {}
				productOnDepotInfo[pod.depotId][pod.productId] = {	"productVersion": 	pod.productVersion,
											"packageVersion":	pod.packageVersion }
		for depotId in depotIds:
			for poc in self.backend.productOnClient_getObjects(productId = productIds, clientId = clientsOnDepot[depotId]):
				if poc.actionRequest != 'none':
					if state != self._CRITICAL:
						state = self._WARNING
					if not actionRequestOnClient.has_key(depotId):
						actionRequestOnClient[depotId] = {}
					if not actionRequestOnClient[depotId].has_key(poc.productId):
						actionRequestOnClient[depotId][poc.productId] = []
					actionRequestOnClient[depotId][poc.productId].append(u"%s (%s)" % (poc.clientId, poc.actionRequest) )
				if poc.installationStatus != "not_installed" and poc.actionResult != "successful": 
					if state != self._CRITICAL:
						state = self._CRITICAL
					if not productProblemsOnClient.has_key(depotId):
						productProblemsOnClient[depotId] = {}
					if not productProblemsOnClient[depotId].has_key(poc.productId):
						productProblemsOnClient[depotId][poc.productId] = []
					productProblemsOnClient[depotId][poc.productId].append(u"%s (%s)" % (poc.clientId, poc.actionResult))
				if not poc.productVersion or poc.packageVersion:
					continue
				if poc.productVersion != productOnDepotInfo[depotId][poc.productId]["productVersion"] or \
					poc.packageVersion != productOnDepotInfo[depotId][poc.productId]["packageVersion"]:
					if state != self._CRITICAL:
						state = self._CRITICAL
					if not productVersionProblemsOnClient.has_key(depotId):
						productVersionProblemsOnClient[depotId] = {}
					if not productVersionProblemsOnClient[depotId].has_key(poc.productId):
						productVersionProblemsOnClient[depotId][poc.productId] = []
					productVersionProblemsOnClient[depotId][poc.productId].append("%s (%s-%s)" % (poc.clientId,poc.productVersion, poc.packageVersion))
		message = ''
		if not verbose:
			for depotId in depotIds:
				message += "Result for Depot: '%s': " % depotId
				if actionRequestOnClient.has_key(depotId):
					for product in actionRequestOnClient[depotId].keys():
						message += "For product '%s' action set on '%d' clients; " % (product, len(actionRequestOnClient[depotId][product]))
				if productProblemsOnClient.has_key(depotId):
					for product in productProblemsOnClient[depotId].keys():
						message += "For product '%s' problems found on '%d' clients; " % (product, len(productProblemsOnClient[depotId][product]))
				if productVersionProblemsOnClient.has_key(depotId):
					for product in productVersionProblemsOnClient[depotId].keys():
						message += "For product '%s' version defference problems found on '%d' clients; " % (product, len(productVersionProblemsOnClient[depotId][product]))
			if state == self._OK:
				message = u"No Problem found for productIds; '%s'" % productIds
			return self._generateResponse(state, message)
				
		for depotId in depotIds:
			message += "Result for Depot: '%s': " % depotId
			if actionRequestOnClient.has_key(depotId):
				message += "Action Request set for "
				for product in actionRequestOnClient[depotId].keys():
					message += "product '%s': " % product
					for item in actionRequestOnClient[depotId][product]:
						message += "%s " % item
			if productProblemsOnClient.has_key(depotId):
				message += "Product Problems for "
				for product in productProblemsOnClient[depotId].keys():
					message += "product '%s': " % product
					for item in productProblemsOnClient[depotId][product]:
						message += "%s " % item
			if productVersionProblemsOnClient.has_key(depotId):
				message += "Product Version difference found for: "
				for product in productVersionProblemsOnClient[depotId].keys():
					message += "product '%s': " % product
					for item in productVersionProblemsOnClient[depotId][product]:
						message += "%s " % item
		
		if state == self._OK:
			message = u"No Problem found for productIds; '%s'" % "".join(productIds)
			
		return self._generateResponse(state, message)
		
	def checkDepotSyncStatus(self, depotIds, productIds = [], exclude = []):
		state = self._OK
		productOnDepotInfo = {}
		differenceProducts = {}
		
		if not depotIds or 'all' in depotIds:
			depotIds = []
			depots = self.backend.host_getObjects(type="OpsiDepotserver")
			for depot in depots:
				depotIds.append(depot.id)
		
		productOnDepots = self.backend.productOnDepot_getObjects(depotId = depotIds, productId = productIds)
		productIds = []
		for depotId in depotIds:
			productOnDepotInfo[depotId] = {}
		for pod in productOnDepots:
			if not pod.productId in productIds:
				productIds.append(pod.productId)
			productOnDepotInfo[pod.depotId][pod.productId] = pod
		productIds.sort()
		
		for productId in productIds:
			if productId in exclude:
				continue
			differs = False
			productVersion = u''
			packageVersion = u''
			for depotId in depotIds:
				productOnDepot = productOnDepotInfo[depotId].get(productId)
				if not productOnDepot:
					if not differenceProducts.has_key(productId): 
						differenceProducts[productId] = {}
					differenceProducts[productId][depotId] = "not installed"
					continue
				if not productVersion:
					productVersion = productOnDepot.productVersion
				elif (productVersion != productOnDepot.productVersion):
					differs = True
				if not packageVersion:
					packageVersion = productOnDepot.packageVersion
				elif (packageVersion != productOnDepot.packageVersion):
					differs = True
				
				if differs:
					if not differenceProducts.has_key(productId): 
						differenceProducts[productId] = {}
					differenceProducts[productId][depotId] = "different"
		
		message = u''
		if differenceProducts:
			state = self._WARNING
			message += u"Differences found for "
			
			for productId in differenceProducts.keys():
				message += u"product: '%s': " % productId
				for depotId in depotIds:
					if differenceProducts[productId].has_key(depotId):
						if differenceProducts[productId][depotId] == "not installed":
							message += u"%s (not installed) " % depotId
						else:
							message += u"%s (%s-%s) " % (depotId,
								productOnDepotInfo[depotId][productId].productVersion,
								productOnDepotInfo[depotId][productId].packageVersion)
					else:
						message += u"%s (%s-%s) " % (depotId,
								productOnDepotInfo[depotId][productId].productVersion,
								productOnDepotInfo[depotId][productId].packageVersion)	
		else:
			message += "Syncstate ok for depots: '%s' " % ",".join(depotIds)
		
		
		print message
		return self._generateResponse(state, message)
			
		
	
	'''
	def checkProductStatus(self, productIds = [], productGroups = [], depotIds = [], exclude=[]):
		productOnDepotInfo = {}
		hostOnDepotInfo = {}
		productOnClientInfo = {}
		
		productProblemsOnClient = {}
		productProblemsOnDepot = {}
		productVersionProblemsOnClient = {}
		
		
		
		state = self._OK
		if not productIds and not productGroups:
			raise Exception(u"Failed to check: No ProductId or ProductGroup is given.")
		elif not productIds:
			productIds = []
			objectToGroups = self.backend.objectToGroup_getObjects(groupId=productGroups, type="ProductGroup")
			for objectToGroup in objectToGroups:
				productIds.append(objectToGroup.objectId)
		
		if exclude:
			newlist = []
			for productId in productIds:
				if not productId in excludes:
					newlist.append(productId)
			if newlist:
				productId = newlist		
			
		configServer = self.backend.host_getObjects(type="OpsiConfigServer")[0].id
		
		if not depotIds:
			depotIds = []
			depots = self.backend.host_getObjects(type=["OpsiConfigserver","OpsiDepotserver"])
			for depot in depots:
				depotIds.append(depot.id)
				productOnDepotInfo[depot.id] = {}
		
		productsOnDepot = self.backend.productOnDepot_getObjects(productId=productIds, depotId=depotIds)
		
		for productOnDepot in productsOnDepot:
			productOnDepotInfo[productOnDepot.depotId][productOnDepot.productId] = productOnDepot
		
		configStates = self.backend.configState_getObjects(configId="clientconfig.depot.id")
		
		
		
		for configState in configStates:
			hostOnDepotInfo[configState.objectId] = configState.values[0]
			
		
		
		
		productsOnClient = self.backend.productOnClient_getObjects(productId=productIds)
		
		for productOnClient in productsOnClient:
			versionDifference = False
			if exclude:
				if productOnClient.clientId in exclude:
					continue
			
			if productOnClient.installationStatus == "installed":
				if productOnClient.actionResult:	
					if not "success" in productOnClient.actionResult:
						if state != self._CRITICAL:
							state = self._CRITICAL
					if not productProblemsOnClient.has_key(productOnClient.productId):
						productProblemsOnClient[productOnClient.productId] = []
					productProblemsOnClient[productOnClient.productId].append(productOnClient.clientId)
			
			if hostOnDepotInfo.has_key(productOnClient.clientId):
				depotId = hostOnDepotInfo[productOnClient.clientId]
			else:
				depotId = configServer
				
			productOnDepot = productOnDepotInfo[depotId].get(productOnClient.productId)
			if not productOnDepot:
				state = self._CRITICAL
				if not productProblemsOnDepot[productOnClient.productId]:
					productProblemsOnDepot[productOnClient.productId] = []
				productProblemsOnDepot[productOnClient.productId].append(depotId)
				continue
			else:
				if productOnDepot.productVersion != productOnClient.productVersion:
					if state != self._CRITICAL:
						state = self._WARNING
						versionDifference = True
				elif productOnDepot.packageVersion != productOnClient.packageVersion:
					if state != self._CRITICAL:
						state = self._WARNING
						versionDifference = True
				if versionDifference:
					if not productVersionProblemsOnClient.has_key(productOnClient.productId):
						productVersionProblemsOnClient[productOnClient.productId] = []
					productVersionProblemsOnClient[productOnClient.productId].append(productOnClient.clientId)		
		
		message = ''		
		
		if productProblemsOnClient:
			message += u"Status Problem detected for: "
			for productId in productIds:
				if productProblemsOnClient.has_key(productId):
					for clientId in productProblemsOnClient[productId]:
						message += u"%s (%s) " % (clientId, productId)
					
		if productProblemsOnDepot:
			message += u"Cannot check, because product not installed on depot: "
			for productId in productIds:
				if productProblemsOnDepot.has_key(productId):
					for clientId in productProblemsOnDepot[productId]:
						message += u"%s (%s) " % (clientId, productId)
	
		if productVersionProblemsOnClient:
			message += u"Version of Installed Software on Client differs from Software on Depot: "
			for productId in productIds:
				if productVersionProblemsOnClient.has_key(productId):
					for clientId in productVersionProblemsOnClient[productId]:
						message += u"%s (%s) " % (clientId, productId)
		
		if not productProblemsOnClient and not productProblemsOnDepot and not productVersionProblemsOnClient:
			message += u"Checked Product looks good, no problems found."
		print ">>>>>>>>>>>>>>>",state
		print ">>>>>>>>>>>>>>>",message
		return self._generateResponse(state, message)
	
	def checkPluginOnClient(self, clientId, plugin, params=None, state=None):
		pass
'''

