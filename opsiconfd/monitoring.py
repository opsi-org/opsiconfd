#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
opsi-nagios-connector endpoint.

opsi-nagios-connector is part of the desktop management solution opsi
(open pc server integration) http://www.opsi.org

Copyright (C) 2010-2016 uib GmbH

http://www.uib.de/

All rights reserved.

@copyright:  uib GmbH <info@uib.de>
@author: Erol Ueluekmen <e.ueluekmen@uib.de>
"""

import base64
import datetime
import json
import os
import re
import time
from collections import defaultdict
from hashlib import md5
from twisted.internet import defer
from twisted.conch.ssh import keys

from OPSI.Logger import LOG_INFO, Logger
from OPSI.Service.Resource import ResourceOpsi
from OPSI.Service.Worker import WorkerOpsi
from OPSI.System import getDiskSpaceUsage
from OPSI.Types import OpsiAuthenticationError
from OPSI.Types import forceList
from OPSI.web2 import http, stream

logger = Logger()


class WorkerOpsiconfdMonitoring(WorkerOpsi):
	def __init__(self, service, request, resource):
		WorkerOpsi.__init__(self, service, request, resource)
		self._debug = self.service.config.get('monitoringDebug', False)
		self._setLogFile(self)
		self.monitoring = None

	def _setLogFile(self, obj):
		if self._debug:
			logger.setLogFile(
				self.service.config['logFile'].replace('%m', 'monitoring'),
				object=obj
			)

	def process(self):
		logger.info(u"Worker %s started processing" % self)
		deferred = defer.Deferred()
		deferred.addCallback(self._authenticate)
		deferred.addCallback(self._getQuery)
		deferred.addCallback(self._processQuery)
		deferred.addCallback(self._setResponse)
		deferred.addErrback(self._errback)
		deferred.callback(None)
		return deferred

	def _processQuery(self, result):
		self._decodeQuery(result)

	def _getAuthorization(self):
		user = u''
		password = u''
		logger.debug(u"Trying to get username and password from Authorization header")
		auth = self.request.headers.getHeader('Authorization')
		if auth:
			logger.debug(u"Authorization header found (type: %s)" % auth[0])
			try:
				encoded = auth[1]

				logger.confidential(u"Auth encoded: %s" % encoded)
				parts = unicode(base64.decodestring(encoded), 'latin-1').split(':')
				if len(parts) > 6:
					user = u':'.join(parts[:6])
					password = u':'.join(parts[6:])
				else:
					user = parts[0]
					password = u':'.join(parts[1:])
				user = user.strip()
				logger.confidential(u"Plugin supplied username '%s' and password '%s'" % (user, password))
			except Exception as error:
				logger.error(u"Bad Authorization header from '%s': %s" % (self.request.remoteAddr.host, error))
		return (user, password)

	def _getCredentials(self):
		return self._getAuthorization()

	def _authenticate(self, result):
		''' This function tries to authenticate the opsi-monitoring-plugin '''

		try:
			# Get authorization from header
			user, password = self._getCredentials()

			try:
				monitoringUsername = self.service.config['monitoringUser']
				try:
					monitoringPassword = self.service._backend.user_getCredentials(username=monitoringUsername)["password"]
				except Exception as error:
					logger.error(u"Password not set, please check documentation from opsi-Nagios-Connector: Have you execute user_setCredentials for User: '%s'" % monitoringUsername)
					return
				logger.confidential(u"Monitoring User Credentials are: user: '%s' password: '%s'" % (monitoringUsername, monitoringPassword))
			except Exception as error:
				monitoringPassword = False
				monitoringUsername = False
				logger.logException(error, LOG_INFO)

			if user == monitoringUsername and password == monitoringPassword:

				if not self.monitoring:
					backendinfo = self.service._backend.backend_info()
					modules = backendinfo['modules']
					helpermodules = backendinfo['realmodules']

					if not modules.get('customer'):
						logger.notice(u"Disabling monitoring module: no customer in modules file")
						self.monitoring = u"Disabling monitoring module: no customer in modules file"
					elif not modules.get('valid'):
						logger.notice(u"Disabling monitoring module: modules file invalid")
						self.monitoring = u"Disabling monitoring module: modules file invalid"
					elif (modules.get('expires', '') != 'never') and (time.mktime(time.strptime(modules.get('expires', '2000-01-01'), "%Y-%m-%d")) - time.time() <= 0):
						logger.notice(u"Disabling monitoring module: modules file expired")
						self.monitoring = u"Disabling monitoring module: modules file expired"
					else:

						publicKey = keys.Key.fromString(data=base64.decodestring('AAAAB3NzaC1yc2EAAAADAQABAAABAQCAD/I79Jd0eKwwfuVwh5B2z+S8aV0C5suItJa18RrYip+d4P0ogzqoCfOoVWtDojY96FDYv+2d73LsoOckHCnuh55GA0mtuVMWdXNZIE8Avt/RzbEoYGo/H0weuga7I8PuQNC/nyS8w3W8TH4pt+ZCjZZoX8S+IizWCYwfqYoYTMLgB0i+6TCAfJj3mNgCrDZkQ24+rOFS4a8RrjamEz/b81noWl9IntllK1hySkR+LbulfTGALHgHkDUlk0OSu+zBPw/hcDSOMiDQvvHfmR4quGyLPbQ2FOVm1TzE0bQPR+Bhx4V8Eo2kNYstG2eJELrz7J1TJI0rCjpB+FQjYPsP')).keyObject
						data = u''
						mks = modules.keys()
						mks.sort()
						for module in mks:
							if module in ('valid', 'signature'):
								continue

							if module in helpermodules:
								val = helpermodules[module]
								if int(val) > 0:
									modules[module] = True
							else:
								val = modules[module]
								if val is False:
									val = 'no'
								if val is True:
									val = 'yes'

							data += u'%s = %s\r\n' % (module.lower().strip(), val)
						if not bool(publicKey.verify(md5(data).digest(), [long(modules['signature'])])):
							logger.error(u"Disabling monitoring module: modules file invalid")
							self.monitoring = u'Module monitoring is Disabled, please contact info@uib.de for activation.'
						else:
							logger.debug(u"Modules file signature verified (customer: %s)" % modules.get('customer'))

							if modules.get('monitoring'):
								self.monitoring = Monitoring(self.service)
							else:
								self.monitoring = u'Module monitoring is Disabled, please contact info@uib.de for activation.'
				return result
			else:
				logger.error(u"Wrong credentials, please check your configurations.")

		except Exception as error:
			logger.logException(error, LOG_INFO)
			raise OpsiAuthenticationError(u"Forbidden: %s" % error)
		return result

	def _authorize(self):
		return True

	def _generateResponse(self, result):
		if not isinstance(result, http.Response):
			result = http.Response()

		if self.query:
			query = json.loads(self.query)
			if "task" not in query:
				res = {
					"state": 3,
					"message": u"No task set, nothing to do"
				}
				result.stream = stream.IByteStream(json.dumps(res).encode('utf-8'))
				return result

			if not isinstance(self.monitoring, Monitoring):
				res = {}
				res["state"] = "3"
				res["message"] = self.monitoring
				result.stream = stream.IByteStream(json.dumps(res).encode('utf-8'))
				return result

			if query["task"] == "checkClientStatus":
				exclude = query.get("param", {}).get("exclude", None)
				clientId = query.get("param", {}).get("clientId", None)

				try:
					try:
						res = self.monitoring.checkClientStatus(
							clientId=clientId,
							excludeProductList=exclude
						)
					except Exception as error:
						logger.logException(error, LOG_INFO)
						res = {"state": "3", "message": str(error)}
						res = res = json.dumps(res)
				finally:
					result.stream = stream.IByteStream(res.encode('utf-8'))
					return result

			elif query["task"] == "getOpsiClientsForGroup":
				if query["param"]:
					if "groups" in query["param"]:
						res = self.monitoring.getOpsiClientsForGroup(query["param"]["groups"])
						result.stream = stream.IByteStream(res.encode('utf-8'))
						return result

			elif query["task"] == "checkProductStatus":
				productIds = query.get("param", {}).get("productIds", [])
				groupIds = query.get("param", {}).get("groupIds", [])
				hostGroupIds = query.get("param", {}).get("hostGroupIds", [])
				depotIds = query.get("param", {}).get("depotIds", [])
				exclude = query.get("param", {}).get("exclude", [])
				verbose = query.get("param", {}).get("verbose", False)

				try:
					try:
						res = self.monitoring.checkProductStatus(
							productIds=productIds,
							productGroups=groupIds,
							hostGroupIds=hostGroupIds,
							depotIds=depotIds,
							exclude=exclude,
							verbose=verbose
						)
					except Exception as error:
						logger.logException(error, LOG_INFO)
						res = {"state": "3", "message": str(error)}
						res = res = json.dumps(res)
				finally:
					result.stream = stream.IByteStream(res.encode('utf-8'))
					return result

			elif query["task"] == "checkDepotSyncStatus":
				depotIds = query.get("param", {}).get("depotIds", [])
				productIds = query.get("param", {}).get("productIds", [])
				exclude = query.get("param", {}).get("exclude", [])
				strict = query.get("param", {}).get("strict", False)
				verbose = query.get("param", {}).get("verbose", False)

				try:
					try:
						res = self.monitoring.checkDepotSyncStatus(
							depotIds,
							productIds,
							exclude,
							strict,
							verbose
						)
					except Exception as error:
						logger.logException(error, LOG_INFO)
						res = {"state": "3", "message": str(error)}
						res = res = json.dumps(res)
				finally:
					result.stream = stream.IByteStream(res.encode('utf-8'))
					return result

			elif query["task"] == "checkPluginOnClient":
				clientId = query.get("param", {}).get("clientId", [])
				command = query.get("param", {}).get("plugin", "")
				statebefore = query.get("param", {}).get("state", None)
				output = query.get("param", {}).get("output", None)
				timeout = query.get("param", {}).get("timeout", 30)
				captureStdErr = query.get("param", {}).get("captureStdErr", True)
				waitForEnding = query.get("param", {}).get("waitForEnding", True)
				encoding = query.get("param", {}).get("encoding", None)

				try:
					try:
						res = self.monitoring.checkPluginOnClient(
							clientId,
							command,
							timeout,
							waitForEnding,
							captureStdErr,
							statebefore,
							output,
							encoding
						)
					except Exception as error:
						logger.logException(error, LOG_INFO)
						res = {"state": "3", "message": str(error)}
						res = res = json.dumps(res)
				finally:
					result.stream = stream.IByteStream(res.encode('utf-8'))
					return result

			elif query["task"] == "checkOpsiWebservice":
				cpu = query.get("param", {}).get("cpu", [])
				errors = query.get("param", {}).get("errors", [])

				try:
					try:
						res = self.monitoring.checkOpsiWebservice(cpu, errors)
					except Exception as error:
						logger.logException(error, LOG_INFO)
						res = {"state": "3", "message": str(error)}
						res = json.dumps(res)
				finally:
					result.stream = stream.IByteStream(res.encode('utf-8'))
					return result

			elif query["task"] == "checkOpsiDiskUsage":
				opsiresource = query.get("param", {}).get("resource", None)
				threshold = {}
				threshold["warning"] = (query.get("param", {}).get("warning", "5G"))
				threshold["critical"] = (query.get("param", {}).get("critical", "1G"))

				try:
					try:
						res = self.monitoring.checkOpsiDiskUsage(
							opsiresource=opsiresource,
							thresholds=threshold
						)
					except Exception as error:
						logger.logException(error, LOG_INFO)
						res = {"state": "3", "message": str(error)}
						res = json.dumps(res)
				finally:
					result.stream = stream.IByteStream(res.encode('utf-8'))
					return result
			else:
				res = {
					"state": "3",
					"message": u"Failure: unknown task!",
				}

				result.stream = stream.IByteStream(json.dumps(res).encode('utf-8'))
				return result


class ResourceOpsiconfdMonitoring(ResourceOpsi):
	WorkerClass = WorkerOpsiconfdMonitoring


class Monitoring(object):

	_OK = 0
	_WARNING = 1
	_CRITICAL = 2
	_UNKNOWN = 3

	_stateText = [u"OK", u"WARNING", u"CRITICAL", u"UNKNOWN"]

	def __init__(self, service):
		self.service = service

		self._errorcodePattern = re.compile('\[Errno\s(\d*)\]\sCommand\s(\'.*\')\sfailed\s\(\d*\)\:\s(.*)')

	def _generateResponse(self, state, message, perfdata=None):
		response = {
			"state": str(state)
		}

		if perfdata:
			if self._stateText[int(state)] in message:
				response["message"] = u"%s | %s" % (message, perfdata)
			else:
				response["message"] = u"%s: %s | %s" % (self._stateText[int(state)], message, perfdata)
		else:
			if self._stateText[int(state)] in message:
				response["message"] = u"%s" % message
			else:
				response["message"] = u"%s: %s" % (self._stateText[int(state)], message)

		return json.dumps(response)

	def checkClientStatus(self, clientId, excludeProductList=None):
		state = self._OK

		if not clientId:
			raise Exception(u"Failed to check: ClientId is needed for checkClientStatus")

		clientObj = self.service._backend.host_getObjects(id=clientId)
		if not clientObj:
			state = self._UNKNOWN
			return self._generateResponse(state, u"opsi-client: '%s' not found" % clientId)
		else:
			clientObj = clientObj[0]

		message = ''
		if not clientObj.lastSeen:
			state = self._WARNING
			message += u"opsi-client: '%s' never seen, please check opsi-client-agent installation on client. " % clientId
		else:
			lastSeen = clientObj.lastSeen.split("-")
			year = int(lastSeen[0])
			month = int(lastSeen[1])
			day = int(lastSeen[2].split()[0])

			today = datetime.date.today()
			delta = None

			if year and month and day:
				lastSeenDate = datetime.date(year, month, day)
				delta = today - lastSeenDate
			elif state == self._OK:
				state = self._WARNING
				message += u"opsi-client: '%s' never seen, please check opsi-client-agent installation on client. " % clientId

			if delta.days >= 30:
				state = self._WARNING
				message += "opsi-client %s has not been seen, since %d days. Please check opsi-client-agent installation on client or perhaps a client that can be deleted. " % (clientId, delta.days)
			elif delta.days == 0:
				message += "opsi-client %s has been seen today. " % (clientId)
			else:
				message += "opsi-client %s has been seen %d days before. " % (clientId, delta.days)

		failedProducts = self.service._backend.productOnClient_getObjects(
			clientId=clientId,
			actionResult='failed'
		)
		if failedProducts:
			state = self._CRITICAL
			products = []
			for product in failedProducts:
				products.append(product.productId)
			message += "Products: '%s' are in failed state. " % (",".join(products))

		actionProducts = self.service._backend.productOnClient_getObjects(clientId=clientId, actionRequest=['setup', 'update', 'uninstall'])
		if actionProducts:
			if state != self._CRITICAL:
				state = self._WARNING
			products = []
			for product in actionProducts:
				products.append("%s (%s)" % (product.productId, product.actionRequest))
			message += "Actions set for products: '%s'." % (",".join(products))
		if state == self._OK:
			message += "No failed products and no actions set for client"

		return self._generateResponse(state, message)

	def getOpsiClientsForGroup(self, groups):
		result = {}
		objectToGroups = self.service._backend.objectToGroup_getObjects(groupId=groups, type="HostGroup")
		if objectToGroups:
			clients = [objectToGroup.objectId for objectToGroup in objectToGroups]

			if clients:
				hosts = self.service._backend.host_getObjects(id=clients)
				for host in hosts:
					result[host.id] = {
						"description": host.description,
						"inventoryNumber": host.inventoryNumber,
						"ipAddress": host.ipAddress
					}

		return json.dumps(result)

	def checkProductStatus(self, productIds=[], productGroups=[], hostGroupIds=[], depotIds=[], exclude=[], verbose=False):
		if not productIds:
			productIds = []
			for product in self.service._backend.objectToGroup_getIdents(groupType='ProductGroup', groupId=productGroups):
				product = product.split(";")[2]
				if product not in productIds:
					productIds.append(product)

		if not productIds:
			return self._generateResponse(self._UNKNOWN, u"Neither productId nor productGroup given, nothing to check!")

		serverType = None
		if not depotIds:
			serverType = "OpsiConfigserver"
		elif 'all' in depotIds:
			serverType = "OpsiDepotserver"

		if serverType:
			depotIds = []
			depots = self.service._backend.host_getObjects(type=serverType)
			for depot in depots:
				depotIds.append(depot.id)

		clientIds = None
		if hostGroupIds:
			clientIds = []
			objectToGroups = self.service._backend.objectToGroup_getObjects(groupId=hostGroupIds, groupType="HostGroup")
			if objectToGroups:
				for objectToGroup in objectToGroups:
					clientIds.append(objectToGroup.objectId)
		else:
			clientIds = self.service._backend.host_getIdents(type="OpsiClient")

		clientsOnDepot = defaultdict(list)
		addConfigStateDefaults = self.service._backend.backend_getOptions().get('addConfigStateDefaults', False)
		try:
			logger.debug("Calling backend_setOptions on %s" % self)
			self.service._backend.backend_setOptions({'addConfigStateDefaults': True})

			for configState in self.service._backend.configState_getObjects(configId=u'clientconfig.depot.id', objectId=clientIds):
				if not configState.values or not configState.values[0]:
					logger.error(u"No depot server configured for client '%s'" % configState.objectId)
					continue

				depotId = configState.values[0]
				if depotId not in depotIds:
					continue

				clientsOnDepot[depotId].append(configState.objectId)
		finally:
			self.service._backend.backend_setOptions({'addConfigStateDefaults': addConfigStateDefaults})

		productOnDepotInfo = defaultdict(dict)
		for pod in self.service._backend.productOnDepot_getObjects(depotId=depotIds, productId=productIds):
			productOnDepotInfo[pod.depotId][pod.productId] = {
				"productVersion": pod.productVersion,
				"packageVersion": pod.packageVersion
			}

		state = self._OK
		productVersionProblemsOnClient = defaultdict(lambda: defaultdict(list))
		productProblemsOnClient = defaultdict(lambda: defaultdict(list))
		actionRequestOnClient = defaultdict(lambda: defaultdict(list))
		for depotId in depotIds:
			for poc in self.service._backend.productOnClient_getObjects(productId=productIds, clientId=clientsOnDepot.get(depotId, None)):
				if poc.actionRequest != 'none':
					if state != self._CRITICAL:
						state = self._WARNING

					actionRequestOnClient[depotId][poc.productId].append(u"%s (%s)" % (poc.clientId, poc.actionRequest))

				if poc.installationStatus != "not_installed" and poc.actionResult != "successful" and poc.actionResult != "none":
					if state != self._CRITICAL:
						state = self._CRITICAL

					productProblemsOnClient[depotId][poc.productId].append(u"%s (%s lastAction: [%s])" % (poc.clientId, poc.actionResult, poc.lastAction))

				if not poc.productVersion or not poc.packageVersion:
					continue

				if poc.productVersion != productOnDepotInfo[depotId][poc.productId]["productVersion"] or \
					poc.packageVersion != productOnDepotInfo[depotId][poc.productId]["packageVersion"]:
					if state != self._CRITICAL:
						state = self._WARNING

					productVersionProblemsOnClient[depotId][poc.productId].append("%s (%s-%s)" % (poc.clientId, poc.productVersion, poc.packageVersion))

		message = ''
		for depotId in depotIds:
			if depotId in actionRequestOnClient or depotId in productProblemsOnClient or depotId in productVersionProblemsOnClient:
				message += "Result for Depot: '%s': " % depotId
			else:
				continue

			if depotId in actionRequestOnClient:
				for product in actionRequestOnClient[depotId].keys():
					message += "For product '%s' action set on '%d' clients! " % (product, len(actionRequestOnClient[depotId][product]))
			if depotId in productProblemsOnClient:
				for product in productProblemsOnClient[depotId].keys():
					message += "For product '%s' problems found on '%d' clients! " % (product, len(productProblemsOnClient[depotId][product]))
			if depotId in productVersionProblemsOnClient:
				for product in productVersionProblemsOnClient[depotId].keys():
					message += "For product '%s' version difference problems found on '%d' clients! " % (product, len(productVersionProblemsOnClient[depotId][product]))

		if not verbose:
			if state == self._OK:
				message = u"No Problem found for productIds: '%s'" % ",".join(productIds)
			return self._generateResponse(state, message)

		for depotId in depotIds:
			if depotId in actionRequestOnClient or depotId in productProblemsOnClient or depotId in productVersionProblemsOnClient:
				message += "Result for Depot: '%s': \n" % depotId
			else:
				continue

			if depotId in actionRequestOnClient:
				message += "Action Request set for "
				for product in actionRequestOnClient[depotId].keys():
					message += "product '%s': \n" % product
					for item in actionRequestOnClient[depotId][product]:
						message += "%s \n" % item

			if depotId in productProblemsOnClient:
				message += "Product Problems for "
				for product in productProblemsOnClient[depotId].keys():
					message += "product '%s': \n" % product
					for item in productProblemsOnClient[depotId][product]:
						message += "%s \n" % item

			if depotId in productVersionProblemsOnClient:
				message += "Product Version difference found for: "
				for product in productVersionProblemsOnClient[depotId].keys():
					message += "product '%s': \n" % product
					for item in productVersionProblemsOnClient[depotId][product]:
						message += "%s \n" % item

		if state == self._OK:
			if productGroups:
				message = u"No Problem found for productIds; '%s'" % ",".join(productGroups)
			else:
				message = u"No Problem found for productIds; '%s'" % ",".join(productIds)

		return self._generateResponse(state, message)

	def checkDepotSyncStatus(self, depotIds, productIds=[], exclude=[], strict=False, verbose=False):
		state = self._OK

		if not depotIds or 'all' in depotIds:
			depotIds = []
			depots = self.service._backend.host_getObjects(type="OpsiDepotserver")
			for depot in depots:
				depotIds.append(depot.id)

		productOnDepots = self.service._backend.productOnDepot_getObjects(depotId=depotIds, productId=productIds)
		productIds = []
		productOnDepotInfo = defaultdict(dict)
		for pod in productOnDepots:
			if pod.productId not in productIds:
				productIds.append(pod.productId)
			productOnDepotInfo[pod.depotId][pod.productId] = pod
		productIds.sort()

		differenceProducts = defaultdict(dict)
		for productId in productIds:
			if productId in exclude:
				continue
			differs = False
			productVersion = u''
			packageVersion = u''
			for depotId in depotIds:
				productOnDepot = productOnDepotInfo[depotId].get(productId)
				if not productOnDepot:
					if not strict:
						continue

					differenceProducts[productId][depotId] = "not installed"
					continue

				if not productVersion:
					productVersion = productOnDepot.productVersion
				elif productVersion != productOnDepot.productVersion:
					differs = True

				if not packageVersion:
					packageVersion = productOnDepot.packageVersion
				elif packageVersion != productOnDepot.packageVersion:
					differs = True

				if differs:
					differenceProducts[productId][depotId] = "different"

		message = u''
		if differenceProducts:
			state = self._WARNING
			message += u"Differences found for '%d'" % len(differenceProducts)

			if verbose:
				message += u":\n"
				for productId in differenceProducts.keys():
					message += u"product: '%s': " % productId
					for depotId in depotIds:
						if depotId in differenceProducts[productId]:
							if differenceProducts[productId][depotId] == "not installed":
								message += u"%s (not installed) \n" % depotId
							else:
								message += u"%s (%s-%s) \n" % (
									depotId,
									productOnDepotInfo[depotId][productId].productVersion,
									productOnDepotInfo[depotId][productId].packageVersion
								)
						else:
							if not productOnDepotInfo.get(depotId, {}).get(productId, None):
								continue

							message += u"%s (%s-%s) " % (
								depotId,
								productOnDepotInfo[depotId][productId].productVersion,
								productOnDepotInfo[depotId][productId].packageVersion
							)
		else:
			message += "Syncstate ok for depots: '%s' " % ",".join(depotIds)

		return self._generateResponse(state, message)

	def checkPluginOnClient(self, hostId, command, timeout=30, waitForEnding=True, captureStdErr=True, statebefore=None, output=None, encoding=None):
		state = self._OK
		message = ""
		hostId = forceList(hostId)

		try:
			result = self.service._backend.hostControl_reachable(hostId)
			if result.get(hostId[0], False):
				checkresult = self.service._backend.hostControl_execute(command, hostId, waitForEnding, captureStdErr, encoding, timeout)
				checkresult = checkresult.get(hostId[0], None)

				if checkresult:
					if checkresult.get("result", None):
						message = checkresult.get("result")[0]
					elif checkresult.get("error", None):
						errormessage = checkresult.get("error", {}).get("message")
						if errormessage:
							logger.debug(u"Try to find Errorcode")
							match = re.match(self._errorcodePattern, errormessage)
							if not match:
								state = self._UNKNOWN
								message = u"Unable to parse Errorcode from plugin"
							else:
								errorcode = int(match.group(1))
								command = match.group(2)
								message = match.group(3)
								if not errorcode > 3:
									state = errorcode
								else:
									state = self._UNKNOWN
									message = "Failed to determine Errorcode from check_command: '%s', message is: '%s'" \
										% (command, message)
						else:
							state = self._UNKNOWN
							message = u"Unknown Problem by checking plugin on Client. Check your configuration."
					else:
						state = self._UNKNOWN
						message = u"Unknown Problem by checking plugin on Client. Check your configuration."
			else:
				if result.get("error", None):
					message = result.get("error").get("message", "")
					state = self._UNKNOWN
				elif statebefore and output:
					return self._generateResponse(int(statebefore), output)
				else:
					message = "Can't check host '%s' is not reachable." % hostId[0]
					state = self._UNKNOWN
			return self._generateResponse(state, message)
		except Exception as erro:
			state = self._UNKNOWN
			message = str(erro)
			return self._generateResponse(state, message)

	def checkOpsiDiskUsage(self, thresholds={}, opsiresource=None, perfdata=False):
		results = {}
		state = self._OK
		message = []
		warning = thresholds.get("warning", "5G")
		critical = thresholds.get("critical", "1G")

		if opsiresource:
			resources = forceList(opsiresource)
		else:
			resources = self.service.config['staticDirectories'].keys()
			resources.sort()

		if warning.lower().endswith("g"):
			unit = "GB"
			warning = float(warning[:-1])
			critical = float(critical[:-1])
		elif warning.lower().endswith("%"):
			unit = "%"
			warning = float(warning[:-1])
			critical = float(critical[:-1])
		else:
			unit = "%"
			warning = float(warning)
			critical = float(critical)

		try:
			for resource in resources:
				path = self.service.config['staticDirectories'][resource]['path']
				if os.path.isdir(path):
					if not resource.startswith('/'):
						resource = u'/' + resource

					info = getDiskSpaceUsage(path)
					results[resource] = info
		except Exception as error:
			state = self._UNKNOWN
			message.append(u"Not able to check DiskUsage. Error: '%s'" % str(error))
			return self._generateResponse(state, message)

		if results:
			state = self._OK
			for result in results.keys():
				info = results[result]
				available = float(info['available']) / 1073741824
				usage = info['usage']*100
				if unit == "GB":
					if available <= critical:
						state = self._CRITICAL
						message.append(u"DiskUsage from ressource: '%s' is critical (available: '%.2f'GB)." % (result, available))
					elif available <= warning:
						if state != self._CRITICAL:
							state = self._WARNING
						message.append(u"DiskUsage warning from ressource: '%s' (available: '%.2f'GB)." % (result, available))
					else:
						message.append(u"DiskUsage from ressource '%s' is ok. (available: '%.2f'GB)." % (result, available))
				elif unit == "%":
					freeSpace = 100 - usage
					if freeSpace <= critical:
						state = self._CRITICAL
						message.append(u"DiskUsage from ressource: '%s' is critical (available: '%.2f%%')." % (result, freeSpace))

					elif freeSpace <= warning:
						if state != self._CRITICAL:
							state = self._WARNING
						message.append(u"DiskUsage warning from ressource: '%s' (available: '%.2f%%')." % (result, freeSpace))

					else:
						message.append(u"DiskUsage from ressource: '%s' is ok. (available: '%.2f%%')." % (result, freeSpace))

		else:
			state = self._UNKNOWN
			message.append("No results get. Nothing to check.")
		if state == self._OK:
			message = u"OK: %s" % " ".join(message)
		elif state == self._WARNING:
			message = u"WARNING: %s" % " ".join(message)
		elif state == self._CRITICAL:
			message = u"CRITICAL: %s" % " ".join(message)

		return self._generateResponse(state, message)

	def checkOpsiWebservice(self, cputhreshold=[], errors=[], perfdata=True):
		state = self._OK
		logger.debug(u"Generating Defaults for checkOpsiWebservice if not given")
		if not cputhreshold:
			cputhreshold = [80, 60]
		if not errors:
			errors = [20, 10]

		try:
			perfdata = []
			message = []
			performanceHash = {}
			performanceHash = self.service.statistics().getStatistics()

			requests = performanceHash["requests"]
			davrequests = performanceHash["davrequests"]
			rpcerrors = performanceHash["rpcerrors"]
			rpcs = performanceHash["rpcs"]

			perfdata.append(u'requests=%s;;;0; ' % requests)
			perfdata.append(u'davrequests=%s;;;0; ' % davrequests)
			perfdata.append(u'rpcs=%s;;;0; ' % rpcs)

			if int(rpcerrors) == 0 or int(rpcs) == '0':
				errorrate = 0
			else:
				errorrate = int(rpcerrors)*100//int(rpcs)

			if errorrate > errors[0]:
				message.append(u'RPC errors over 20\%')
				state = self._CRITICAL
			elif errorrate > errors[1]:
				message.append(u'RPC errors over 10\%')
				state = self._WARNING
			perfdata.append(u'rpcerror=%s;;;0; ' % rpcerrors)
			perfdata.append(u"sessions=%s;;;0; " % performanceHash["sessions"])
			perfdata.append(u"threads=%s;;;0; " % performanceHash["threads"])

			virtmem = performanceHash["virtmem"]
			perfdata.append(u"virtmem=%s;;;0; " % virtmem)

			if int(performanceHash["cpu"]) > cputhreshold[0]:
				state = self._CRITICAL
				message.append(u'CPU-Usage over 80%')
			elif int(performanceHash["cpu"]) > cputhreshold[1]:
				if not state == self._CRITICAL:
					state = self._WARNING
				message.append(u'CPU-Usage over 60%')
			perfdata.append(u"cpu=%s;;;0;100 " % performanceHash["cpu"])

			if state == self._OK:
				message.append("OK: Opsi Webservice has no Problem")

			if perfdata:
				message = "%s | %s" % (" ".join(message), "".join(perfdata))
			else:
				message = "%s" % (" ".join(message))
			return self._generateResponse(state, message)
		except Exception as error:
			state = self._UNKNOWN
			message = u"cannot check webservice state: '%s'." % str(error)
			return self._generateResponse(state, message)

	def checkOpsiLicensePool(self, poolId='all'):
		pass
