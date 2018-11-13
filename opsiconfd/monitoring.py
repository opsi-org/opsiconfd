# -*- coding: utf-8 -*-
"""
opsi-nagios-connector endpoint.

opsi-nagios-connector is part of the desktop management solution opsi
(open pc server integration) http://www.opsi.org

Copyright (C) 2010-2018 uib GmbH

http://www.uib.de/

All rights reserved.

@copyright:  uib GmbH <info@uib.de>
@author: Erol Ueluekmen <e.ueluekmen@uib.de>
@author: Niko Wenselowski <n.wenselowski@uib.de>
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

from OPSI.Backend.Backend import temporaryBackendOptions
from OPSI.Logger import LOG_INFO, Logger
from OPSI.Service.Resource import ResourceOpsi
from OPSI.Service.Worker import WorkerOpsi
from OPSI.System import getDiskSpaceUsage
from OPSI.Exceptions import OpsiAuthenticationError
from OPSI.Types import forceList, forceProductIdList
from OPSI.web2 import http, stream

logger = Logger()


class State:
	OK = 0
	WARNING = 1
	CRITICAL = 2
	UNKNOWN = 3

	_stateText = [u"OK", u"WARNING", u"CRITICAL", u"UNKNOWN"]

	@classmethod
	def text(cls, state):
		return cls._stateText[state]


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
					logger.error(u"Password not set, please check documentation for opsi-Nagios-Connector: Have you executed user_setCredentials for User: '%s'" % monitoringUsername)
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

			try:
				task = query['task']
			except KeyError:
				res = json.dumps({
					"state": State.UNKNOWN,
					"message": u"No task set, nothing to do"
				})
				result.stream = stream.IByteStream(res.encode('utf-8'))
				return result

			if not isinstance(self.monitoring, Monitoring):
				res = json.dumps({
					"state": State.UNKNOWN,
					"message": self.monitoring
				})

				result.stream = stream.IByteStream(res.encode('utf-8'))
				return result

			params = query.get("param", {})

			if task == "checkClientStatus":
				try:
					res = self.monitoring.checkClientStatus(
						clientId=params.get("clientId", None),
						excludeProductList=params.get("exclude", None)
					)
				except Exception as error:
					logger.logException(error, LOG_INFO)
					res = json.dumps({"state": State.UNKNOWN, "message": str(error)})

			elif task == "checkShortProductStatus":
				res = None
				try:
					productId = params.get("productIds", [])[0]
				except IndexError:
					res = json.dumps({"state": State.UNKNOWN, "message": "No ProductId given"})

				if res is None:  # no error encountered
					threshold = {
						"warning": params.get("warning", "20%"),
						"critical": params.get("critical", "20%")
					}

					try:
						res = self.monitoring.checkShortProductStatus(
							productId=productId,
							thresholds=threshold
						)
					except Exception as error:
						logger.logException(error, LOG_INFO)
						res = json.dumps({"state": State.UNKNOWN, "message": str(error)})

			elif task == "checkProductStatus":
				try:
					res = self.monitoring.checkProductStatus(
						productIds=params.get("productIds", []),
						productGroups=params.get("groupIds", []),
						hostGroupIds=params.get("hostGroupIds", []),
						depotIds=params.get("depotIds", []),
						exclude=params.get("exclude", []),
						verbose=params.get("verbose", False)
					)
				except Exception as error:
					logger.logException(error, LOG_INFO)
					res = json.dumps({"state": State.UNKNOWN, "message": str(error)})

			elif task == "checkDepotSyncStatus":
				try:
					res = self.monitoring.checkDepotSyncStatus(
						depotIds=params.get("depotIds", []),
						productIds=params.get("productIds", []),
						exclude=params.get("exclude", []),
						strict=params.get("strict", False),
						verbose=params.get("verbose", False)
					)
				except Exception as error:
					logger.logException(error, LOG_INFO)
					res = json.dumps({"state": State.UNKNOWN, "message": str(error)})

			elif task == "checkPluginOnClient":
				try:
					res = self.monitoring.checkPluginOnClient(
						hostId=params.get("clientId", []),
						command=params.get("plugin", ""),
						timeout=params.get("timeout", 30),
						waitForEnding=params.get("waitForEnding", True),
						captureStdErr=params.get("captureStdErr", True),
						statebefore=params.get("state", None),
						output=params.get("output", None),
						encoding=params.get("encoding", None)
					)
				except Exception as error:
					logger.logException(error, LOG_INFO)
					res = json.dumps({"state": State.UNKNOWN, "message": str(error)})
			elif task == "checkOpsiWebservice":
				cpu = params.get("cpu", [])
				errors = params.get("errors", [])

				try:
					res = self.monitoring.checkOpsiWebservice(cpu, errors)
				except Exception as error:
					logger.logException(error, LOG_INFO)
					res = json.dumps({"state": State.UNKNOWN, "message": str(error)})
			elif task == "checkOpsiDiskUsage":
				threshold = {
					"warning": params.get("warning", "5G"),
					"critical": params.get("critical", "1G")
				}

				try:
					res = self.monitoring.checkOpsiDiskUsage(
						opsiresource=params.get("resource", None),
						thresholds=threshold
					)
				except Exception as error:
					logger.logException(error, LOG_INFO)
					res = json.dumps({"state": State.UNKNOWN, "message": str(error)})
			elif task == "checkProductLocks":
				try:
					res = self.monitoring.checkLockedProducts(
						depotIds=params.get("depotIds", []),
						productIds=params.get("productIds", []),
					)
				except Exception as error:
					logger.logException(error, LOG_INFO)
					res = json.dumps({"state": State.UNKNOWN, "message": str(error)})
			else:
				res = json.dumps({
					"state": State.UNKNOWN,
					"message": u"Failure: unknown task!",
				})

			result.stream = stream.IByteStream(res.encode('utf-8'))
			return result
		else:
			logger.debug("No query given.")


class ResourceOpsiconfdMonitoring(ResourceOpsi):
	WorkerClass = WorkerOpsiconfdMonitoring


class Monitoring(object):

	ERRORCODE_PATTERN = re.compile('\[Errno\s(\d*)\]\sCommand\s(\'.*\')\sfailed\s\(\d*\)\:\s(.*)')

	def __init__(self, service):
		self.service = service

	def _generateResponse(self, state, message, perfdata=None):
		response = {
			"state": str(state)
		}

		if perfdata:
			if State.text(int(state)) in message:
				response["message"] = u"%s | %s" % (message, perfdata)
			else:
				response["message"] = u"%s: %s | %s" % (State.text(int(state)), message, perfdata)
		else:
			if State.text(int(state)) in message:
				response["message"] = u"%s" % message
			else:
				response["message"] = u"%s: %s" % (State.text(int(state)), message)

		return json.dumps(response)

	def checkClientStatus(self, clientId, excludeProductList=None):
		state = State.OK

		if not clientId:
			raise Exception(u"Failed to check: ClientId is needed for checkClientStatus")

		clientObj = self.service._backend.host_getObjects(id=clientId)
		if not clientObj:
			state = State.UNKNOWN
			return self._generateResponse(state, u"opsi-client: '%s' not found" % clientId)
		else:
			clientObj = clientObj[0]

		message = ''
		if not clientObj.lastSeen:
			state = State.WARNING
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
			elif state == State.OK:
				state = State.WARNING
				message += u"opsi-client: '%s' never seen, please check opsi-client-agent installation on client. " % clientId

			if delta.days >= 30:
				state = State.WARNING
				message += "opsi-client %s has not been seen, since %d days. Please check opsi-client-agent installation on client or perhaps a client that can be deleted. " % (clientId, delta.days)
			elif delta.days == 0:
				message += "opsi-client %s has been seen today. " % (clientId)
			else:
				message += "opsi-client %s has been seen %d days before. " % (clientId, delta.days)

		failedProducts = self.service._backend.productOnClient_getObjects(
			clientId=clientId,
			actionResult='failed'
		)

		if excludeProductList:
			productsToExclude = set(forceProductIdList(excludeProductList))
		else:
			productsToExclude = []

		failedProducts = [
			poc for poc in failedProducts
			if poc.productId not in productsToExclude
		]

		if failedProducts:
			state = State.CRITICAL
			products = [product.productId for product in failedProducts]
			message += "Products: '%s' are in failed state. " % (",".join(products))

		actionProducts = self.service._backend.productOnClient_getObjects(clientId=clientId, actionRequest=['setup', 'update', 'uninstall'])
		actionProducts = [
			poc for poc in actionProducts
			if poc.productId not in productsToExclude
		]

		if actionProducts:
			if state != State.CRITICAL:
				state = State.WARNING
			products = ["%s (%s)" % (product.productId, product.actionRequest) for product in actionProducts]
			message += "Actions set for products: '%s'." % (",".join(products))

		if state == State.OK:
			message += "No failed products and no actions set for client"

		return self._generateResponse(state, message)

	def checkShortProductStatus(self, productId=None, thresholds={}):
		actionRequestOnClients = []
		productProblemsOnClients = []
		productVersionProblemsOnClients = []
		uptodateClients = []
		targetProductVersion = None
		targetPackackeVersion = None

		state = State.OK
		message = []

		warning = thresholds.get("warning", "20")
		critical = thresholds.get("critical", "20")
		warning = float(removePercent(warning))
		critical = float(removePercent(critical))

		logger.debug("Checking shortly the productStates on Clients")
		configServer = self.service._backend.host_getObjects(type="OpsiConfigserver")[0]
		for pod in self.service._backend.productOnDepot_getObjects(depotId=configServer.id, productId=productId):
			targetProductVersion = pod.productVersion
			targetPackackeVersion = pod.packageVersion

		productOnClients = self.service._backend.productOnClient_getObjects(productId=productId)

		if not productOnClients:
			return self._generateResponse(State.UNKNOWN, "No ProductStates found for product '%s'" % productId)

		for poc in productOnClients:
			if poc.installationStatus != "not_installed" and poc.actionResult != "successful" and poc.actionResult != "none":
				if poc.clientId not in productProblemsOnClients:
					productProblemsOnClients.append(poc.clientId)
					continue

			if poc.actionRequest != 'none':
				if poc.clientId not in actionRequestOnClients:
					actionRequestOnClients.append(poc.clientId)
					continue

			if not poc.productVersion or not poc.packageVersion:
				continue

			if poc.productVersion != targetProductVersion or poc.packageVersion != targetPackackeVersion:
				productVersionProblemsOnClients.append(poc.clientId)
				continue

			if poc.actionResult == "successful":
				uptodateClients.append(poc.clientId)

		message.append("%d ProductStates for product: '%s' found; checking for Version: '%s' and Package: '%s'" % (len(productOnClients), productId, targetProductVersion, targetPackackeVersion))
		if uptodateClients:
			message.append("%d Clients are up to date" % len(uptodateClients))
		if actionRequestOnClients and len(actionRequestOnClients) * 100 / len(productOnClients) > warning:
			state = State.WARNING
			message.append("ActionRequest set on %d clients" % len(actionRequestOnClients))
		if productProblemsOnClients:
			message.append("Problems found on %d clients" % len(productProblemsOnClients))
		if productVersionProblemsOnClients:
			message.append("Version difference found on %d clients" % len(productVersionProblemsOnClients))

		problemClientsCount = len(productProblemsOnClients) + len(productVersionProblemsOnClients)
		if problemClientsCount * 100 / len(productOnClients) > critical:
			state = State.CRITICAL

		return self._generateResponse(state, "; ".join(message))

	def checkProductStatus(self, productIds=[], productGroups=[], hostGroupIds=[], depotIds=[], exclude=[], verbose=False):
		if not productIds:
			productIds = set()
			for product in self.service._backend.objectToGroup_getIdents(groupType='ProductGroup', groupId=productGroups):
				product = product.split(";")[2]
				if product not in exclude:
					productIds.add(product)

		if not productIds:
			return self._generateResponse(State.UNKNOWN, u"Neither productId nor productGroup given, nothing to check!")

		serverType = None
		if not depotIds:
			serverType = "OpsiConfigserver"
		elif 'all' in depotIds:
			serverType = "OpsiDepotserver"

		if serverType:
			depots = self.service._backend.host_getObjects(attributes=['id'], type=serverType)
			depotIds = set(depot.id for depot in depots)
			del depots

		if hostGroupIds:
			objectToGroups = self.service._backend.objectToGroup_getObjects(groupId=hostGroupIds, groupType="HostGroup")
			if objectToGroups:
				clientIds = [objectToGroup.objectId for objectToGroup in objectToGroups]
			else:
				clientIds = []
		else:
			clientIds = self.service._backend.host_getIdents(type="OpsiClient")

		clientsOnDepot = defaultdict(list)
		with temporaryBackendOptions(self.service._backend, addConfigStateDefaults=True):
			for configState in self.service._backend.configState_getObjects(configId=u'clientconfig.depot.id', objectId=clientIds):
				if not configState.values or not configState.values[0]:
					logger.error(u"No depot server configured for client '%s'" % configState.objectId)
					continue

				depotId = configState.values[0]
				if depotId not in depotIds:
					continue

				clientsOnDepot[depotId].append(configState.objectId)

		productOnDepotInfo = defaultdict(dict)
		for pod in self.service._backend.productOnDepot_getObjects(depotId=depotIds, productId=productIds):
			productOnDepotInfo[pod.depotId][pod.productId] = {
				"productVersion": pod.productVersion,
				"packageVersion": pod.packageVersion
			}

		state = State.OK
		productVersionProblemsOnClient = defaultdict(lambda: defaultdict(list))
		productProblemsOnClient = defaultdict(lambda: defaultdict(list))
		actionRequestOnClient = defaultdict(lambda: defaultdict(list))

		actionRequestsToIgnore = set([None, 'none', 'always'])

		for depotId in depotIds:
			for poc in self.service._backend.productOnClient_getObjects(productId=productIds, clientId=clientsOnDepot.get(depotId, None)):
				if poc.actionRequest not in actionRequestsToIgnore:
					if state != State.CRITICAL:
						state = State.WARNING

					actionRequestOnClient[depotId][poc.productId].append(u"%s (%s)" % (poc.clientId, poc.actionRequest))

				if poc.installationStatus != "not_installed" and poc.actionResult != "successful" and poc.actionResult != "none":
					if state != State.CRITICAL:
						state = State.CRITICAL

					productProblemsOnClient[depotId][poc.productId].append(u"%s (%s lastAction: [%s])" % (poc.clientId, poc.actionResult, poc.lastAction))

				if not poc.productVersion or not poc.packageVersion:
					continue

				if depotId not in productOnDepotInfo:
					continue

				try:
					productOnDepot = productOnDepotInfo[depotId][poc.productId]
				except KeyError:
					logger.debug("Product {} not found on depot {}", poc.productId, depotId)
					continue

				if (poc.productVersion != productOnDepot["productVersion"] or
					poc.packageVersion != productOnDepot["packageVersion"]):

					if state != State.CRITICAL:
						state = State.WARNING

					productVersionProblemsOnClient[depotId][poc.productId].append("%s (%s-%s)" % (poc.clientId, poc.productVersion, poc.packageVersion))

		message = ''
		for depotId in depotIds:
			if depotId in actionRequestOnClient or depotId in productProblemsOnClient or depotId in productVersionProblemsOnClient:
				message += "Result for Depot: '%s': " % depotId
			else:
				continue

			if depotId in actionRequestOnClient:
				for product, clients in actionRequestOnClient[depotId].items():
					message += "For product '%s' action set on %d clients! " % (product, len(clients))
			if depotId in productProblemsOnClient:
				for product, clients in productProblemsOnClient[depotId].items():
					message += "For product '%s' problems found on %d clients! " % (product, len(clients))
			if depotId in productVersionProblemsOnClient:
				for product, clients in productVersionProblemsOnClient[depotId].items():
					message += "For product '%s' version difference problems found on %d clients! " % (product, len(clients))

		if not verbose:
			if state == State.OK:
				message = u"No Problem found for productIds: '%s'" % ",".join(productIds)
			return self._generateResponse(state, message)

		for depotId in depotIds:
			if depotId in actionRequestOnClient or depotId in productProblemsOnClient or depotId in productVersionProblemsOnClient:
				message += "\nResult for Depot: '%s':" % depotId
			else:
				continue

			if depotId in actionRequestOnClient:
				for product, clients in actionRequestOnClient[depotId].items():
					message += "\n  Action Request set for product '%s':\n" % product
					for client in clients:
						message += "    %s\n" % client

			if depotId in productProblemsOnClient:
				for product, clients in productProblemsOnClient[depotId].items():
					message += "\n  Product Problems for product '%s':\n" % product
					for client in clients:
						message += "    %s\n" % client

			if depotId in productVersionProblemsOnClient:
				for product, clients in productVersionProblemsOnClient[depotId].items():
					message += "\n  Product Version difference found for product '%s': \n" % product
					for client in clients:
						message += "    %s\n" % client

		if state == State.OK:
			if productGroups:
				message = u"No Problem found for product groups '%s'" % ",".join(productGroups)
			else:
				message = u"No Problem found for productIds '%s'" % ",".join(productIds)

		return self._generateResponse(state, message)

	def checkDepotSyncStatus(self, depotIds, productIds=[], exclude=[], strict=False, verbose=False):
		if not depotIds or 'all' in depotIds:
			depots = self.service._backend.host_getObjects(type="OpsiDepotserver")
			depotIds = [depot.id for depot in depots]

		productOnDepots = self.service._backend.productOnDepot_getObjects(depotId=depotIds, productId=productIds)
		productIds = set()
		productOnDepotInfo = defaultdict(dict)
		for pod in productOnDepots:
			productIds.add(pod.productId)
			productOnDepotInfo[pod.depotId][pod.productId] = pod

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

		state = State.OK
		message = u''
		if differenceProducts:
			state = State.WARNING
			message += u"Differences found for %d products" % len(differenceProducts)

			if verbose:
				message += u":\n"
				for productId in sorted(differenceProducts):
					message += u"product '%s': " % productId
					for depotId in depotIds:
						try:
							if differenceProducts[productId][depotId] == "not installed":
								message += u"%s (not installed) \n" % depotId
							else:
								message += u"%s (%s-%s) \n" % (
									depotId,
									productOnDepotInfo[depotId][productId].productVersion,
									productOnDepotInfo[depotId][productId].packageVersion
								)
						except KeyError:
							if not productOnDepotInfo.get(depotId, {}).get(productId, None):
								continue

							message += u"%s (%s-%s) " % (
								depotId,
								productOnDepotInfo[depotId][productId].productVersion,
								productOnDepotInfo[depotId][productId].packageVersion
							)
		else:
			message += "Syncstate ok for depots %s" % ", ".join(depotIds)

		return self._generateResponse(state, message)

	def checkPluginOnClient(self, hostId, command, timeout=30, waitForEnding=True, captureStdErr=True, statebefore=None, output=None, encoding=None):
		state = State.OK
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
							match = self.ERRORCODE_PATTERN.match(errormessage)
							if not match:
								state = State.UNKNOWN
								message = u"Unable to parse Errorcode from plugin"
							else:
								errorcode = int(match.group(1))
								command = match.group(2)
								message = match.group(3)
								if not errorcode > 3:
									state = errorcode
								else:
									state = State.UNKNOWN
									message = "Failed to determine Errorcode from check_command: '%s', message is: '%s'" \
										% (command, message)
						else:
							state = State.UNKNOWN
							message = u"Unknown Problem by checking plugin on Client. Check your configuration."
					else:
						state = State.UNKNOWN
						message = u"Unknown Problem by checking plugin on Client. Check your configuration."
			else:
				if result.get("error", None):
					message = result.get("error").get("message", "")
					state = State.UNKNOWN
				elif statebefore and output:
					return self._generateResponse(int(statebefore), output)
				else:
					message = "Can't check host '%s' is not reachable." % hostId[0]
					state = State.UNKNOWN
		except Exception as erro:
			state = State.UNKNOWN
			message = str(erro)

		return self._generateResponse(state, message)

	def checkOpsiDiskUsage(self, thresholds={}, opsiresource=None):
		warning = thresholds.get("warning", "5G")
		critical = thresholds.get("critical", "1G")

		if opsiresource:
			resources = forceList(opsiresource)
		else:
			resources = list(self.service.config['staticDirectories'])
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

		results = {}
		state = State.OK
		message = []

		try:
			for resource in resources:
				path = self.service.config['staticDirectories'][resource]['path']
				if os.path.isdir(path):
					if not resource.startswith('/'):
						resource = u'/' + resource

					info = getDiskSpaceUsage(path)
					results[resource] = info
		except Exception as error:
			message.append(u"Not able to check DiskUsage. Error: '%s'" % str(error))
			return self._generateResponse(State.UNKNOWN, message)

		if results:
			state = State.OK
			for result, info in results.items():
				available = float(info['available']) / 1073741824
				usage = info['usage'] * 100
				if unit == "GB":
					if available <= critical:
						state = State.CRITICAL
						message.append(u"DiskUsage from ressource: '%s' is critical (available: '%.2f'GB)." % (result, available))
					elif available <= warning:
						if state != State.CRITICAL:
							state = State.WARNING
						message.append(u"DiskUsage warning from ressource: '%s' (available: '%.2f'GB)." % (result, available))
					else:
						message.append(u"DiskUsage from ressource '%s' is ok. (available: '%.2f'GB)." % (result, available))
				elif unit == "%":
					freeSpace = 100 - usage
					if freeSpace <= critical:
						state = State.CRITICAL
						message.append(u"DiskUsage from ressource: '%s' is critical (available: '%.2f%%')." % (result, freeSpace))

					elif freeSpace <= warning:
						if state != State.CRITICAL:
							state = State.WARNING
						message.append(u"DiskUsage warning from ressource: '%s' (available: '%.2f%%')." % (result, freeSpace))

					else:
						message.append(u"DiskUsage from ressource: '%s' is ok. (available: '%.2f%%')." % (result, freeSpace))

		else:
			state = State.UNKNOWN
			message.append("No results get. Nothing to check.")

		if state == State.OK:
			message = u"OK: %s" % " ".join(message)
		elif state == State.WARNING:
			message = u"WARNING: %s" % " ".join(message)
		elif state == State.CRITICAL:
			message = u"CRITICAL: %s" % " ".join(message)

		return self._generateResponse(state, message)

	def checkOpsiWebservice(self, cputhreshold=[], errors=[], perfdata=True):
		state = State.OK
		logger.debug(u"Generating Defaults for checkOpsiWebservice if not given")
		if not cputhreshold:
			cputhreshold = [80, 60]
		if not errors:
			errors = [20, 10]

		try:
			performanceHash = self.service.statistics().getStatistics()

			rpcerrors = performanceHash["rpcerrors"]
			rpcs = performanceHash["rpcs"]
			if int(rpcerrors) == 0 or int(rpcs) == '0':
				errorrate = 0
			else:
				errorrate = int(rpcerrors) * 100 // int(rpcs)

			message = []
			if errorrate > errors[0]:
				message.append(u'RPC errors over {}%'.format(errors[0]))
				state = State.CRITICAL
			elif errorrate > errors[1]:
				message.append(u'RPC errors over {}%'.format(errors[1]))
				state = State.WARNING

			cpu = int(performanceHash["cpu"])
			if cpu > cputhreshold[0]:
				state = State.CRITICAL
				message.append(u'CPU-Usage over {}%'.format(cputhreshold[0]))
			elif cpu > cputhreshold[1]:
				if not state == State.CRITICAL:
					state = State.WARNING
				message.append(u'CPU-Usage over {}%'.format(cputhreshold[1]))

			if state == State.OK:
				message.append("OK: Opsi Webservice has no Problem")

			message = " ".join(message)

			if perfdata:
				performance = [
					u'requests=%s;;;0; ' % performanceHash["requests"],
					u'davrequests=%s;;;0; ' % performanceHash["davrequests"],
					u'rpcs=%s;;;0; ' % rpcs,
					u'rpcerror=%s;;;0; ' % rpcerrors,
					u"sessions=%s;;;0; " % performanceHash["sessions"],
					u"threads=%s;;;0; " % performanceHash["threads"],
					u"virtmem=%s;;;0; " % performanceHash["virtmem"],
					u"cpu=%s;;;0;100 " % performanceHash["cpu"]
				]

				return self._generateResponse(state, message, "".join(performance))
			else:
				return self._generateResponse(state, message)
		except Exception as error:
			state = State.UNKNOWN
			message = u"cannot check webservice state: '%s'." % str(error)
			return self._generateResponse(state, message)

	def checkLockedProducts(self, depotIds=None, productIds=[]):
		if not depotIds or 'all' in depotIds:
			depots = self.service._backend.host_getObjects(type="OpsiDepotserver")
			depotIds = [depot.id for depot in depots]

		lockedProducts = self.service._backend.productOnDepot_getObjects(depotId=depotIds, productId=productIds, locked=True)

		state = State.OK
		if lockedProducts:
			state = State.WARNING

			message = u'{} products are in locked state.'.format(len(lockedProducts))
			for prodOnDepot in lockedProducts:
				message += '\nProduct {0.productId} locked on depot {0.depotId}'.format(prodOnDepot)
		else:
			message = "No products locked on depots: {}".format(",".join(depotIds))

		return self._generateResponse(state, message)


def removePercent(string):
	if string.endswith("%"):
		return string[:-1]
	else:
		return string
