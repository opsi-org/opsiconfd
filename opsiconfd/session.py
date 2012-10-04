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

from OPSI.Service.Session import SessionHandler, Session
from OPSI.Types import *
from OPSI.Logger import *

logger = Logger()

class OpsiconfdSession(Session):
	def __init__(self, sessionHandler, name = u'OPSISID', sessionMaxInactiveInterval = 120):
		Session.__init__(self, sessionHandler, name, sessionMaxInactiveInterval)
		self.callInstance = None
		self.callInterface = None
		self.isHost = False
		self.isAdmin = False
		self.isReadOnlyUser = False
		self.lastRpcSuccessfullyDecoded = False
		self.lastRpcMethod = u''
		
	def setLastRpcSuccessfullyDecoded(self, successfullyDecoded):
		self.lastRpcSuccessfullyDecoded = forceBool(successfullyDecoded)
		
	def setLastRpcMethod(self, methodName):
		self.lastRpcMethod = forceUnicode(methodName)
	
	def delete(self):
		Session.delete(self)
		if self.callInstance:
			logger.debug(u"Calling backend_exit() on backend %s" % self.callInstance)
			self.callInstance.backend_exit()

class OpsiconfdSessionHandler(SessionHandler):
	def __init__(self, opsiconfd):
		self.opsiconfd = opsiconfd
		SessionHandler.__init__(self,
			sessionName                = self.opsiconfd.config['sessionName'],
			sessionMaxInactiveInterval = self.opsiconfd.config['sessionMaxInactiveInterval'],
			maxSessionsPerIp           = self.opsiconfd.config['maxSessionsPerIp'])
	
	def createSession(self):
		session = OpsiconfdSession(self, self.sessionName, self.sessionMaxInactiveInterval)
		self.sessions[session.uid] = session
		logger.notice(u"New session created")
		self.opsiconfd.statistics().addSession(session)
		return session
	
	def sessionExpired(self, session):
		if (session.usageCount > 0):
			# Session in use (long running method?)
			self.sessionDeletionTimeout = 3600
		if SessionHandler.sessionExpired(self, session):
			# Session expired
			self.opsiconfd.statistics().sessionExpired(session)
		
		
	def deleteSession(self, uid):
		session = self.sessions.get(uid)
		if session:
			self.opsiconfd.statistics().removeSession(session)
		SessionHandler.deleteSession(self, uid)
	


