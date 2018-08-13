#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
opsi configuration daemon - resources

opsiconfd is part of the desktop management solution opsi
(open pc server integration) http://www.opsi.org

Copyright (C) 2010-2018 uib GmbH

http://www.uib.de/

All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

@copyright:  uib GmbH <info@uib.de>
@author: Jan Schneider <j.schneider@uib.de>
@author: Erol Ueluekmen <e.ueluekmen@uib.de>
@author: Niko Wenselowski <n.wenselowski@uib.de>
@license: GNU Affero General Public License version 3
"""

from OPSI.web2 import http, resource
from OPSI.Service.Resource import ResourceOpsi, ResourceOpsiJsonRpc, ResourceOpsiJsonInterface, ResourceOpsiDAV

from workers import WorkerOpsiconfd, WorkerOpsiconfdJsonRpc, WorkerOpsiconfdJsonInterface, WorkerOpsiconfdDAV


class ResourceRoot(resource.Resource):
	addSlash = True

	def render(self, request):
		''' Process request. '''
		return http.Response(stream="<html><head><title>opsiconfd</title></head><body></body></html>")


class ResourceOpsiconfd(ResourceOpsi):
	WorkerClass = WorkerOpsiconfd

	def renderHTTP(self, request):
		self._service.statistics().addRequest(request)
		return ResourceOpsi.renderHTTP(self, request)


class ResourceOpsiconfdJsonRpc(ResourceOpsiJsonRpc):
	WorkerClass = WorkerOpsiconfdJsonRpc


class ResourceOpsiconfdJsonInterface(ResourceOpsiJsonInterface):
	WorkerClass = WorkerOpsiconfdJsonInterface


class ResourceOpsiconfdDAV(ResourceOpsiDAV):
	WorkerClass = WorkerOpsiconfdDAV

	def __init__(self, service, path, readOnly=True, defaultType="text/plain", indexNames=None, authRequired=True):
		ResourceOpsiDAV.__init__(self, service, path, readOnly, defaultType, indexNames, authRequired)

	def renderHTTP(self, request):
		self._service.statistics().addWebDAVRequest(request)
		return ResourceOpsiDAV.renderHTTP(self, request)
