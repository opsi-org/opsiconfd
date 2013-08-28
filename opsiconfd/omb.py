#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
opsi configuration daemon - message bus

opsiconfd is part of the desktop management solution opsi
(open pc server integration) http://www.opsi.org

Copyright (C) 2011-2013 uib GmbH

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
@author: Niko Wenselowski <n.wenselowski@uib.de>
@license: GNU Affero General Public License version 3
"""

import base64
from sys import version_info
if (version_info >= (2,6)):
	import json
else:
	import simplejson as json

if (version_info < (2,5)):
	import sha as sha1
else:
	from hashlib import sha1

from OPSI.Logger import Logger
from OPSI.web2.channel.http import HTTPChannel, HTTPFactory
from OPSI.Util.MessageBus import MessageBusClient, MessageBusServerFactory
from OPSI.Util.HTTP import hybi10Encode, hybi10Decode
from OPSI.Backend.BackendManager import BackendAccessControl
from OPSI.Types import forceUnicode

logger = Logger()

ombTestPage = '''
<html>
<head>
	<title>opsi message bus</title>
</head>
<body>
	<p id="title">
		<img src="/opsi_logo.png" />
		<span style="font-family: verdana, arial; padding: 10px; color: #6276a0; font-size: 20px; letter-spacing: 5px;">opsi message bus</span>
	</p>
	<p name="connection" id="connection" style="color: #a5183b; font-family: verdana, arial; padding: 20px 0px 0px 30px; font-size: 13px;">Not connected</p>
	<textarea name="events" id="events" style="font-family: verdana, arial; width: 95%%; height: 80%%; color: #555555; margin: 0px 30px 30px 30px; padding: 20px; background-color: #fafafa; border: 1px #abb1ef dashed; font-size: 11px;"></textarea>

	<script type="text/javascript">
	var websocket = null;
	var websocket_url = "wss://%(host)s:%(port)s/omb";
	var client_id = '';
	var eventbox_color = '#555555';
	function create_websocket() {
		if ('WebSocket' in window) {
			websocket = new WebSocket(websocket_url);
		}
		else if ('MozWebSocket' in window) {
			websocket = new MozWebSocket(websocket_url);
		}
		if (websocket != null) {
			websocket.onopen = function() {
				var el = document.getElementById("connection");
				el.innerHTML = 'Connected';
				el.style.color = '#0ca225';

				cookies = client.headers['cookie'];
			}
			websocket.onclose = function() {
				websocket = null;
				var el = document.getElementById("connection");
				el.innerHTML = 'Not connected';
				el.style.color = '#a5183b';
				setTimeout("create_websocket()",10000);
			}
			websocket.onmessage = function(evt) {
				var data = evt.data;
				append_line(data);
				blink();
				var obj = eval(data);
				if (obj[0].message_type == "init") {
					client_id = obj[0].client_id;
					websocket.send('{"client_id":"' + client_id + '","message_type":"register_for_object_events","operations":[],"object_types":[]}');
				}

			}
		}
	}
	function blink() {
		var el = document.getElementById("events");
		if (eventbox_color == '#555555') {
			eventbox_color = '#6276a0';
			setTimeout("blink()",300);
		}
		else {
			eventbox_color = '#555555';
		}
		el.style.color = eventbox_color;
	}
	function append_line(text) {
		var el = document.getElementById("events");
		el.value = el.value + text + '\\n';
		el.scrollTop = el.scrollHeight;
	}
	create_websocket();
	</script>
</body>
</html>
'''

class OMBClient(MessageBusClient):
	def __init__(self, ombService):
		MessageBusClient.__init__(self)
		self.__ombService = ombService

	def initialized(self):
		self.registerForObjectEvents(object_types = [], operations = [])

	def objectEventReceived(self, object_type, ident, operation):
		self.__ombService.objectEventReceived(object_type, ident, operation)

class MessageBusService(MessageBusServerFactory):
	def __init__(self):
		MessageBusServerFactory.__init__(self)
		self._ombClient = OMBClient(self)

	def start(self):
		self._ombClient.start(startReactor = False)

	def stop(self):
		self._ombClient.stop()
		self._ombClient.join(5)

	def objectEventReceived(self, object_type, ident, operation):
		self._sendObjectEvent(object_type, ident, operation)

	def connectionMade(self, client, readonly = True):
		MessageBusServerFactory.connectionMade(self, client, readonly=readonly)

	def transmitMessages(self, messages, clientId):
		logger.info(u"Transmitting messages to client '%s'" % clientId)
		messages = json.dumps(messages)
		client = self.clients.get(clientId)
		if not client:
			logger.error(u"Failed to send message: client '%s' not connected" % clientId)
			return
		client['connection'].sendMessage(messages)

class OpsiconfdHTTPChannel(HTTPChannel):
	messageBusService = None
	backend = None

	def __init__(self):
		HTTPChannel.__init__(self)
		self.__handshakeDone = False
		self.__readOnly = True
		self.__authenticated = False
		self.__headers = {}
		self.__wsbuffer = ''

	def _isWebsocketConnection(self):
		if not self.messageBusService:
			return False
		return self.__handshakeDone

	def connectionLost(self, reason):
		if self._isWebsocketConnection():
			self.messageBusService.connectionLost(self, reason)
		else:
			HTTPChannel.connectionLost(self, reason)

	def rawDataReceived(self, data):
		if self._isWebsocketConnection():
			if data and data.endswith('\n'):
				data = data[:-1]
			if data and data.endswith('\r'):
				data = data[:-1]
			self.__wsbuffer += data
			data = hybi10Decode(self.__wsbuffer)
			if data:
				self.onMessage(data.decode('utf-8'))
				self.__wsbuffer = ''
		else:
			HTTPChannel.rawDataReceived(self, data)

	def sendMessage(self, message):
		encodedData = hybi10Encode(forceUnicode(message).encode('utf-8'))
		self.transport.write(encodedData)

	def onMessage(self, message):
		logger.debug2(u"onMessage: %s" % message)
		self.messageBusService.lineReceived(message)

	def _authenticate(self):
		if self.__authenticated:
			return
		(user, password) = (u'', u'')
		try:
			encoded = self.__headers['authorization'].strip().split()[1]
			parts = unicode(base64.decodestring(encoded), 'latin-1').split(':')
			user = parts[0].strip()
			password = u':'.join(parts[1:]).strip()
		except:
			raise OpsiAuthenticationError(u"Failed to read authorization header")

		bac = BackendAccessControl(
			backend     = self.backend,
			username    = user,
			password    = password
		)
		if not bac.accessControl_authenticated():
			raise OpsiAuthenticationError(u"Bad user or password")
		if not bac.accessControl_userIsAdmin():
			raise OpsiAuthenticationError(u"User is not allowed to access opsi message bus")
		self.__authenticated = True
		self.__readOnly = False

	def _websocketHandshake(self):
		self.__handshakeDone = False

		# 'sec-websocket-origin',
		for header in ('upgrade', 'connection', 'host', 'sec-websocket-key', 'sec-websocket-version'):
			if not self.__headers.get(header):
				logger.error(u'Websocket handshake error: header %s missing' % header)
				raise Exception(u'Websocket handshake error: header %s missing' % header)

		key = self.__headers.get('sec-websocket-key').strip()
		key += '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
		key = sha1(key).digest()
		key = base64.encodestring(key)

		headers =  'HTTP/1.1 101 Switching Protocols\r\n'
		headers += 'Upgrade: websocket\r\n'
		headers += 'Connection: Upgrade\r\n'
		headers += 'Sec-WebSocket-Accept: %s\r\n' % key.strip()
		headers += 'WebSocket-Protocol: omb\r\n'
		self.sendLine(headers)

		self.setRawMode()

		self.__handshakeDone = True

		self.messageBusService.connectionMade(self, readonly = self.__readOnly)

	def lineReceived(self, line):
		#logger.debug2("lineReceived: %s" % line)
		if self.chanRequest and self.chanRequest.path.startswith('/omb'):
			line = line.strip()
			if line:
				if (line.find(':') == -1):
					raise Exception(u"Bad header: %s" % line)
				(k, v) = line.split(':', 1)
				self.__headers[k.strip().lower()] = v.strip()
			else:
				logger.confidential("Headers: %s" % self.__headers)
				try:
					self._authenticate()
				except Exception, e:
					logger.debug(u"Unauthorized connection attempt to opsi message bus: %s" % e)
					#logger.warning(u"Unauthorized connection attempt to opsi message bus: %s" % e)
					#headers =  'HTTP/1.1 401 Unauthorized\r\n'
					#headers += 'www-authenticate: basic realm="opsi message bus"\r\n'
					#self.sendLine(headers)
					#self.lingeringClose()
					#return

				if (self.chanRequest.path == '/omb.html'):
					(host, port) = self.chanRequest.transport.socket.getsockname()
					headers  = 'HTTP/1.1 200 OK\r\n'
					headers += 'Content-Type: text/html\r\n'
					self.sendLine(headers)
					self.sendLine(ombTestPage % { 'host': host, 'port': port})
					self.lingeringClose()
				else:
					self._websocketHandshake()
			return
		return HTTPChannel.lineReceived(self, line)

class OpsiconfdHTTPFactory(HTTPFactory):
	protocol = OpsiconfdHTTPChannel
