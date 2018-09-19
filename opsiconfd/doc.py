# -*- coding: utf-8 -*-
"""
opsi configuration daemon - documentation

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
@author: Christian Kampka <c.kampka@uib.de>
@author: Niko Wenselowski <n.wenselowski@uib.de>
@license: GNU Affero General Public License version 3
"""

from OPSI.web2.static import File
from OPSI.web2.dirlist import DirectoryLister
from OPSI.web2 import http, http_headers
from OPSI.Logger import Logger
import gettext


logger = Logger()

try:
	t = gettext.translation('python-opsi', '/usr/share/locale')
	_ = t.ugettext
except Exception as e:
	logger.error(u"Locale not found: %s" % e)

	def _(string):
		return string


class DocumentationDirectoryLister(DirectoryLister):
	_title = _("opsi Documentation and Manuals")
	_template = u'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<title>%s</title>
	<style>
	a:link 	  { color: #555555; text-decoration: none; }
	a:visited { color: #555555; text-decoration: none; }
	a:hover	  { color: #46547f; text-decoration: none; }
	a:active  { color: #555555; text-decoration: none; }
	body      { font-family: verdana, arial; font-size: 12px; }
	#title    { padding: 10px; color: #6276a0; font-size: 20px; letter-spacing: 5px; }
	h1        { font-size: 14px; font-weight; bold; letter-spacing: 2px; }
	ul li     { font-size: 14px;}
	</style>
</head>
<body>
	<div id="title">
		<img src="/opsi_logo.png" />
		<span style="padding: 1px">%s</span>
	</div>
	<div>
		__content__
	</div>

</body>
</html>
''' % (_title, _title)
	_li = '<li><a href="%s">%s</a></li>'

	_langs = {
		"en": u"English",
		"de": u"Deutsch",
		"fr": u"Française",
	}

	def render(self, request):
		s = self._template

		content = []

		for row in self.data_listing(request, None):
			linktext = row["linktext"].rstrip("/")
			if row['type'] == '-':
				if linktext.startswith("opsi"):
					content.append(self._li % (row['link'] + ("%s.html" % linktext), linktext))
				elif linktext in self._langs:
					lang = linktext.rstrip("/")
					try:
						linktext = self._langs[lang]
					except KeyError:
						pass
					content.append(self._li % (row['link'], linktext))

		if len(content):
			s = s.replace("__content__", "<ul>%s</ul>" % "".join(content)).encode('utf-8')
			response = http.Response(200, {}, s)
		else:
			s = s.replace("__content__", _("To view the documentation please install the opsi-doc package on your opsi server.")).encode('utf-8')
			response = http.Response(404, {}, s)
		response.headers.setHeader("content-type", http_headers.MimeType('text', 'html'))
		return response


class ResourceOpsiDocumentation(File):

	def __init__(self, path = "/usr/share/doc/opsi/xhtml", defaultType="text/xhtml", *args, **kwargs):
		File.__init__(self, path, defaultType, *args, **kwargs)

	def directoryListing(self):
		return DocumentationDirectoryLister(
			self.fp.path,
			self.listChildren(),
			self.contentTypes,
			self.contentEncodings,
			self.defaultType
		)
