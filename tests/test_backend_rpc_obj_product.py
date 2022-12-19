# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
test opsiconfd.backend.rpc.obj_product
"""

from pathlib import Path
from typing import Generator

import pytest

from opsiconfd.backend.rpc.opsiconfd import ProtectedBackend

from .utils import (  # pylint: disable=unused-import
	ADMIN_PASS,
	ADMIN_USER,
	Connection,
	OpsiconfdTestClient,
	clean_redis,
	database_connection,
	get_config,
	test_client,
)


@pytest.fixture(autouse=True)
def cleanup_database(database_connection: Connection) -> Generator[None, None, None]:  # pylint: disable=redefined-outer-name
	cursor = database_connection.cursor()
	cursor.execute("DELETE FROM `PRODUCT` WHERE productId LIKE 'test-backend-rpc-product%'")
	database_connection.commit()
	yield
	cursor.execute("DELETE FROM `PRODUCT` WHERE productId LIKE 'test-backend-rpc-product%'")
	database_connection.commit()
	cursor.close()


def test_product_insertObject(  # pylint: disable=invalid-name
	test_client: OpsiconfdTestClient,  # pylint: disable=redefined-outer-name,unused-argument
) -> None:
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	product1 = {
		"name": "test-backend-rpc-product-1",
		"licenseRequired": False,
		"setupScript": "setup.opsiscript",
		"uninstallScript": "uninstall.opsiscript",
		"updateScript": "update.opsiscript",
		"priority": 0,
		"description": "test-backend-rpc-product 1",
		"advice": "Some advice ",
		"changelog": 'jedit_5.3.0-2 stable; urgency=low\n\n   * opsi-script.xml for opsi-script 4.11.6.4\n\n-- d.oertel <d.oertel@uib.de> Tue, 11 Oct 2016 15:00:00 + 0100\n\njedit_5.3.0-1 stable; urgency=low\n\n   * update to 5.3\n   * opsi-script.xml for opsi-script 4.11.6.1\n\n-- d.oertel <d.oertel@uib.de> Fri, 24 Jun 2016 15:00:00 + 0100\n\njedit_5.2.0-2 stable; urgency=low\n\n   * script changes for win10\n\n-- detlef oertel <d.oertel@uib.de>  Tue, 30 June 2015 15:00:00 +0100\n\n\njedit_5.2.0-1 stable; urgency=low\n\n   * update to 5.2 stable\n   * update opsi-winst.xml to opsi-script xml 4.11.5.2\n   * code cleanup\n\n-- detlef oertel <d.oertel@uib.de>  Mon, 18 May 2015 15:00:00 +0100\n\njedit_5.1.0-3 stable; urgency=low\n\n   * check for jre8 fixes #1357\n\n-- bardo wolf <b.wolf@uib.de>  21 Jan 2015\n\njedit_5.1.0-2 stable; urgency=low\n\n   * update opsi-winst.xml to opsi-script xml 4.11.4.4\n\n-- detlef oertel <d.oertel@uib.de>  Thu, 17 Apr 2014 16:01:53 +0200\n\njedit_5.1.0-1 stable; urgency=low\n\n   * update to jedit 5.1\n   * update opsi-winst.xml to opsi-script xml 4.11.4.3\n\n-- detlef oertel <d.oertel@uib.de>  Fri, 17 Jan 2014 16:01:53 +0200\n\njedit_5.0.0-3 stable; urgency=low\n\n   * opsi-winst.xml for version 4.11.3.5\n   * code cleanup\n\n-- detlef oertel <d.oertel@uib.de>  Fri, 15 Feb 2013 16:01:53 +0200\n\njedit_5.0.0-2 stable; urgency=low\n\n   * jedit version with localization support\n\n  -- rupert röder <r.roeder@uib.de>  Tue, 27 Nov 2012 16:01:53 +0200\n\njedit_4.5.2-2 stable; urgency=low\n\n   * opsi-winst.xml for version 4.11.3.2\n\n  -- detlef oertel <d.oertel@uib.de>  Tue, 31 Jul 2012 16:01:53 +0200\n\njedit_4.5.2-1 stable; urgency=low\n\n   * update to version 4.5.2\n   * opsi-winst.xml for version 4.11.3.1\n   * opsi-winst.xml for *ins,*.opsiscript,*opsiinc\n\n  -- detlef oertel <d.oertel@uib.de>  Thu, 12 Jul 2012 16:01:53 +0200\n\njedit_4.5.1-1 stable; urgency=low\n\n   * update to version 4.5.1\n   * property gui_language description:  jedit localisation\n   values: ["auto", "de", "en", "fr"]\n   default: ["en"]\n\n\n  -- bardo wolf <b.wolf@uib.de>   12 Jun 2012\n\njedit_4.5-3 stable; urgency=low\n   * moved changelog to changelog file cause ldap-Backend\n  -- bardo wolf <b.wolf@uib.de>   1 Mar 2012\n\njedit_4.5-2 stable; urgency=low\n\n   * updated opsi-winst mode file (4.11.2.6): ChangeDirectory\n\n  -- detlef oertel <d.oertel@uib.de>  Wed, 13 Feb 2012 16:01:53 +0200\n\njedit_4.5-1 stable; urgency=low\n\n   * update to version 4.5\n   * propery startserver (default=off)\n   * moved changelog to control file\n\n  -- detlef oertel <d.oertel@uib.de>  Wed, 02 Jan 2012 16:01:53 +0200\n\n\njedit_4.4.1-4 stable; urgency=low\n\n   * modify mode file FILE_NAME_GLOB="*.asciidoc"\n\n  -- karsten köpke <k.koepke@uib.de>  Wed, 05 Oct 2011 16:01:53 +0200\n\n\njedit_4.4.1-3 stable; urgency=low\n\n   * updatet opsi-winst mode file (4.11.2.1): profileactions\n\n  -- detlef oertel <d.oertel@uib.de>  Wed, 05 Oct 2011 16:01:53 +0200\n\n\njedit_4.4.1-2 stable; urgency=low\n\n   * updatet opsi-winst mode file (4.11.2.1)\n   * added /SUPPRESSMSGBOXES to setup call and comment out autoit call\n   * version 4.3 removed\n   * test for java 1.6 and 1.7\n\n  -- detlef oertel <d.oertel@uib.de>  Wed, 05 Oct 2011 16:01:53 +0200\n\n\njedit_4.4.1-1 stable; urgency=low\n\n   * updatet opsi-winst mode file\n   * jedit ver 4.4.1\n\n  -- detlef oertel <d.oertel@uib.de>  Mon, 02 Aug 2011 16:01:53 +0200\n\n\njedit_4.3.2-6 stable; urgency=low\n\n   * new asciidoc mode file\n\n  -- Jan Schneider <j.schneider@uib.de>  Fri, 25 Mar 2011 10:13:00 +0100\n\njedit_4.3.2-5 stable; urgency=low\n\n\t* changed: winst.xml changed to opsi-winst.xml\n\t* new: opsi-log.xml\n\t* new: asciidoc.xml\n\n  -- detlef oertel <d.oertel@uib.de>  Mon, 22 Feb 2011 16:01:53 +0200\n\n\njedit_4.3.2-4 stable; urgency=low\n\n\t* (x64) installations go to "%ProgramFilesSysnativeDir%\\" + $ProductId$\n\t* prority set to 0\n\n  -- detlef oertel <d.oertel@uib.de>  Mon, 29 Aug 2010 16:01:53 +0200\n\njedit_4.3.2-3 stable; urgency=low\n\n\t* bugFix in Line 54 LogError Command\n\n -- erol ueluekmen <e.ueluekmen@uib.de>  Fri, 13 Aug 2010 16:01:53 +0200\n\njedit_4.3.2-2 stable; urgency=low\n\n\t* added jar based silent install for nt6 familiy (bug in silent installer)\n\t* requires winst 4.10.8 -> uses %ProgramFiles32Dir%\n\n -- detlef oertel <d.oertel@uib.de>  Wed, 29 Jun 2010 16:01:53 +0200\n\n\njedit_4.3.2-1 stable; urgency=low\n\n\t* initial\n\n -- detlef oertel <d.oertel@uib.de>  Wed, 29 Jun 2010 16:01:53 +0200\n\n\n\n\n\n\n',
		"id": "test-backend-rpc-product-1",
		"productVersion": "5.3.0",
		"packageVersion": "2",
		"type": "LocalbootProduct",
	}
	product2 = {
		"name": "test-backend-rpc-product-2",
		"licenseRequired": False,
		"setupScript": "setup.opsiscript",
		"uninstallScript": "uninstall.opsiscript",
		"updateScript": "update.opsiscript",
		"priority": 0,
		"description": "test-backend-rpc-product 2",
		"advice": "Some advice ",
		"changelog": 'jedit_5.3.0-2 stable; urgency=low\n\n   * opsi-script.xml for opsi-script 4.11.6.4\n\n-- d.oertel <d.oertel@uib.de> Tue, 11 Oct 2016 15:00:00 + 0100\n\njedit_5.3.0-1 stable; urgency=low\n\n   * update to 5.3\n   * opsi-script.xml for opsi-script 4.11.6.1\n\n-- d.oertel <d.oertel@uib.de> Fri, 24 Jun 2016 15:00:00 + 0100\n\njedit_5.2.0-2 stable; urgency=low\n\n   * script changes for win10\n\n-- detlef oertel <d.oertel@uib.de>  Tue, 30 June 2015 15:00:00 +0100\n\n\njedit_5.2.0-1 stable; urgency=low\n\n   * update to 5.2 stable\n   * update opsi-winst.xml to opsi-script xml 4.11.5.2\n   * code cleanup\n\n-- detlef oertel <d.oertel@uib.de>  Mon, 18 May 2015 15:00:00 +0100\n\njedit_5.1.0-3 stable; urgency=low\n\n   * check for jre8 fixes #1357\n\n-- bardo wolf <b.wolf@uib.de>  21 Jan 2015\n\njedit_5.1.0-2 stable; urgency=low\n\n   * update opsi-winst.xml to opsi-script xml 4.11.4.4\n\n-- detlef oertel <d.oertel@uib.de>  Thu, 17 Apr 2014 16:01:53 +0200\n\njedit_5.1.0-1 stable; urgency=low\n\n   * update to jedit 5.1\n   * update opsi-winst.xml to opsi-script xml 4.11.4.3\n\n-- detlef oertel <d.oertel@uib.de>  Fri, 17 Jan 2014 16:01:53 +0200\n\njedit_5.0.0-3 stable; urgency=low\n\n   * opsi-winst.xml for version 4.11.3.5\n   * code cleanup\n\n-- detlef oertel <d.oertel@uib.de>  Fri, 15 Feb 2013 16:01:53 +0200\n\njedit_5.0.0-2 stable; urgency=low\n\n   * jedit version with localization support\n\n  -- rupert röder <r.roeder@uib.de>  Tue, 27 Nov 2012 16:01:53 +0200\n\njedit_4.5.2-2 stable; urgency=low\n\n   * opsi-winst.xml for version 4.11.3.2\n\n  -- detlef oertel <d.oertel@uib.de>  Tue, 31 Jul 2012 16:01:53 +0200\n\njedit_4.5.2-1 stable; urgency=low\n\n   * update to version 4.5.2\n   * opsi-winst.xml for version 4.11.3.1\n   * opsi-winst.xml for *ins,*.opsiscript,*opsiinc\n\n  -- detlef oertel <d.oertel@uib.de>  Thu, 12 Jul 2012 16:01:53 +0200\n\njedit_4.5.1-1 stable; urgency=low\n\n   * update to version 4.5.1\n   * property gui_language description:  jedit localisation\n   values: ["auto", "de", "en", "fr"]\n   default: ["en"]\n\n\n  -- bardo wolf <b.wolf@uib.de>   12 Jun 2012\n\njedit_4.5-3 stable; urgency=low\n   * moved changelog to changelog file cause ldap-Backend\n  -- bardo wolf <b.wolf@uib.de>   1 Mar 2012\n\njedit_4.5-2 stable; urgency=low\n\n   * updated opsi-winst mode file (4.11.2.6): ChangeDirectory\n\n  -- detlef oertel <d.oertel@uib.de>  Wed, 13 Feb 2012 16:01:53 +0200\n\njedit_4.5-1 stable; urgency=low\n\n   * update to version 4.5\n   * propery startserver (default=off)\n   * moved changelog to control file\n\n  -- detlef oertel <d.oertel@uib.de>  Wed, 02 Jan 2012 16:01:53 +0200\n\n\njedit_4.4.1-4 stable; urgency=low\n\n   * modify mode file FILE_NAME_GLOB="*.asciidoc"\n\n  -- karsten köpke <k.koepke@uib.de>  Wed, 05 Oct 2011 16:01:53 +0200\n\n\njedit_4.4.1-3 stable; urgency=low\n\n   * updatet opsi-winst mode file (4.11.2.1): profileactions\n\n  -- detlef oertel <d.oertel@uib.de>  Wed, 05 Oct 2011 16:01:53 +0200\n\n\njedit_4.4.1-2 stable; urgency=low\n\n   * updatet opsi-winst mode file (4.11.2.1)\n   * added /SUPPRESSMSGBOXES to setup call and comment out autoit call\n   * version 4.3 removed\n   * test for java 1.6 and 1.7\n\n  -- detlef oertel <d.oertel@uib.de>  Wed, 05 Oct 2011 16:01:53 +0200\n\n\njedit_4.4.1-1 stable; urgency=low\n\n   * updatet opsi-winst mode file\n   * jedit ver 4.4.1\n\n  -- detlef oertel <d.oertel@uib.de>  Mon, 02 Aug 2011 16:01:53 +0200\n\n\njedit_4.3.2-6 stable; urgency=low\n\n   * new asciidoc mode file\n\n  -- Jan Schneider <j.schneider@uib.de>  Fri, 25 Mar 2011 10:13:00 +0100\n\njedit_4.3.2-5 stable; urgency=low\n\n\t* changed: winst.xml changed to opsi-winst.xml\n\t* new: opsi-log.xml\n\t* new: asciidoc.xml\n\n  -- detlef oertel <d.oertel@uib.de>  Mon, 22 Feb 2011 16:01:53 +0200\n\n\njedit_4.3.2-4 stable; urgency=low\n\n\t* (x64) installations go to "%ProgramFilesSysnativeDir%\\" + $ProductId$\n\t* prority set to 0\n\n  -- detlef oertel <d.oertel@uib.de>  Mon, 29 Aug 2010 16:01:53 +0200\n\njedit_4.3.2-3 stable; urgency=low\n\n\t* bugFix in Line 54 LogError Command\n\n -- erol ueluekmen <e.ueluekmen@uib.de>  Fri, 13 Aug 2010 16:01:53 +0200\n\njedit_4.3.2-2 stable; urgency=low\n\n\t* added jar based silent install for nt6 familiy (bug in silent installer)\n\t* requires winst 4.10.8 -> uses %ProgramFiles32Dir%\n\n -- detlef oertel <d.oertel@uib.de>  Wed, 29 Jun 2010 16:01:53 +0200\n\n\njedit_4.3.2-1 stable; urgency=low\n\n\t* initial\n\n -- detlef oertel <d.oertel@uib.de>  Wed, 29 Jun 2010 16:01:53 +0200\n\n\n\n\n\n\n',
		"id": "test-backend-rpc-product-2",
		"productVersion": "5.3.0",
		"packageVersion": "2",
		"type": "LocalbootProduct",
	}
	# Create product 1
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_insertObject", "params": [product1]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# Create product 2
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_insertObject", "params": [product2]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res

	# product 1 should be created
	rpc = {"jsonrpc": "2.0", "id": 1, "method": "product_getObjects", "params": [[], {"name": product1["name"]}]}
	res = test_client.post("/rpc", json=rpc).json()
	assert "error" not in res
	print(res)
	product = res["result"][0]
	for attr, val in product1.items():
		assert val == product[attr]
