# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
backup
"""

from opsiconfd.backend import get_private_backend

OBJECT_CLASSES = (
	"Host",
	"Config",
	"Product",
	"ProductProperty",
	"ProductDependency",
	"ProductOnDepot",
	"ProductOnClient",
	"ProductPropertyState",
	"Group",
	"ObjectToGroup",
	"AuditSoftware",
	"AuditSoftwareOnClient",
	"AuditHardware",
	"AuditHardwareOnHost",
	"LicenseContract",
	"SoftwareLicense",
	"LicensePool",
	"AuditSoftwareToLicensePool",
	"SoftwareLicenseToLicensePool",
	"LicenseOnClient",
)


def create_backup() -> dict:
	backend = get_private_backend()
	data = {}
	for obj_class in OBJECT_CLASSES:  # pylint: disable=loop-global-usage
		method = getattr(backend, f"{obj_class[0].lower()}{obj_class[1:]}_getObjects")
		data[obj_class] = [o.to_hash() for o in method()]
	return data
