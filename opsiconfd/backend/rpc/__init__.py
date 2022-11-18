# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
backend.rpc
"""

from __future__ import annotations

from functools import partial
from typing import Callable

DOC_INSERT_OBJECT = """Creates a new object in the backend.
If the object already exists, it will be completely overwritten with the new values.
Attributes that are not passed (or passed with the value 'null') will be set to 'null' in the backend.
"""

DOC_UPDATE_OBJECT = """Updates an object in the backend.
Attributes that are not passed (or passed with the value 'null'), will not be changed in the backend.
If the object does not exist, no change takes place, no object is created.
"""

DOC_CREATE_OBJECTS = """An object or a list of objects can be passed.
Each object will be created in the backend.
Existing objects will be overwritten.
"""
DOC_UPDATE_OBJECTS = """An object or a list of objects can be passed.
Each object will be updated if it exists or created if it does not exist yet.
"""
DOC_GET_OBJECTS = """Returns a list of objects that match the specified filter.
If a list of attributes is specified, only these are read from the backend.
The filter object consists of attribute-value pairs that are ANDed during the search.
If the value is a list, the individual entries are ORed during the search.
For strings, "*" can be used as a wildcard.
"""
DOC_GET_HASHES = """Returns a list of objects as dictionaries that match the specified filter.
If a list of attributes is specified, only these are read from the backend.
The filter object consists of attribute-value pairs that are ANDed during the search.
If the value is a list, the individual entries are ORed during the search.
For strings, "*" can be used as a wildcard.
"""
DOC_GET_IDENTS = """Returns a list of object identifiers that match the specified filter.
Possible returnTypes are: "str" (default), "dict", "list" and "tuple".
The filter object consists of attribute-value pairs that are ANDed during the search.
If the value is a list, the individual entries are ORed during the search.
For strings, "*" can be used as a wildcard.
"""
DOC_DELETE_OBJECTS = """Deletes a list of objects.
Only the attributes identifying the object ('type'/'id'/'ident') are used to select the objects to be deleted.
"""
DOC_DELETE = """Deletes the object identified by the specified parameters.
"""


def rpc_method(func: Callable) -> Callable:
	if not func.__doc__:
		if func.__name__.endswith("_insertObject"):
			func.__doc__ = DOC_INSERT_OBJECT
		elif func.__name__.endswith("_updateObject"):
			func.__doc__ = DOC_UPDATE_OBJECT
		elif func.__name__.endswith("_createObjects"):
			func.__doc__ = DOC_CREATE_OBJECTS
		elif func.__name__.endswith("_updateObjects"):
			func.__doc__ = DOC_UPDATE_OBJECTS
		elif func.__name__.endswith("_getObjects"):
			func.__doc__ = DOC_GET_OBJECTS
		elif func.__name__.endswith("_getHashes"):
			func.__doc__ = DOC_GET_HASHES
		elif func.__name__.endswith("_getIdents"):
			func.__doc__ = DOC_GET_IDENTS
		elif func.__name__.endswith("_deleteObjects"):
			func.__doc__ = DOC_DELETE_OBJECTS
		elif func.__name__.endswith("_delete"):
			func.__doc__ = DOC_DELETE
	setattr(func, "rpc_method", True)
	return func


def deprecated_rpc_method(func: Callable = None, *, alternative_method: str = None) -> Callable:
	if func is None:
		return partial(deprecated, alternative_method=alternative_method)

	setattr(func, "rpc_method", True)
	setattr(func, "deprecated", True)
	setattr(func, "alternative_method", alternative_method)
	return func


deprecated = deprecated_rpc_method
