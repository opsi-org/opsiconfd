# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
backend.rpc
"""

from __future__ import annotations

import re
import socket  # Needed for backends/dhcpd.conf # pylint: disable=unused-import
from asyncio import iscoroutinefunction
from dataclasses import asdict, dataclass
from functools import wraps
from inspect import getfullargspec, signature
from pathlib import Path
from textwrap import dedent
from typing import Any, Callable

from starlette.concurrency import run_in_threadpool

from .cache import rpc_cache_clear, rpc_cache_load, rpc_cache_store

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
For string attributes, "*" can be used as a wildcard.
"""


@dataclass(slots=True)
class MethodInterface:  # pylint: disable=too-many-instance-attributes
	name: str
	params: list[str]
	args: list[str]
	varargs: str | None
	keywords: str | None
	defaults: tuple[Any, ...] | None
	deprecated: bool
	drop_version: str | None
	alternative_method: str | None
	doc: str | None
	annotations: dict[str, str]

	def as_dict(self) -> dict[str, Any]:
		return asdict(self)


def get_method_interface(  # pylint: disable=too-many-locals
	func: Callable, deprecated: bool = False, drop_version: str | None = None, alternative_method: str | None = None
) -> MethodInterface:
	spec = getfullargspec(func)
	sig = signature(func)
	args = spec.args
	defaults = spec.defaults
	params = [arg for arg in args if arg != "self"]
	annotations = {}
	for param in params:
		str_param = str(sig.parameters[param])
		if ": " in str_param:
			annotations[param] = str_param.split(": ", 1)[1].split(" = ", 1)[0]

	if defaults is not None:
		offset = len(params) - len(defaults)
		for i in range(len(defaults)):
			index = offset + i
			params[index] = f"*{params[index]}"

	for index, element in enumerate((spec.varargs, spec.varkw), start=1):
		if element:
			stars = "*" * index
			params.extend([f"{stars}{arg}" for arg in (element if isinstance(element, list) else [element])])

	doc = func.__doc__
	if doc:
		doc = dedent(doc).lstrip() or None

	if drop_version:
		deprecated = True

	return MethodInterface(
		name=func.__name__,
		params=params,
		args=args,
		varargs=spec.varargs,
		keywords=spec.varkw,
		defaults=defaults,
		deprecated=deprecated,
		drop_version=drop_version,
		alternative_method=alternative_method,
		doc=doc,
		annotations=annotations,
	)


def rpc_method(
	func: Callable | None = None,
	/,
	*,
	check_acl: bool | str = True,
	deprecated: bool = False,
	drop_version: str | None = None,
	alternative_method: str | None = None,
	use_cache: str | None = None,
	clear_cache: str | None = None,
) -> Callable:
	def decorator(func: Callable) -> Callable:

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

		check_name = None
		if check_acl:
			check_name = check_acl if isinstance(check_acl, str) else func.__name__

		@wraps(func)
		def wrapper(*args: Any, **kwargs: Any) -> Any:
			if check_name:
				args[0]._get_ace(check_name)  # pylint: disable=protected-access
			if clear_cache:
				rpc_cache_clear(clear_cache)
			if use_cache:
				result = rpc_cache_load(use_cache, *args[1:], **kwargs)
				if result is not None:
					return result
			result = func(*args, **kwargs)
			if use_cache:
				rpc_cache_store(use_cache, result, *args[1:], **kwargs)
			return result

		@wraps(func)
		async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
			if check_name:
				args[0]._get_ace(check_name)  # pylint: disable=protected-access
			if clear_cache:
				await run_in_threadpool(rpc_cache_clear, clear_cache)
			if use_cache:
				result = await run_in_threadpool(rpc_cache_load, use_cache, *args[1:], **kwargs)
				if result is not None:
					return result
			result = await func(*args, **kwargs)
			if use_cache:
				await run_in_threadpool(rpc_cache_store, use_cache, result, *args[1:], **kwargs)
			return result

		if iscoroutinefunction(func):
			wrapper = async_wrapper

		setattr(
			wrapper,
			"rpc_interface",
			get_method_interface(func, deprecated=deprecated, drop_version=drop_version, alternative_method=alternative_method),
		)
		return wrapper

	if func is None:
		# Called as @rpc_method() with parens
		return decorator

	# Called as @rpc_method without parens
	return decorator(func)


def backend_event(event: str) -> Callable:
	if event != "shutdown":
		raise ValueError(f"Invalid event: {event}")

	def decorator(func: Callable) -> Callable:
		setattr(func, f"backend_event_{event}", True)
		return func

	return decorator


def read_backend_config_file(config_file: Path, add_enabled_option: bool = True) -> dict[str, Any]:
	if add_enabled_option:
		config_start_regex = re.compile(r"^\s*config\s*=\s*{")
		config_regex = re.compile(r'^(\s*)"([^"]+)"\s*:.*$')
		lines = config_file.read_text(encoding="utf-8").split("\n")
		add_idx = -1
		indent = "    "
		for idx, line in enumerate(lines):
			if config_start_regex.search(line):
				add_idx = idx + 1
				continue
			match = config_regex.search(line)
			if match:
				indent = match.group(1)
				if match.group(2) == "enabled":
					add_idx = -1
					break
		if add_idx >= 0:
			lines.insert(add_idx, f'{indent}"enabled": True,')
			config_file.write_text("\n".join(lines), encoding="utf-8")

	loc: dict[str, Any] = {}
	exec(compile(config_file.read_bytes(), "<string>", "exec"), None, loc)  # pylint: disable=exec-used
	return loc.get("config", {})
