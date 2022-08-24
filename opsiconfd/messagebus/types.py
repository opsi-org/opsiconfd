# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
opsiconfd.messagebus.types
"""

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Tuple, Union
from uuid import uuid4

from msgpack import dumps as msgpack_dumps  # type: ignore[import]
from msgpack import loads as msgpack_loads  # type: ignore[import]
from orjson import dumps as json_dumps  # pylint: disable=no-name-in-module
from orjson import loads as json_loads  # pylint: disable=no-name-in-module


class MessageTypes(str, Enum):
	JSONRPC_REQUEST = "jsonrpc_request"
	JSONRPC_RESPONSE = "jsonrpc_response"
	FILE_UPLOAD = "file_upload"
	FILE_UPLOAD_RESULT = "file_upload_result"
	FILE_CHUNK = "file_chunk"


@dataclass(slots=True, kw_only=True)
class Error:
	message: str
	code: Union[int, None] = None
	details: Union[str, None] = None


@dataclass(slots=True, kw_only=True)
class Message:
	type: str  # Custom message types are allowed
	sender: str
	channel: str
	id: str = field(default_factory=lambda: str(uuid4()))  # pylint: disable=invalid-name
	created: int = field(default_factory=lambda: int(time.time() * 1000))
	expires: int = 0

	@classmethod
	def from_dict(cls, data: Dict[str, Any]) -> "Message":
		_cls = cls
		if _cls is Message:
			_type = data.get("type")
			if _type:
				if isinstance(_type, MessageTypes):
					_type = _type.value
				_cls = MESSAGE_TYPE_TO_CLASS.get(_type, Message)
		return _cls(**data)

	def to_dict(self) -> Dict[str, Any]:
		return asdict(self)

	@classmethod
	def from_json(cls, data: Union[bytes, str]) -> "Message":
		return cls.from_dict(json_loads(data))

	def to_json(self) -> bytes:
		return json_dumps(self.to_dict())

	@classmethod
	def from_msgpack(cls, data: bytes) -> "Message":
		return cls.from_dict(msgpack_loads(data))

	def to_msgpack(self) -> bytes:
		return msgpack_dumps(self.to_dict())


@dataclass(slots=True, kw_only=True)
class JSONRPCRequestMessage(Message):

	type: str = MessageTypes.JSONRPC_REQUEST.value
	rpc_id: str = field(default_factory=lambda: str(uuid4()))
	method: str
	params: Tuple[Any, ...] = tuple()


@dataclass(slots=True, kw_only=True)
class JSONRPCResponseMessage(Message):
	type: str = MessageTypes.JSONRPC_RESPONSE.value
	rpc_id: str
	error: Any = None
	result: Any = None


@dataclass(slots=True, kw_only=True)
class FileUploadMessage(Message):
	type: str = MessageTypes.FILE_UPLOAD.value
	file_id: str
	content_type: str
	name: Union[str, None] = None
	size: Union[int, None] = None


@dataclass(slots=True, kw_only=True)
class FileUploadResultMessage(Message):
	type: str = MessageTypes.FILE_UPLOAD_RESULT.value
	file_id: str
	error: Error
	path: Union[str, None] = None


@dataclass(slots=True, kw_only=True)
class FileChunk(Message):
	type: str = MessageTypes.FILE_CHUNK.value
	file_id: str
	number: int
	last: bool = False
	data: bytes


MESSAGE_TYPE_TO_CLASS = {
	MessageTypes.JSONRPC_REQUEST.value: JSONRPCRequestMessage,
	MessageTypes.JSONRPC_RESPONSE.value: JSONRPCResponseMessage,
	MessageTypes.FILE_UPLOAD.value: FileUploadMessage,
	MessageTypes.FILE_UPLOAD_RESULT.value: FileUploadResultMessage,
	MessageTypes.FILE_CHUNK.value: FileChunk,
}
