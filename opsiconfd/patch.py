# -*- coding: utf-8 -*-

# This file is part of opsi.
# Copyright (C) 2020 uib GmbH <info@uib.de>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
:copyright: uib GmbH <info@uib.de>
:license: GNU Affero General Public License version 3
"""

import inspect
from hashlib import sha512

from websockets import protocol
from websockets.protocol import State
from websockets.framing import Frame
from websockets.exceptions import InvalidState

from .logging import logger

def assert_function_unchanged(function_to_patch: callable, function_hash: str):
	source = inspect.getsource(function_to_patch)
	source_hash = sha512(source.encode("utf-8")).hexdigest()
	if source_hash != function_hash:
		raise ValueError(f"Function to patch '{function_to_patch}' has changed, expected '{function_hash}', got '{source_hash}'")

def patch_websockets_protocol():
	# Assert that functions to patch are unchanged
	assert_function_unchanged(protocol.WebSocketCommonProtocol.read_frame, "464d14376d9fdcb5cf9865350948d5633fea6afa1cbda162d90d23f8bbd8b3f8dfdcdd1142c832a5fa5e45b5855527d68208d1d79a3f380fb8e1670878a309fb")
	assert_function_unchanged(protocol.WebSocketCommonProtocol.write_frame, "7b743bb1696651d7e6a871c14dca3066ca038054bc943e1a67ce53d461e2da8ff61cd2dba1ef95d23c0f23d77c3dea0ebc14dc96d47b9b0687fad44d80fd66ff")
	
	async def read_frame(self, max_size: int) -> Frame:
		"""
		Read a single frame from the connection.

		"""
		frame = await Frame.read(
			self.reader.readexactly,
			mask=not self.is_client,
			max_size=max_size,
			extensions=self.extensions,
		)
		logger.trace("%s < %r", self.side, frame) # patch: changed debug() to trace()
		return frame
	protocol.WebSocketCommonProtocol.read_frame = read_frame

	async def write_frame(
		self, fin: bool, opcode: int, data: bytes, *, _expected_state: int = State.OPEN
	) -> None:
		# Defensive assertion for protocol compliance.
		if self.state is not _expected_state:  # pragma: no cover
			raise InvalidState(
				f"Cannot write to a WebSocket in the {self.state.name} state"
			)

		frame = Frame(fin, opcode, data)
		logger.trace("%s > %r", self.side, frame) # patch: changed debug() to trace()
		frame.write(
			self.transport.write, mask=self.is_client, extensions=self.extensions
		)

		try:
			# drain() cannot be called concurrently by multiple coroutines:
			# http://bugs.python.org/issue29930. Remove this lock when no
			# version of Python where this bugs exists is supported anymore.
			async with self._drain_lock: # pylint: disable=protected-access
				# Handle flow control automatically.
				await self.writer.drain()
		except ConnectionError:
			# Terminate the connection if the socket died.
			self.fail_connection()
			# Wait until the connection is closed to raise ConnectionClosed
			# with the correct code and reason.
			await self.ensure_open()
	protocol.WebSocketCommonProtocol.write_frame = write_frame

def apply_patches():
	patch_websockets_protocol()
