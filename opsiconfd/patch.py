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

from websockets import protocol
from websockets.protocol import State
from websockets.framing import Frame
from websockets.exceptions import InvalidState

from .logging import logger

def patch_websockets_protocol():
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
		frame.write(self.writer.write, mask=self.is_client, extensions=self.extensions)

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
