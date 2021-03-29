# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2021 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

import sys
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
		#logger.debug(source)
		raise ValueError(f"Function to patch '{function_to_patch}' has changed, expected '{function_hash}', got '{source_hash}'")

def patch_websockets_protocol():
	if not getattr(sys, 'frozen', False):
		# Assert that functions to patch are unchanged
		assert_function_unchanged(
			protocol.WebSocketCommonProtocol.read_frame,
			"5de6c28d279813fda6499ea980f578c10d7eedef38effb89152d0a93154923891f12f256b63ceb8a9b6611593e777325a593a1e9438f53bf17dd16985632f519"
		)
		assert_function_unchanged(
			protocol.WebSocketCommonProtocol.write_frame,
			"805f88a9201ae53fb09b9c96b6fab1d6b8e3063ff6e3c02362a56e081bf96b1e9a02766662e01c8928fc07c3066215ac383ec45037416b651506a90462214ed5"
		)

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
				await self._drain() # pylint: disable=protected-access
		except ConnectionError:
			# Terminate the connection if the socket died.
			self.fail_connection()
			# Wait until the connection is closed to raise ConnectionClosed
			# with the correct code and reason.
			await self.ensure_open()
	protocol.WebSocketCommonProtocol.write_frame = write_frame

def apply_patches():
	patch_websockets_protocol()
