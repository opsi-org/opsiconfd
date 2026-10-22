# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from opsi.opsi.messagebus import (
	ChannelSubscriptionEventMessage,
	FileChunkMessage,
	FileDownloadInformationMessage,
	FileDownloadRequestMessage,
	FileTransferErrorMessage,
)

from opsiconfd.config import get_configserver_id
from opsiconfd.messagebus import get_user_id_for_user
from opsiconfd.messagebus.file_transfer import check_filetransfer_message

from .utils import (  # noqa: F401
	ADMIN_PASS,
	ADMIN_USER,
	OpsiconfdTestClient,
	WebSocketMessageReader,
	create_client_via_jsonrpc,
	test_client,
)


def test_messagebus_filetransfer(tmp_path: Path, test_client: OpsiconfdTestClient) -> None:  # noqa: F811
	channel = f"service:depot:{get_configserver_id()}:filetransfer"
	test_client.auth = (ADMIN_USER, ADMIN_PASS)
	user_id = get_user_id_for_user(ADMIN_USER)
	(tmp_path / "testfile.txt").write_text("0" * 4000)
	with (
		test_client,
		test_client.websocket_connect("/messagebus/v1") as websocket,
		WebSocketMessageReader(websocket, messagebus_messages=True) as reader,
		patch("opsiconfd.messagebus.file_transfer.FILE_DOWNLOAD_ALLOWED_PATHS", [tmp_path]),
	):
		reader.wait_for_message(count=1)
		message = next(reader.get_messagbus_messages())
		assert isinstance(message, ChannelSubscriptionEventMessage)

		file_download_request = FileDownloadRequestMessage(
			sender=user_id, channel=channel, path=str(tmp_path / "testfile.txt"), chunk_size=1000
		)
		websocket.send_bytes(file_download_request.to_msgpack())
		reader.wait_for_message(count=5)
		message = next(reader.get_messagbus_messages())
		assert isinstance(message, FileDownloadInformationMessage)
		for _ in range(5):
			message = next(reader.get_messagbus_messages())
			assert isinstance(message, FileChunkMessage)
			print(message.number, len(message.data), message.last)


@pytest.mark.parametrize(
	"path, allowed",
	(
		("log/file.log", True),
		("log/sub/../file.log", True),
		("log/../secret.txt", False),
		("log/secret-link.log", False),
		("secret.txt", False),
		("log-other/file.log", False),
	),
)
async def test_check_filetransfer_message_path(tmp_path: Path, path: str, allowed: bool) -> None:
	log_dir = tmp_path / "log"
	(log_dir / "sub").mkdir(parents=True)
	(log_dir / "file.log").write_text("log")
	(tmp_path / "log-other").mkdir()
	(tmp_path / "log-other" / "file.log").write_text("log")
	(tmp_path / "secret.txt").write_text("secret")
	(log_dir / "secret-link.log").symlink_to(tmp_path / "secret.txt")

	sent_messages: list[Any] = []

	async def send_message(message: Any) -> None:
		"""Collect sent messages."""
		sent_messages.append(message)

	message = FileDownloadRequestMessage(sender="test", channel="test", path=str(tmp_path / path))
	with patch("opsiconfd.messagebus.file_transfer.FILE_DOWNLOAD_ALLOWED_PATHS", [log_dir]):
		if allowed:
			await check_filetransfer_message(message, send_message)
			assert not sent_messages
			assert message.path == str((log_dir / "file.log").resolve())
			return

		with pytest.raises(ValueError, match="not in allowed paths"):
			await check_filetransfer_message(message, send_message)
		assert len(sent_messages) == 1
		assert isinstance(sent_messages[0], FileTransferErrorMessage)
