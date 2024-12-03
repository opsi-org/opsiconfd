from pathlib import Path
from unittest.mock import patch

from opsicommon.messagebus.message import (
	ChannelSubscriptionEventMessage,
	FileChunkMessage,
	FileDownloadRequestMessage,
	FileDownloadResponseMessage,
)

from opsiconfd.config import get_configserver_id
from opsiconfd.messagebus import get_user_id_for_user

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
		assert isinstance(message, FileDownloadResponseMessage)
		for _ in range(5):
			message = next(reader.get_messagbus_messages())
			assert isinstance(message, FileChunkMessage)
			print(message.number, len(message.data), message.last)
