from unittest.mock import patch, MagicMock
import pytest
from opsiconfd.check.grafana import GrafanaHealth
from opsiconfd.check.common import CheckStatus

# filepath: /workspace/tests/check/test_grafana_check.py



@pytest.mark.parametrize(
	"mock_status_code, mock_json, expected_status, expected_message",
	[
		(
			200,
			{"database": "ok", "version": "12.0.1"},
			CheckStatus.OK,
			"Grafana server is accessible.",
		),
		(
			500,
			{},
			CheckStatus.ERROR,
			"Cannot connect to grafana server, status code: 500",
		),
		(
			200,
			{"database": "error", "version": "12.0.1"},
			CheckStatus.ERROR,
			"Grafana database is not OK.",
		),
		(
			200,
			{"database": "ok", "version": "11.2.0"},
			CheckStatus.WARNING,
			"Grafana version is too old. Version: 11.2.0",
		),
		(
			404,
			{},
			CheckStatus.ERROR,
			"Cannot connect to grafana server, status code: 404",
		),
		(
			200,
			{"database": "ok"},
			CheckStatus.WARNING,
			"Grafana version information is missing.",
		),
		(
			200,
			{},
			CheckStatus.ERROR,
			"Grafana database is not OK.",
		),
	],
)
def test_grafana_health_check(
	mock_status_code: int, mock_json: dict, expected_status: CheckStatus, expected_message: str
) -> None:
	"""
	Test the GrafanaHealth check with various mocked API responses.

	Args:
		mock_status_code (int): The HTTP status code to mock.
		mock_json (dict): The JSON response to mock.
		expected_status (CheckStatus): The expected check status.
		expected_message (str): The expected check message.
	"""
	with patch("opsiconfd.check.grafana.get_requests_session") as mock_get_session:
		mock_session = MagicMock()
		mock_response = MagicMock()
		mock_response.status_code = mock_status_code
		mock_response.json.return_value = mock_json
		mock_session.get.return_value = mock_response
		mock_get_session.return_value = mock_session

		check = GrafanaHealth()
		result = check._check()

		assert result.check_status == expected_status
		assert result.message == expected_message