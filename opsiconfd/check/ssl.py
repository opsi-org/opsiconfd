# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2023 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0
"""
health check
"""
from __future__ import annotations

from opsiconfd.check.common import CheckResult, CheckStatus, PartialCheckResult, exc_to_result
from opsiconfd.config import config, opsi_config
from opsiconfd.ssl import (
	FILETYPE_PEM,
	X509StoreContextError,
	check_intermediate_ca,
	dump_publickey,
	get_ca_subject,
	get_not_before_and_not_after,
	get_server_cn,
	load_ca_cert,
	load_ca_key,
	load_local_server_cert,
	load_local_server_key,
	opsi_ca_is_self_signed,
	subject_to_dict,
	validate_cert,
)


def check_ssl() -> CheckResult:
	"""
	## SSL
	Checks the state of the opsi CA and the server certificate.
	"""
	server_role = opsi_config.get("host", "server-role")
	result = CheckResult(
		check_id="ssl",
		check_name="SSL",
		check_description="Checks the state of the opsi CA and the server certificate.",
		message="No SSL issues found.",
	)

	with exc_to_result(result):
		# opsi_ca_cert
		partial_result = PartialCheckResult(
			check_id="ssl:opsi_ca_cert",
			check_name="opsi CA certificate",
			check_status=CheckStatus.OK,
			message="The opsi CA certificate is OK.",
		)
		try:
			ca_cert = load_ca_cert()
			not_after_days = get_not_before_and_not_after(ca_cert)[3] or 0
			if not_after_days <= 0:
				partial_result.check_status = CheckStatus.ERROR
				partial_result.message = "The opsi CA certificate is expired."
			else:
				partial_result.message = f"The opsi CA certificate is OK and will expire in {not_after_days} days."
				if not_after_days <= config.ssl_ca_cert_renew_days:
					partial_result.message = f"The opsi CA certificate is OK but will expire in {not_after_days} days."
					partial_result.check_status = CheckStatus.WARNING
				else:
					ca_subject = get_ca_subject()
					current_ca_subject = subject_to_dict(load_ca_cert().get_subject())
					if ca_subject != current_ca_subject:
						partial_result.message = f"The subject of the CA has changed from {current_ca_subject!r} to {ca_subject!r}."
						partial_result.check_status = CheckStatus.WARNING
		except Exception as err:  # pylint: disable=broad-except
			partial_result.check_status = CheckStatus.ERROR
			partial_result.message = f"A problem was found with the opsi CA certificate: {err}."
			ca_cert = None

		result.add_partial_result(partial_result)

		if server_role == "configserver":
			# intermediate_ca
			partial_result = PartialCheckResult(
				check_id="ssl:intermediate_ca",
				check_name="opsi CA as intermediate CA",
				check_status=CheckStatus.OK,
				message="The opsi CA is not a intermediate CA",
			)
			if ca_cert and not opsi_ca_is_self_signed():
				partial_result.message = "The opsi CA is a functional intermediate CA"
				try:
					check_intermediate_ca(ca_cert)
				except Exception as err:  # pylint: disable=broad-except
					partial_result.check_status = CheckStatus.ERROR
					partial_result.message = f"The opsi CA is an intermediate CA and a problem has been found: {err}"

			result.add_partial_result(partial_result)

			# opsi_ca_key
			partial_result = PartialCheckResult(
				check_id="ssl:opsi_ca_key",
				check_name="opsi CA key",
				check_status=CheckStatus.OK,
				message="The opsi CA key is OK.",
			)
			try:
				load_ca_key()
			except Exception as err:  # pylint: disable=broad-except
				partial_result.check_status = CheckStatus.ERROR
				partial_result.message = f"A problem was found with the opsi CA key: {err}."

			result.add_partial_result(partial_result)

		# server_cert
		partial_result = PartialCheckResult(
			check_id="ssl:server_cert",
			check_name="Server certificate",
			check_status=CheckStatus.OK,
			message="The server certificate is OK.",
		)
		try:
			srv_crt = load_local_server_cert()
			not_after_days = get_not_before_and_not_after(srv_crt)[3] or 0
			if not_after_days <= 0:
				partial_result.check_status = CheckStatus.ERROR
				partial_result.message = "The server certificate is expired."
			else:
				partial_result.message = f"The server certificate is OK and will expire in {not_after_days} days."
				if not_after_days <= config.ssl_server_cert_renew_days:
					partial_result.message = f"The server certificate is OK but will expire in {not_after_days} days."
					partial_result.check_status = CheckStatus.WARNING
		except Exception as err:  # pylint: disable=broad-except
			partial_result.check_status = CheckStatus.ERROR
			partial_result.message = f"A problem was found with the server certificate: {err}."
			ca_cert = None

		result.add_partial_result(partial_result)

		# server_key
		partial_result = PartialCheckResult(
			check_id="ssl:server_key",
			check_name="server key",
			check_status=CheckStatus.OK,
			message="The server key is OK.",
		)
		try:
			srv_key = load_local_server_key()
			if dump_publickey(FILETYPE_PEM, srv_key) != dump_publickey(FILETYPE_PEM, srv_crt.get_pubkey()):
				partial_result.check_status = CheckStatus.ERROR
				partial_result.message = "Server cert does not match server key."
			else:
				server_cn = get_server_cn()
				if server_cn != srv_crt.get_subject().CN:
					partial_result.check_status = CheckStatus.ERROR
					partial_result.message = f"Server CN has changed from '{server_cn}' to '{srv_crt.get_subject().CN}'"
				elif ca_cert:
					try:
						validate_cert(srv_crt, ca_cert)
					except X509StoreContextError:
						partial_result.check_status = CheckStatus.ERROR
						partial_result.message = "Failed to verify server cert with opsi CA."
		except Exception as err:  # pylint: disable=broad-except
			partial_result.check_status = CheckStatus.ERROR
			partial_result.message = f"A problem was found with the server key: {err}."

		result.add_partial_result(partial_result)

	if result.check_status != CheckStatus.OK:
		result.message = "Some SSL issues where found."

	return result
