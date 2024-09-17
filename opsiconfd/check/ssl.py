# # -*- coding: utf-8 -*-

# # opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# # Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# # All rights reserved.
# # License: AGPL-3.0

# """
# health check
# """

# from __future__ import annotations

# from cryptography import x509
# from cryptography.hazmat.primitives import serialization
# from cryptography.x509 import verification  # type: ignore[attr-defined]

# from opsiconfd.check.common import Check, CheckResult, CheckStatus, CheckResult, exc_to_result
# from opsiconfd.config import config, get_server_role
# from opsiconfd.ssl import (
# 	check_intermediate_ca,
# 	get_ca_subject,
# 	get_not_before_and_not_after,
# 	get_server_cn,
# 	load_local_server_cert,
# 	load_local_server_key,
# 	load_opsi_ca_cert,
# 	load_opsi_ca_key,
# 	opsi_ca_is_self_signed,
# 	validate_cert,
# 	x509_name_to_dict,
# )


# """
# health check
# """

from __future__ import annotations

from dataclasses import dataclass

from opsiconfd.check.common import Check, CheckResult, CheckStatus, check_manager, exc_to_result
from opsiconfd.config import config
from opsiconfd.ssl import (
	check_intermediate_ca,
	get_ca_subject,
	get_not_before_and_not_after,
	load_local_server_cert,
	load_opsi_ca_cert,
	load_opsi_ca_key,
	opsi_ca_is_self_signed,
	x509_name_to_dict,
)


@dataclass()
class OpsiCaCert(Check):
	id: str = "ssl:opsi_ca_cert"
	name: str = "opsi CA certificate"
	description: str = "Checks the state of the opsi CA certificate."
	documentation: str = """

## opsi CA certificate
Checks the state of the opsi CA certificate

"""
	partial_check: bool = True

	def check(self) -> CheckResult:
		print("ssl:opsi_ca_cert")
		result = CheckResult(
			check=self,
			message="The opsi CA certificate is OK.",
			check_status=CheckStatus.OK,
		)
		with exc_to_result(result):
			try:
				ca_cert = load_opsi_ca_cert()
				not_after_days = get_not_before_and_not_after(ca_cert)[3] or 0
				if not_after_days <= 0:
					result.check_status = CheckStatus.ERROR
					result.message = "The opsi CA certificate is expired."
				else:
					result.message = f"The opsi CA certificate is OK and will expire in {not_after_days} days."
					if not_after_days <= config.ssl_ca_cert_renew_days - 1:
						result.message = f"The opsi CA certificate is OK but will expire in {not_after_days} days."
						result.check_status = CheckStatus.WARNING
					else:
						ca_subject = get_ca_subject()
						current_ca_subject = x509_name_to_dict(load_opsi_ca_cert().subject)
						if ca_subject != current_ca_subject:
							result.message = f"The subject of the CA has changed from {current_ca_subject!r} to {ca_subject!r}."
							result.check_status = CheckStatus.WARNING
			except Exception as err:
				result.check_status = CheckStatus.ERROR
				result.message = f"A problem was found with the opsi CA certificate: {err}."
				ca_cert = None

		return result


@dataclass()
class IntermediateCACheck(Check):
	id: str = "ssl:intermediate_ca"
	name: str = "opsi CA as intermediate CA"
	description: str = "Checks if the opsi CA is an intermediate CA."
	documentation: str = """
## Intermediate CA
Checks if the opsi CA is an intermediate CA.
"""
	depot_check: bool = False
	partial_check: bool = True

	def check(self) -> CheckResult:
		print("ssl intermediate ca")
		result = CheckResult(
			check=self,
			check_status=CheckStatus.OK,
			message="The opsi CA is not a intermediate CA.",
		)

		ca_cert = load_opsi_ca_cert()
		if ca_cert and not opsi_ca_is_self_signed():
			result.message = "The opsi CA is a functional intermediate CA."
			try:
				check_intermediate_ca(ca_cert)
			except Exception as err:
				result.check_status = CheckStatus.ERROR
				result.message = f"The opsi CA is an intermediate CA and a problem has been found: {err}"

		return result


@dataclass()
class OpsiCaKeyCheck(Check):
	id: str = "ssl:opsi_ca_key"
	name: str = "opsi CA key"
	description: str = "Checks the state of the opsi CA key."
	documentation: str = """
## opsi CA key

Checks the state of the opsi CA key.
"""
	depot_check: bool = False
	partial_check: bool = True

	def check(self) -> CheckResult:
		print("ssl:opsi_ca_key")
		result = CheckResult(
			check=self,
			check_status=CheckStatus.OK,
			message="The opsi CA key is OK.",
		)
		try:
			load_opsi_ca_key()
		except Exception as err:
			result.check_status = CheckStatus.ERROR
			result.message = f"A problem was found with the opsi CA key: {err}."

		return result


@dataclass()
class ServerCertCheck(Check):
	id: str = "ssl:server_cert"
	name: str = "Server certificate"
	description: str = "Checks the state of the server certificate."
	documentation: str = """
## Server certificate
Checks the state of the server certificate.
"""
	depot_check: bool = False
	partial_check: bool = True

	def check(self) -> CheckResult:
		# print("ssl:server_cert")
		result = CheckResult(
			check=self,
			check_status=CheckStatus.OK,
			message="The server certificate is OK.",
		)
		try:
			srv_crt = load_local_server_cert()
			not_after_days = get_not_before_and_not_after(srv_crt)[3] or 0
			if not_after_days <= 0:
				result.check_status = CheckStatus.ERROR
				result.message = "The server certificate is expired."
			else:
				result.message = f"The server certificate is OK and will expire in {not_after_days} days."
				if not_after_days <= config.ssl_server_cert_renew_days:
					result.message = f"The server certificate is OK but will expire in {not_after_days} days."
					result.check_status = CheckStatus.WARNING
		except Exception as err:
			result.check_status = CheckStatus.ERROR
			result.message = f"A problem was found with the server certificate: {err}."

		return result


@dataclass()
class SSLCheck(Check):
	id: str = "ssl"
	name: str = "SSL"
	description: str = "Checks the state of the opsi CA and the server certificate."
	documentation: str = """
## SSL
Checks the state of the opsi CA and the server certificate.
"""
	# cache: bool = False

	def check(self) -> CheckResult:
		result = CheckResult(
			check=self,
			message="No SSL issues found.",
			check_status=CheckStatus.OK,
		)

		# if result.check_status != CheckStatus.OK:
		# 	result.message = "Some SSL issues where found."

		return result

	# result.message = "Some SSL issues where found."


ssl_check = SSLCheck(partial_checks=[OpsiCaCert(), IntermediateCACheck(), OpsiCaKeyCheck(), ServerCertCheck()])
# print("ssl_check:", ssl_check)
check_manager.register(ssl_check)


# @dataclass()
# class SSLCheck(Check):
# 	id: str = "ssl"
# 	name: str = "SSL"
# 	description: str = "Checks the state of the opsi CA and the server certificate."
# 	documentation: str = """
# ## SSL
# Checks the state of the opsi CA and the server certificate.
# """

# 	def check(self) -> CheckResult:
# 		result = CheckResult(
# 			check=self,
# 			message="No SSL issues found.",
# 			check_status=CheckStatus.OK,
# 		)
# 		server_role = get_server_role()

# 		with exc_to_result(result):
# 			# opsi_ca_cert
# 			partial_result = CheckResult(
# 				check_id="ssl:opsi_ca_cert",
# 				check_name="opsi CA certificate",
# 				check_status=CheckStatus.OK,
# 				message="The opsi CA certificate is OK.",
# 			)
# 			try:
# 				ca_cert = load_opsi_ca_cert()
# 				not_after_days = get_not_before_and_not_after(ca_cert)[3] or 0
# 				if not_after_days <= 0:
# 					partial_result.check_status = CheckStatus.ERROR
# 					partial_result.message = "The opsi CA certificate is expired."
# 				else:
# 					partial_result.message = f"The opsi CA certificate is OK and will expire in {not_after_days} days."
# 					if not_after_days <= config.ssl_ca_cert_renew_days - 1:
# 						partial_result.message = f"The opsi CA certificate is OK but will expire in {not_after_days} days."
# 						partial_result.check_status = CheckStatus.WARNING
# 					else:
# 						ca_subject = get_ca_subject()
# 						current_ca_subject = x509_name_to_dict(load_opsi_ca_cert().subject)
# 						if ca_subject != current_ca_subject:
# 							partial_result.message = f"The subject of the CA has changed from {current_ca_subject!r} to {ca_subject!r}."
# 							partial_result.check_status = CheckStatus.WARNING
# 			except Exception as err:
# 				partial_result.check_status = CheckStatus.ERROR
# 				partial_result.message = f"A problem was found with the opsi CA certificate: {err}."
# 				ca_cert = None

# 			result.add_partial_result(partial_result)

# 			if server_role == "configserver":
# 				# intermediate_ca
# 				partial_result = CheckResult(
# 					check_id="ssl:intermediate_ca",
# 					check_name="opsi CA as intermediate CA",
# 					check_status=CheckStatus.OK,
# 					message="The opsi CA is not a intermediate CA.",
# 				)
# 				if ca_cert and not opsi_ca_is_self_signed():
# 					partial_result.message = "The opsi CA is a functional intermediate CA."
# 					try:
# 						check_intermediate_ca(ca_cert)
# 					except Exception as err:
# 						partial_result.check_status = CheckStatus.ERROR
# 						partial_result.message = f"The opsi CA is an intermediate CA and a problem has been found: {err}"

# 				result.add_partial_result(partial_result)

# 				# opsi_ca_key
# 				partial_result = CheckResult(
# 					check_id="ssl:opsi_ca_key",
# 					check_name="opsi CA key",
# 					check_status=CheckStatus.OK,
# 					message="The opsi CA key is OK.",
# 				)
# 				try:
# 					load_opsi_ca_key()
# 				except Exception as err:
# 					partial_result.check_status = CheckStatus.ERROR
# 					partial_result.message = f"A problem was found with the opsi CA key: {err}."

# 				result.add_partial_result(partial_result)

# 			# server_cert
# 			partial_result = CheckResult(
# 				check_id="ssl:server_cert",
# 				check_name="Server certificate",
# 				check_status=CheckStatus.OK,
# 				message="The server certificate is OK.",
# 			)
# 			try:
# 				srv_crt = load_local_server_cert()
# 				not_after_days = get_not_before_and_not_after(srv_crt)[3] or 0
# 				if not_after_days <= 0:
# 					partial_result.check_status = CheckStatus.ERROR
# 					partial_result.message = "The server certificate is expired."
# 				else:
# 					partial_result.message = f"The server certificate is OK and will expire in {not_after_days} days."
# 					if not_after_days <= config.ssl_server_cert_renew_days:
# 					result.message = "Some SSL issues where found."	partial_result.message = f"The server certificate is OK but will expire in {not_after_days} days."
# 						partial_result.check_status = CheckStatus.WARNING
# 			except Exception as err:
# 				partial_result.check_status = CheckStatus.ERROR
# 				partial_result.message = f"A problem was found with the server certificate: {err}."
# 				ca_cert = None

# 			result.add_partial_result(partial_result)

# 			# server_key
# 			partial_result = CheckResult(
# 				check_id="ssl:server_key",
# 				check_name="server key",
# 				check_status=CheckStatus.OK,
# 				message="The server key is OK.",
# 			)
# 			try:
# 				srv_key = load_local_server_key()
# 				if srv_key.public_key().public_bytes(
# 					encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1
# 				) != srv_crt.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1):
# 					partial_result.check_status = CheckStatus.ERROR
# 					partial_result.message = "Server cert does not match server key."
# 				else:
# 					server_cn = get_server_cn()
# 					cert_cn = srv_crt.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
# 					if not isinstance(cert_cn, str):
# 						cert_cn = cert_cn.decode("utf-8")
# 					if server_cn != cert_cn:
# 						partial_result.check_status = CheckStatus.ERROR
# 						partial_result.message = f"Server CN has changed from '{server_cn}' to '{cert_cn}'"
# 					elif ca_cert:
# 						try:
# 							validate_cert(srv_crt, ca_cert)
# 						except verification.VerificationError:
# 							partial_result.check_status = CheckStatus.ERROR
# 							partial_result.message = "Failed to verify server cert with opsi CA."
# 			except Exception as err:
# 				partial_result.check_status = CheckStatus.ERROR
# 				partial_result.message = f"A problem was found with the server key: {err}."

# 			result.add_partial_result(partial_result)

# 		if result.check_status != CheckStatus.OK:
# 			result.message = "Some SSL issues where found."

# 		return result


# ssl_check = SSLCheck()
# check_manager.register(ssl_check)

# # docs = """
# # ## SSL
# # Checks the state of the opsi CA and the server certificate.
# # """

# # ssl_check = SSLCheck(
# # 	id="ssl",
# # 	name="SSL",
# # 	description="Checks the state of the opsi CA and the server certificate.",
# # 	documentation=docs,
# # 	status=CheckStatus.OK,
# # 	message="No SSL issues found.",
# # 	depot_check=True,
# # )
