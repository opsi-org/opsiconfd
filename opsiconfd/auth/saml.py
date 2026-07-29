# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.auth.saml
"""

import re
import xml.dom.minidom
from datetime import UTC, datetime, timedelta
from pathlib import Path
from textwrap import dedent
from typing import Any
from urllib.parse import urlparse
from xml.etree import ElementTree

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateBuilder
from fastapi import Request
from onelogin.saml2.metadata import OneLogin_Saml2_Metadata
from opsi.exception import OpsiServiceAuthenticationError
from opsi.opsi.service.model.object import AuditLogAuthenticationFailureReason
from rich import print as rich_print
from rich.prompt import Prompt

from opsiconfd.config import config, get_configserver_id
from opsiconfd.logging import get_logger
from opsiconfd.ssl import as_pem
from opsiconfd.utils import get_requests_session
from opsiconfd.utils.modules import module_available

logger = get_logger("opsiconfd.saml")


def check_if_saml_available() -> None:
	if not module_available("sso"):
		raise RuntimeError("Single Sign On module not licensed. Please check your OPSI licenses.")
	if "saml" in config.disabled_auth_methods:
		raise OpsiServiceAuthenticationError(
			"SAML authentication is disabled",
			authentication_failure_reason=AuditLogAuthenticationFailureReason.AUTH_MODULE_NOT_AVAILABLE,
		)
	if not config.saml_idp_entity_id:
		raise ValueError("saml-idp-entity-id not set in config")
	if not config.saml_idp_sso_url:
		raise ValueError("saml-idp-sso-url not set in config")
	if not config.saml_idp_x509_cert:
		raise ValueError("saml-idp-x509-cert not set in config")


def get_sp_entity_id() -> str:
	return get_configserver_id()


def get_sp_base_url() -> str:
	return config.external_url


def get_sp_url(path: str | None = None) -> str:
	base_url = get_sp_base_url()
	if not path:
		return base_url
	return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def get_saml_settings(
	login_callback_path: str = "/auth/saml/callback/login", logout_callback_path: str = "/auth/saml/callback/logout"
) -> dict[str, Any]:
	check_if_saml_available()

	settings: dict[str, Any] = {
		"strict": False,
		# If debug is True, xmlsec errors will be printed
		"debug": False,
		"security": {
			"allowRepeatAttributeName": True,
			# Prevent sending RequestedAuthnContext in AuthnRequest to avoid error AADSTS75011
			# See https://learn.microsoft.com/de-de/troubleshoot/entra/entra-id/app-integration/error-code-AADSTS75011-auth-method-mismatch
			"requestedAuthnContext": False,
			# Indicates whether the <samlp:AuthnRequest> messages sent by this SP
			# will be signed. [Metadata of the SP will offer this info]
			"authnRequestsSigned": False,
			# Indicates whether the <samlp:logoutRequest> messages sent by this SP
			# will be signed.
			"logoutRequestSigned": False,
			# Indicates whether the <samlp:logoutResponse> messages sent by this SP
			# will be signed.
			"logoutResponseSigned": False,
			# Indicates a requirement for the <samlp:Response>, <samlp:LogoutRequest>
			# and <samlp:LogoutResponse> elements received by this SP to be signed.
			"wantMessagesSigned": False,
			# Indicates a requirement for the <saml:Assertion> elements received by
			# this SP to be signed. [Metadata of the SP will offer this info]
			# This setting is not needed if document is already being signed.
			"wantAssertionsSigned": False,
		},
		# Identity Provider
		"idp": {
			"entityId": config.saml_idp_entity_id,
			"singleSignOnService": {
				"url": config.saml_idp_sso_url,
				"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
			"x509cert": config.saml_idp_x509_cert,
			# TODO: Support separate certificates for signing and encryption?
			# "x509certMulti": {"signing": [config.saml_idp_x509_cert], "encryption": [config.saml_idp_x509_cert]},
		},
		# Service Provider
		"sp": {
			"entityId": get_sp_entity_id(),
			"NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
			"assertionConsumerService": {
				"url": f"{get_sp_url(login_callback_path)}",
				"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
			},
		},
	}
	if config.saml_idp_slo_url:
		settings["idp"]["singleLogoutService"] = {
			"url": config.saml_idp_slo_url,
			"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		}
		settings["sp"]["singleLogoutService"] = {
			"url": f"{get_sp_url(logout_callback_path)}",
			"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		}

	if config.saml_sp_client_signature or config.saml_encrypted_assertions:
		if not config.saml_sp_x509_cert or not config.saml_sp_private_key:
			raise ValueError("saml-sp-x509-cert and saml-sp-private-key must be set in config")
		settings["sp"]["x509cert"] = config.saml_sp_x509_cert
		settings["sp"]["privateKey"] = config.saml_sp_private_key

	if config.saml_sp_client_signature:
		settings["security"]["authnRequestsSigned"] = True
		settings["security"]["logoutRequestSigned"] = True
		settings["security"]["logoutResponseSigned"] = True
		settings["security"]["wantMessagesSigned"] = True
		settings["security"]["wantAssertionsSigned"] = True

	return settings


async def saml_auth_request_data(request: Request) -> dict[str, Any]:
	assert request.client
	assert request.url
	params: dict[str, Any] = {
		"http_host": request.client.host,
		"server_port": request.url.port,
		"script_name": request.url.path,
		"post_data": {},
		"get_data": {},
	}
	form_data = await request.form()
	if request.query_params:
		params["get_data"].update(request.query_params)
	if "SAMLResponse" in form_data:
		params["post_data"]["SAMLResponse"] = form_data["SAMLResponse"]
	if "RelayState" in form_data:
		params["post_data"]["RelayState"] = form_data["RelayState"]
	return params


def update_config_from_idp_metadata_xml(metadata_xml: str) -> None:
	root = ElementTree.fromstring(metadata_xml)
	search = "{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor"
	entity_descriptor: ElementTree.Element | None
	if root.tag == search:
		entity_descriptor = root
	else:
		entity_descriptor = root.find(f".//{search}")
	if entity_descriptor is None:
		raise ValueError(f"{search} not found in metadata XML")
	idp_entity_id = entity_descriptor.attrib.get("entityID")
	if not idp_entity_id:
		raise ValueError("entityID attribute not found in EntityDescriptor")

	search = "{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor[@use='signing']"
	node = entity_descriptor.find(f".//{search}")
	if node is None:
		raise ValueError(f"{search} not found in metadata XML")
	idp_x509_cert_node = node.find(".//{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
	if idp_x509_cert_node is None or not idp_x509_cert_node.text:
		raise ValueError("X509Certificate not found in KeyDescriptor")
	idp_x509_cert = idp_x509_cert_node.text

	search = "{urn:oasis:names:tc:SAML:2.0:metadata}SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']"
	node = entity_descriptor.find(f".//{search}")
	if node is None:
		raise ValueError(f"{search} not found in metadata XML")
	idp_sso_url = node.attrib.get("Location")
	if not idp_sso_url:
		raise ValueError("Location attribute not found in SingleSignOnService")

	search = "{urn:oasis:names:tc:SAML:2.0:metadata}SingleLogoutService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']"
	node = entity_descriptor.find(f".//{search}")
	idp_slo_url = None
	if node is not None:
		idp_slo_url = node.attrib.get("Location", "")

	config.update_config(
		{
			"saml_idp_entity_id": idp_entity_id,
			"saml_idp_sso_url": idp_sso_url,
			"saml_idp_x509_cert": idp_x509_cert,
			"saml_idp_slo_url": idp_slo_url,
		}
	)


def get_sp_metadata_xml(
	login_callback_path: str = "/auth/saml/callback/login", logout_callback_path: str = "/auth/saml/callback/logout"
) -> str:
	now = datetime.now(tz=UTC)
	valid_until = now + timedelta(days=2)

	saml_settings = get_saml_settings(login_callback_path=login_callback_path, logout_callback_path=logout_callback_path)
	metadata = OneLogin_Saml2_Metadata.builder(
		sp=saml_settings["sp"],
		authnsign=saml_settings["security"]["authnRequestsSigned"],
		wsign=saml_settings["security"]["wantAssertionsSigned"],
		valid_until=valid_until,
	)
	if saml_settings["sp"].get("x509cert"):
		metadata = OneLogin_Saml2_Metadata.add_x509_key_descriptors(
			metadata=metadata,
			cert=saml_settings["sp"]["x509cert"],
			add_encryption=config.saml_encrypted_assertions,
		)
	if isinstance(metadata, bytes):
		metadata = metadata.decode("utf-8")

	# Fix XML formatting
	dom = xml.dom.minidom.parseString(metadata)
	metadata = dom.toprettyxml()
	metadata = re.sub(r"^\s*\n", "", metadata, flags=re.MULTILINE)
	return metadata


def generate_client_certificate() -> None:
	logger.notice("Setting up SAML SP client signature")
	common_name = get_sp_entity_id()
	subject = x509.Name(
		[
			x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
		]
	)
	key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
	builder = CertificateBuilder(
		issuer_name=subject,
		subject_name=subject,
		public_key=key.public_key(),
		serial_number=x509.random_serial_number(),
		not_valid_before=datetime.now(tz=UTC),
		not_valid_after=datetime.now(tz=UTC) + timedelta(days=3000),
	)
	cert = builder.sign(key, hashes.SHA256())
	key_pem = "".join(line.strip() for line in as_pem(key).split("\n") if not line.startswith("-----"))
	cert_pem = "".join(line.strip() for line in as_pem(cert).split("\n") if not line.startswith("-----"))
	config.update_config({"saml_sp_x509_cert": cert_pem, "saml_sp_private_key": key_pem}, on_change="reload")


def setup_saml() -> None:
	if not config.saml_sp_client_signature or (config.saml_sp_x509_cert and config.saml_sp_private_key):
		return

	generate_client_certificate()


def setup_saml_configuration(interactive: bool = True, unattended_configuration: dict[str, str] | None = None) -> None:
	if unattended_configuration:
		url = unattended_configuration.get("idp_metadata_url")
		if not url:
			raise ValueError("idp_metadata_url not set in unattended configuration")
	else:
		if not interactive:
			raise ValueError("Interactive setup or unattended configuration required")
		url = Prompt.ask("Enter SAML IdP XML metadata URL of filename").strip()

	if url.startswith("http"):
		rich_print(f"Fetching metadata from '{url}'")
		metadata_xml = get_requests_session(urlparse(url).hostname or "").get(url, timeout=10).text
	else:
		file = Path(url.removeprefix("file://"))
		rich_print(f"Reading metadata from '{file}'")
		metadata_xml = file.read_text(encoding="utf-8")

	rich_print("Updating configuration")
	rich_print(
		dedent(
			"""
			Encrypted assertions are generally unnecessary because the connection to the Identity Provider is already secure.
			If you still want to enable encrypted assertions, activate saml-encrypted-assertions in the opsiconfd configuration
			and ensure that RSA1_5 (http://www.w3.org/2001/04/xmlenc#rsa-1_5) is set as the key transport algorithm
			on the Service Provider side, since RSA-OAEP-11 and RSA-OAEP-MGF1P are not currently supported.
			"""
		)
	)
	update_config_from_idp_metadata_xml(metadata_xml)
	config.update_config({"saml_sp_client_signature": True})
	generate_client_certificate()
	metadata_xml = get_sp_metadata_xml()
	metadata_xml = re.sub(r'<\?\s*xml version="1.0"\s*\?>', "", metadata_xml)
	rich_print(
		dedent(
			f"""
			<?xml version="1.0"?>
			<!--
			opsiconfd SP XML metadata.
			This data is also available at: {get_sp_url("/auth/saml/sp-meta.xml")}
			-->
			"""
		).strip()
		+ metadata_xml
	)
