# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.auth.saml

SAML 2.0 Service Provider (SP) implementation based on minisaml.

SAML responses (HTTP-POST binding) are validated by minisaml.
The HTTP-Redirect binding for AuthnRequest and LogoutRequest messages,
including the optional query string signature as specified in the
SAML 2.0 bindings specification, is implemented in this module.
"""

from __future__ import annotations

import re
import secrets
import xml.dom.minidom
import zlib
from base64 import b64decode, b64encode
from datetime import UTC, datetime, timedelta
from pathlib import Path
from textwrap import dedent
from urllib.parse import urlencode, urlparse
from xml.etree import ElementTree

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import CertificateBuilder
from minisaml.response import Response as SamlResponse
from minisaml.response import TimeDriftLimits, validate_response
from opsi.exception import OpsiServiceAuthenticationError
from opsi.logging import TRACE
from opsi.opsi.service.model.object import AuditLogAuthenticationFailureReason
from rich import print as rich_print
from rich.prompt import Prompt

from opsiconfd.config import config, get_configserver_id
from opsiconfd.logging import get_logger
from opsiconfd.ssl import as_pem
from opsiconfd.utils import get_requests_session
from opsiconfd.utils.modules import module_available

logger = get_logger("opsiconfd.saml")

SAML_NS_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML_NS_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
SAML_NS_METADATA = "urn:oasis:names:tc:SAML:2.0:metadata"
XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#"
SAML_BINDING_HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
SAML_BINDING_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
SAML_NAME_ID_FORMAT_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
SAML_STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
SIG_ALG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
SAML_DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
# Tolerated clock skew between IdP and SP when validating the conditions of a SAML response
ALLOWED_TIME_DRIFT = TimeDriftLimits(not_before_max_drift=timedelta(seconds=30), not_on_or_after_max_drift=timedelta(seconds=30))


def check_if_saml_available() -> None:
	"""Raise an exception if SAML authentication is unavailable or not configured."""
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
	"""Return the SAML entity ID of the Service Provider."""
	return get_configserver_id()


def get_sp_base_url() -> str:
	"""Return the external base URL of the Service Provider."""
	return config.external_url


def get_sp_url(path: str | None = None) -> str:
	"""Return the absolute external URL of the Service Provider for the given path."""
	base_url = get_sp_base_url()
	if not path:
		return base_url
	return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def generate_saml_id() -> str:
	"""Generate a random SAML message ID (must be an xsd:ID / NCName, therefore it must not start with a digit)."""
	return f"id-{secrets.token_hex(20)}"


def get_idp_certificate() -> x509.Certificate:
	"""Load the X.509 certificate of the IdP from the config (Base64 encoded DER)."""
	if not config.saml_idp_x509_cert:
		raise ValueError("saml-idp-x509-cert not set in config")
	return x509.load_der_x509_certificate(b64decode("".join(config.saml_idp_x509_cert.split())))


def get_sp_private_key() -> rsa.RSAPrivateKey:
	"""Load the RSA private key of the SP from the config (Base64 encoded DER / PKCS#8)."""
	if not config.saml_sp_private_key:
		raise ValueError("saml-sp-private-key not set in config")
	private_key = serialization.load_der_private_key(b64decode("".join(config.saml_sp_private_key.split())), password=None)
	if not isinstance(private_key, rsa.RSAPrivateKey):
		raise TypeError("saml-sp-private-key is not an RSA private key")
	return private_key


def deflate_and_base64_encode(data: bytes) -> str:
	"""Compress data with raw deflate and encode it as Base64 as required by the SAML HTTP-Redirect binding."""
	# Strip zlib header (2 bytes) and checksum (4 bytes) to get a raw deflate stream
	return b64encode(zlib.compress(data, 9)[2:-4]).decode("ascii")


def build_redirect_binding_url(endpoint: str, parameters: dict[str, str]) -> str:
	"""Build a SAML HTTP-Redirect binding URL, signing the query string if saml-sp-client-signature is enabled.

	According to the SAML 2.0 bindings specification the signature is computed over the
	URL-encoded query string containing SAMLRequest/SAMLResponse, RelayState and SigAlg
	(in this order) and transmitted in the Signature query parameter.
	"""
	if config.saml_sp_client_signature:
		parameters["SigAlg"] = SIG_ALG_RSA_SHA256
	query = urlencode(parameters)
	if config.saml_sp_client_signature:
		signature = get_sp_private_key().sign(query.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
		query += "&" + urlencode({"Signature": b64encode(signature).decode("ascii")})
	separator = "&" if urlparse(endpoint).query else "?"
	return f"{endpoint}{separator}{query}"


def build_authn_request_xml(request_id: str, login_callback_path: str = "/auth/saml/callback/login") -> bytes:
	"""Build a SAML AuthnRequest for the HTTP-Redirect binding.

	No RequestedAuthnContext is included to avoid error AADSTS75011 with Entra ID.
	See https://learn.microsoft.com/de-de/troubleshoot/entra/entra-id/app-integration/error-code-AADSTS75011-auth-method-mismatch
	"""
	authn_request = ElementTree.Element(
		f"{{{SAML_NS_PROTOCOL}}}AuthnRequest",
		{
			"ID": request_id,
			"Version": "2.0",
			"IssueInstant": datetime.now(tz=UTC).strftime(SAML_DATE_TIME_FORMAT),
			"Destination": config.saml_idp_sso_url,
			"ProtocolBinding": SAML_BINDING_HTTP_POST,
			"AssertionConsumerServiceURL": get_sp_url(login_callback_path),
		},
	)
	issuer = ElementTree.SubElement(authn_request, f"{{{SAML_NS_ASSERTION}}}Issuer")
	issuer.text = get_sp_entity_id()
	ElementTree.SubElement(
		authn_request, f"{{{SAML_NS_PROTOCOL}}}NameIDPolicy", {"Format": SAML_NAME_ID_FORMAT_UNSPECIFIED, "AllowCreate": "true"}
	)
	return ElementTree.tostring(authn_request, encoding="utf-8", xml_declaration=True)


def build_login_redirect_url(request_id: str, relay_state: str, login_callback_path: str = "/auth/saml/callback/login") -> str:
	"""Build the IdP redirect URL for a SP initiated login via SAML HTTP-Redirect binding."""
	check_if_saml_available()
	authn_request_xml = build_authn_request_xml(request_id=request_id, login_callback_path=login_callback_path)
	if logger.isEnabledFor(TRACE):
		logger.trace("SAML AuthnRequest XML: %s", authn_request_xml)
	parameters = {"SAMLRequest": deflate_and_base64_encode(authn_request_xml), "RelayState": relay_state}
	return build_redirect_binding_url(config.saml_idp_sso_url, parameters)


def build_logout_request_xml(name_id: str) -> bytes:
	"""Build a SAML LogoutRequest for the HTTP-Redirect binding."""
	logout_request = ElementTree.Element(
		f"{{{SAML_NS_PROTOCOL}}}LogoutRequest",
		{
			"ID": generate_saml_id(),
			"Version": "2.0",
			"IssueInstant": datetime.now(tz=UTC).strftime(SAML_DATE_TIME_FORMAT),
			"Destination": config.saml_idp_slo_url,
		},
	)
	issuer = ElementTree.SubElement(logout_request, f"{{{SAML_NS_ASSERTION}}}Issuer")
	issuer.text = get_sp_entity_id()
	name_id_element = ElementTree.SubElement(logout_request, f"{{{SAML_NS_ASSERTION}}}NameID", {"Format": SAML_NAME_ID_FORMAT_UNSPECIFIED})
	name_id_element.text = name_id
	return ElementTree.tostring(logout_request, encoding="utf-8", xml_declaration=True)


def build_logout_redirect_url(name_id: str) -> str:
	"""Build the IdP redirect URL for a SP initiated Single Logout via SAML HTTP-Redirect binding."""
	check_if_saml_available()
	if not config.saml_idp_slo_url:
		raise ValueError("saml-idp-slo-url not set in config")
	logout_request_xml = build_logout_request_xml(name_id=name_id)
	if logger.isEnabledFor(TRACE):
		logger.trace("SAML LogoutRequest XML: %s", logout_request_xml)
	parameters = {"SAMLRequest": deflate_and_base64_encode(logout_request_xml)}
	return build_redirect_binding_url(config.saml_idp_slo_url, parameters)


def validate_login_response(saml_response: bytes | str) -> SamlResponse:
	"""Validate a Base64 encoded SAML response including its XML signature and return the parsed response.

	Raises:
		minisaml.errors.MiniSAMLError: If the response is invalid, expired or does not match audience / issuer.
	"""
	check_if_saml_available()
	return validate_response(
		data=saml_response,
		certificate=get_idp_certificate(),
		expected_audience=get_sp_entity_id(),
		idp_issuer=config.saml_idp_entity_id,
		allowed_time_drift=ALLOWED_TIME_DRIFT,
	)


def get_logout_response_status(saml_response: str) -> str:
	"""Decode a Base64 encoded SAML LogoutResponse (HTTP-Redirect or HTTP-POST binding) and return its status code.

	The signature of the LogoutResponse is not verified, the status is used for logging purposes only.
	The local session is terminated regardless of the outcome of the Single Logout at the IdP.
	"""
	data = b64decode(saml_response)
	try:
		# HTTP-Redirect binding uses raw deflate compression
		data = zlib.decompress(data, wbits=-15)
	except zlib.error:
		pass
	root = ElementTree.fromstring(data)
	status_code = root.find(f".//{{{SAML_NS_PROTOCOL}}}StatusCode")
	if status_code is None:
		raise ValueError("StatusCode not found in LogoutResponse")
	return status_code.attrib.get("Value", "")


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
	"""Generate the SAML metadata XML document of the Service Provider.

	WantAssertionsSigned is always true, as minisaml requires a valid XML signature
	on the SAML response or assertion.
	"""
	check_if_saml_available()
	valid_until = (datetime.now(tz=UTC) + timedelta(days=2)).strftime(SAML_DATE_TIME_FORMAT)

	ElementTree.register_namespace("md", SAML_NS_METADATA)
	ElementTree.register_namespace("ds", XMLDSIG_NS)
	entity_descriptor = ElementTree.Element(
		f"{{{SAML_NS_METADATA}}}EntityDescriptor", {"validUntil": valid_until, "entityID": get_sp_entity_id()}
	)
	sp_sso_descriptor = ElementTree.SubElement(
		entity_descriptor,
		f"{{{SAML_NS_METADATA}}}SPSSODescriptor",
		{
			"AuthnRequestsSigned": "true" if config.saml_sp_client_signature else "false",
			"WantAssertionsSigned": "true",
			"protocolSupportEnumeration": SAML_NS_PROTOCOL,
		},
	)
	if config.saml_sp_client_signature:
		if not config.saml_sp_x509_cert:
			raise ValueError("saml-sp-x509-cert not set in config")
		key_descriptor = ElementTree.SubElement(sp_sso_descriptor, f"{{{SAML_NS_METADATA}}}KeyDescriptor", {"use": "signing"})
		key_info = ElementTree.SubElement(key_descriptor, f"{{{XMLDSIG_NS}}}KeyInfo")
		x509_data = ElementTree.SubElement(key_info, f"{{{XMLDSIG_NS}}}X509Data")
		x509_certificate = ElementTree.SubElement(x509_data, f"{{{XMLDSIG_NS}}}X509Certificate")
		x509_certificate.text = "".join(config.saml_sp_x509_cert.split())
	if config.saml_idp_slo_url:
		ElementTree.SubElement(
			sp_sso_descriptor,
			f"{{{SAML_NS_METADATA}}}SingleLogoutService",
			{"Binding": SAML_BINDING_HTTP_REDIRECT, "Location": get_sp_url(logout_callback_path)},
		)
	name_id_format = ElementTree.SubElement(sp_sso_descriptor, f"{{{SAML_NS_METADATA}}}NameIDFormat")
	name_id_format.text = SAML_NAME_ID_FORMAT_UNSPECIFIED
	ElementTree.SubElement(
		sp_sso_descriptor,
		f"{{{SAML_NS_METADATA}}}AssertionConsumerService",
		{"Binding": SAML_BINDING_HTTP_POST, "Location": get_sp_url(login_callback_path), "index": "1"},
	)

	metadata = ElementTree.tostring(entity_descriptor, encoding="unicode")
	dom = xml.dom.minidom.parseString(metadata)
	metadata = dom.toprettyxml()
	return re.sub(r"^\s*\n", "", metadata, flags=re.MULTILINE)


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
