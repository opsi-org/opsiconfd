# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

"""
opsiconfd.auth.saml
"""

import re
import xml.dom.minidom
from base64 import b64decode
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from functools import cached_property
from pathlib import Path
from tempfile import TemporaryDirectory
from textwrap import dedent
from typing import Any
from urllib.parse import urlparse
from xml.etree import ElementTree

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateBuilder
from opsi.exception import OpsiServiceAuthenticationError
from opsi.logging import LOG_DEBUG
from opsi.opsi.service.model.object import AuditLogAuthenticationFailureReason
from opsi.process import run_command
from opsi.system.file.temp import TempFile
from rich import print as rich_print
from rich.prompt import Prompt
from saml2 import metadata as saml2_metadata
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.sigver import CryptoBackendXmlSec1, XmlsecError
from saml2.xmldsig import DIGEST_SHA256, SIG_RSA_SHA256

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
) -> SPConfig:
	"""Build a PySAML2 service provider configuration."""
	check_if_saml_available()

	metadata_namespace = "urn:oasis:names:tc:SAML:2.0:metadata"
	signature_namespace = "http://www.w3.org/2000/09/xmldsig#"
	http_post_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	http_redirect_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	name_id_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	entity_descriptor = ElementTree.Element(f"{{{metadata_namespace}}}EntityDescriptor", entityID=config.saml_idp_entity_id)
	idp_descriptor = ElementTree.SubElement(
		entity_descriptor,
		f"{{{metadata_namespace}}}IDPSSODescriptor",
		protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol",
	)
	key_descriptor = ElementTree.SubElement(idp_descriptor, f"{{{metadata_namespace}}}KeyDescriptor", use="signing")
	key_info = ElementTree.SubElement(key_descriptor, f"{{{signature_namespace}}}KeyInfo")
	x509_data = ElementTree.SubElement(key_info, f"{{{signature_namespace}}}X509Data")
	x509_certificate = ElementTree.SubElement(x509_data, f"{{{signature_namespace}}}X509Certificate")
	x509_certificate.text = "".join(line.strip() for line in config.saml_idp_x509_cert.splitlines() if not line.startswith("-----"))
	if config.saml_idp_slo_url:
		ElementTree.SubElement(
			idp_descriptor,
			f"{{{metadata_namespace}}}SingleLogoutService",
			Binding=http_redirect_binding,
			Location=config.saml_idp_slo_url,
		)
	ElementTree.SubElement(
		idp_descriptor,
		f"{{{metadata_namespace}}}SingleSignOnService",
		Binding=http_redirect_binding,
		Location=config.saml_idp_sso_url,
	)

	sign_messages = config.saml_sp_client_signature
	sp_settings: dict[str, Any] = {
		"endpoints": {
			"assertion_consumer_service": [(get_sp_url(login_callback_path), http_post_binding)],
		},
		"name_id_format": [name_id_format],
		"name_id_policy_format": name_id_format,
		"requested_authn_context": None,
		"authn_requests_signed": sign_messages,
		"logout_requests_signed": sign_messages,
		"logout_responses_signed": sign_messages,
		"want_response_signed": sign_messages,
		"want_assertions_signed": sign_messages,
		# Like python3-saml: At least the response or the assertion has to be signed
		"want_assertions_or_response_signed": True,
		# Like python3-saml (non strict mode): InResponseTo is not checked
		"allow_unsolicited": True,
	}
	if config.saml_idp_slo_url:
		sp_settings["endpoints"]["single_logout_service"] = [(get_sp_url(logout_callback_path), http_redirect_binding)]

	if (config.saml_sp_client_signature or config.saml_encrypted_assertions) and (
		not config.saml_sp_x509_cert or not config.saml_sp_private_key
	):
		raise ValueError("saml-sp-x509-cert and saml-sp-private-key must be set in config")

	settings: dict[str, Any] = {
		"entityid": get_sp_entity_id(),
		"debug": 0,
		# Allowed clock drift in seconds like python3-saml
		"accepted_time_diff": 300,
		"signing_algorithm": SIG_RSA_SHA256,
		"digest_algorithm": DIGEST_SHA256,
		"allow_unknown_attributes": True,
		"metadata": {"inline": [ElementTree.tostring(entity_descriptor, encoding="unicode")]},
		"metadata_key_usage": "both" if config.saml_encrypted_assertions else "signing",
		"service": {"sp": sp_settings},
	}
	return SPConfig().load(settings)


class XmlSec1CryptoBackend(CryptoBackendXmlSec1):
	"""
	PySAML2 xmlsec1 crypto backend which runs xmlsec1 via opsi.process.

	In PyInstaller builds LD_LIBRARY_PATH points to the bundled libraries,
	which can be incompatible with the system xmlsec1 binary.
	opsi.process runs subprocesses with the original environment.
	Except for this, the behaviour is identical to CryptoBackendXmlSec1.
	"""

	@cached_property
	def version(self) -> str:
		"""Version of the xmlsec1 binary, determined once per instance."""
		proc = run_command([self.xmlsec, "--version"], success_exit_codes=None, start_log_level=LOG_DEBUG)
		try:
			return proc.get_stdout_text().split(" ")[1]
		except IndexError:
			return "0.0.0"

	def _run_xmlsec(self, com_list: list[str], extra_args: list[str]) -> tuple[str, str, bytes]:
		"""
		Run xmlsec1 and return stdout, stderr and the content of the output file.

		Args:
			com_list: Key-value parameter list for xmlsec1.
			extra_args: Positional parameters appended after all key-value parameters.

		Returns:
			A tuple of stdout, stderr and the content written to the --output file.

		Raises:
			XmlsecError: If xmlsec1 exits with a non-zero return code.
		"""
		with TempFile(extension="xml") as output_file:
			com_list.extend(["--output", str(output_file.path)])
			if self.version_nums >= (1, 3):
				com_list.append("--lax-key-search")
			com_list += extra_args

			proc = run_command(com_list, success_exit_codes=None, start_log_level=LOG_DEBUG)
			p_out = proc.get_stdout_text()
			p_err = proc.get_stderr_text()

			if proc.exit_code != 0:
				errmsg = f"returncode={proc.exit_code}\nerror={p_err}\noutput={p_out}"
				logger.error(errmsg)
				raise XmlsecError(errmsg)

			return p_out, p_err, output_file.path.read_bytes()


@contextmanager
def saml_client(
	login_callback_path: str = "/auth/saml/callback/login", logout_callback_path: str = "/auth/saml/callback/logout"
) -> Generator[Saml2Client]:
	"""
	PySAML2 service provider client.
	PySAML2 requires the SP private key and certificate as files,
	they are only available in a temporary directory while the context is active.
	"""
	sp_config = get_saml_settings(login_callback_path=login_callback_path, logout_callback_path=logout_callback_path)
	with TemporaryDirectory(prefix="opsiconfd-saml-") as tmp_dir:
		if config.saml_sp_client_signature or config.saml_encrypted_assertions:
			# Presence is checked in get_saml_settings
			assert config.saml_sp_private_key and config.saml_sp_x509_cert
			private_key = config.saml_sp_private_key
			if "-----BEGIN" not in private_key:
				private_key = (
					serialization.load_der_private_key(b64decode("".join(private_key.split())), password=None)
					.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
					.decode("ascii")
				)
			certificate = config.saml_sp_x509_cert
			if "-----BEGIN" not in certificate:
				certificate = as_pem(x509.load_der_x509_certificate(b64decode("".join(certificate.split()))))

			key_file = Path(tmp_dir) / "sp.key"
			cert_file = Path(tmp_dir) / "sp.crt"
			for file, content in ((key_file, private_key), (cert_file, certificate)):
				file.touch(mode=0o600)
				file.write_text(content, encoding="utf-8")

			sp_config.key_file = str(key_file)
			sp_config.cert_file = str(cert_file)
			if config.saml_encrypted_assertions:
				sp_config.encryption_keypairs = [{"key_file": str(key_file), "cert_file": str(cert_file)}]

		client = Saml2Client(config=sp_config)
		security_context = client.sec
		if security_context and isinstance(security_context.crypto, CryptoBackendXmlSec1):
			crypto = security_context.crypto
			security_context.crypto = XmlSec1CryptoBackend(crypto.xmlsec, delete_tmpfiles=crypto.delete_tmpfiles)
		yield client


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
	"""Build PySAML2 service provider metadata XML."""
	sp_config = get_saml_settings(login_callback_path=login_callback_path, logout_callback_path=logout_callback_path)
	sp_config.valid_for = 48

	metadata_descriptor = saml2_metadata.entity_descriptor(sp_config)

	if config.saml_sp_x509_cert and (config.saml_sp_client_signature or config.saml_encrypted_assertions):
		certificate = "".join(line.strip() for line in config.saml_sp_x509_cert.splitlines() if not line.startswith("-----"))
		metadata_descriptor.spsso_descriptor.key_descriptor = saml2_metadata.do_key_descriptor(
			cert=certificate,
			enc_cert=certificate if config.saml_encrypted_assertions else None,
			use="both",
		)

	ElementTree.register_namespace("md", "urn:oasis:names:tc:SAML:2.0:metadata")
	ElementTree.register_namespace("ds", "http://www.w3.org/2000/09/xmldsig#")
	dom = xml.dom.minidom.parseString(str(metadata_descriptor))
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
		url = Prompt.ask("Enter SAML IdP XML metadata URL or filename").strip()

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
	# Plain print, rich would insert line breaks and interpret markup, which breaks the XML
	print(
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
