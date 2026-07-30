# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

import json
import zlib
from base64 import b64decode, b64encode
from collections.abc import Collection
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlparse
from xml.etree import ElementTree

import pytest
from _pytest.capture import CaptureFixture
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from lxml import etree
from minisignxml.config import VerifyConfig
from opsi.testing.helper import http_test_server

from opsiconfd.auth.saml import build_login_redirect_url, get_sp_metadata_xml, update_config_from_idp_metadata_xml
from opsiconfd.config import get_configserver_id
from opsiconfd.redis import redis_client
from opsiconfd.session import OPSISession
from opsiconfd.setup import setup

from .utils import (  # noqa: F401
	Config,
	OpsiconfdTestClient,
	UnprotectedBackend,
	backend,
	clean_mysql,
	clean_redis,
	config,
	get_config,
	test_client,
)


@lru_cache
def create_test_certificate() -> tuple[str, str]:
	"""Create a self-signed test certificate.

	Returns:
		Tuple of Base64 encoded DER certificate and Base64 encoded DER PKCS#8 private key.
	"""
	key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")])
	cert = x509.CertificateBuilder(
		issuer_name=subject,
		subject_name=subject,
		public_key=key.public_key(),
		serial_number=x509.random_serial_number(),
		not_valid_before=datetime.now(tz=UTC) - timedelta(days=1),
		not_valid_after=datetime.now(tz=UTC) + timedelta(days=30),
	).sign(key, hashes.SHA256())
	cert_b64 = b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
	key_b64 = b64encode(
		key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
	).decode("ascii")
	return cert_b64, key_b64


def fake_extract_verified_element_and_certificate(
	*,
	xml: bytes,
	certificates: Collection[x509.Certificate],
	config: VerifyConfig,  # noqa: F811
) -> tuple[etree._Element, x509.Certificate]:
	"""Bypass the XML signature verification and return the parsed root element."""
	return etree.fromstring(xml), next(iter(certificates))


def get_saml_request_id(redirect_url: str) -> str:
	"""Extract the SAML request ID from a HTTP-Redirect binding URL."""
	saml_request = parse_qs(urlparse(redirect_url).query)["SAMLRequest"][0]
	xml_data = zlib.decompress(b64decode(saml_request), -15)
	return ElementTree.fromstring(xml_data).attrib["ID"]


@pytest.mark.parametrize(
	"expiration_seconds, redirect, expected_status_code, expected_text",
	(
		(360000, None, 200, '<meta http-equiv="refresh" content="0; url=/admin">'),
		(100, "/some/path", 200, '<meta http-equiv="refresh" content="0; url=/some/path">'),
		(60, "close_window", 200, "<script>window.close();</script>"),
		(0, None, 401, "Authentication failure"),
	),
)
def test_saml_login(
	config: Config,  # noqa: F811
	test_client: OpsiconfdTestClient,  # noqa: F811
	expiration_seconds: int,
	redirect: str | None,
	expected_status_code: int,
	expected_text: str,
) -> None:
	now = datetime.now(tz=UTC)
	not_before = now - timedelta(seconds=10)
	not_on_or_after = now + timedelta(seconds=expiration_seconds)
	not_before_str = not_before.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
	not_on_or_after_str = not_on_or_after.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

	assertion_id = "ID_0cda0c90-ba3d-4b03-aa3d-1e0899e71615"
	saml_response = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Destination="https://server.opsi.test:4447/auth/saml/callback/login" ID="ID_f347561d-180c-46c6-8840-f44fc12d6d2e" InResponseTo="__REQUEST_ID__" IssueInstant="{not_before_str}" Version="2.0">
		<saml:Issuer>https://keycloak.opsi.test/realms/master</saml:Issuer>
		<dsig:Signature xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
			<dsig:SignedInfo>
				<dsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
				<dsig:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
				<dsig:Reference URI="#ID_f347561d-180c-46c6-8840-f44fc12d6d2e">
					<dsig:Transforms>
						<dsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
						<dsig:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
					</dsig:Transforms>
					<dsig:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
					<dsig:DigestValue>bItA9x5zMs1dyyf9OBYJs7jNDij4oIRL96R92GOBkhE=</dsig:DigestValue>
				</dsig:Reference>
			</dsig:SignedInfo>
			<dsig:SignatureValue>==</dsig:SignatureValue>
			<dsig:KeyInfo>
				<dsig:X509Data>
					<dsig:X509Certificate>==</dsig:X509Certificate>
				</dsig:X509Data>
			</dsig:KeyInfo>
		</dsig:Signature>
		<samlp:Status>
			<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
		</samlp:Status>
		<saml:Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}" IssueInstant="{not_before_str}" Version="2.0">
			<saml:Issuer>https://keycloak.opsi.test/realms/master</saml:Issuer>
			<saml:Subject>
				<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">adminuser</saml:NameID>
				<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
					<saml:SubjectConfirmationData InResponseTo="__REQUEST_ID__" NotOnOrAfter="{not_on_or_after_str}" Recipient="https://server.opsi.test:4447/auth/saml/callback/login"/>
				</saml:SubjectConfirmation>
			</saml:Subject>
			<saml:Conditions NotBefore="{not_before_str}" NotOnOrAfter="{not_on_or_after_str}">
				<saml:AudienceRestriction>
					<saml:Audience>{get_configserver_id()}</saml:Audience>
				</saml:AudienceRestriction>
			</saml:Conditions>
			<saml:AuthnStatement AuthnInstant="{not_before_str}" SessionIndex="ff584b64-6bb2-4138-a8d7-e275b1303933::3b94df11-7bab-441c-a15f-2717404dbb15" SessionNotOnOrAfter="{not_on_or_after_str}">
				<saml:AuthnContext>
					<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef>
				</saml:AuthnContext>
			</saml:AuthnStatement>
			<saml:AttributeStatement>
				<saml:Attribute Name="Role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
					<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
						xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">offline_access</saml:AttributeValue>
				</saml:Attribute>
				<saml:Attribute Name="Role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
					<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
						xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">view-profile</saml:AttributeValue>
				</saml:Attribute>
				<saml:Attribute Name="Role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
					<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
						xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">opsiadmin</saml:AttributeValue>
				</saml:Attribute>
				<saml:Attribute Name="Role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
					<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
						xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">uma_authorization</saml:AttributeValue>
				</saml:Attribute>
			</saml:AttributeStatement>
		</saml:Assertion>
	</samlp:Response>
	"""
	redis = redis_client()
	saml_idp_sso_url = "https://keycloak.opsi.test/realms/master/protocol/saml"
	with (
		patch("minisaml.response.extract_verified_element_and_certificate", fake_extract_verified_element_and_certificate),
		get_config(
			{
				"saml-idp-entity-id": "https://keycloak.opsi.test/realms/master",
				"saml-idp-x509-cert": create_test_certificate()[0],
				"saml-idp-sso-url": saml_idp_sso_url,
				"saml-role-group-mappings": [" view-profile=map-view-profile  ", " offline_access =  group_offline_access"],
			}
		),
	):
		res = test_client.get("/auth/saml/login", follow_redirects=False)
		assert res.status_code == 307
		assert res.headers["location"].startswith(saml_idp_sso_url + "?")
		cookie = next(iter(test_client.cookies.jar))
		session_id = cookie.value

		request_id = get_saml_request_id(res.headers["location"])
		saml_response = saml_response.replace("__REQUEST_ID__", request_id)
		redis_request_key = f"{config.redis_key('saml_login_request_ids')}:{request_id}"
		assert redis.get(redis_request_key) == session_id.encode("utf-8")
		assert 0 < redis.ttl(redis_request_key) <= 600

		data: dict[str, str] = {
			"SAMLResponse": b64encode(saml_response.encode()).decode(),
			"RelayState": json.dumps({"session_id": session_id, "redirect": redirect}),
		}

		redis_session_key = f"{config.redis_key('session')}:{session_id}"
		session_data = OPSISession.deserialize(redis.hgetall(redis_session_key))
		assert session_data
		assert session_data["username"] == ""
		assert session_data["authenticated"] is False
		assert session_data["is_admin"] is False
		assert not session_data["user_groups"]

		for attempt in range(2):
			res = test_client.post("/auth/saml/callback/login", data=data)

			if attempt == 0:
				assert res.status_code == expected_status_code
				assert expected_text in res.text
				# The SAML login request ID must be consumed after the first callback
				assert redis.get(redis_request_key) is None
				if res.status_code == 200:
					session_data = OPSISession.deserialize(redis.hgetall(redis_session_key))
					assert session_data
					assert session_data["username"] == "adminuser"
					assert session_data["user_groups"] == {
						"map-view-profile",
						"uma_authorization",
						"opsiadmin",
						"group_offline_access",
					}
					assert session_data["authenticated"] is True
					assert session_data["is_admin"] is True
					assert session_data["auth_methods"] == {"saml"}

			else:
				# SAML SSO response already processed
				assert res.status_code == 401
				assert res.text == "Authentication failure"


def test_saml_keycloak_group_membership(
	config: Config,  # noqa: F811
	test_client: OpsiconfdTestClient,  # noqa: F811
) -> None:
	now = datetime.now(tz=UTC)
	not_before = now - timedelta(seconds=10)
	not_on_or_after = now + timedelta(seconds=10)
	not_before_str = not_before.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
	not_on_or_after_str = not_on_or_after.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

	saml_response = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Destination="https://opsi.acme.corp:4447/auth/saml/callback/login" ID="ID_2289cf5d-f901-4222-a4a7-1f14887fb8af" InResponseTo="__REQUEST_ID__" IssueInstant="{not_before_str}" Version="2.0">
		<saml:Issuer>https://sso.acme.corp/auth/realms/CORP-REALM</saml:Issuer>
		<dsig:Signature xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
			<dsig:SignedInfo>
				<dsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
				<dsig:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>

			</dsig:SignedInfo>
			<dsig:SignatureValue>==</dsig:SignatureValue>
			<dsig:KeyInfo>
				<dsig:X509Data>
					<dsig:X509Certificate>==</dsig:X509Certificate>
				</dsig:X509Data>
			</dsig:KeyInfo>
		</dsig:Signature>
		<samlp:Status>
			<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
		</samlp:Status>
		<saml:Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="ID_d8e2bcf4-aff4-42a8-9284-9bda77887cbe" IssueInstant="{not_before_str}" Version="2.0">
			<saml:Issuer>https://sso.acme.corp/auth/realms/CORP-REALM</saml:Issuer>
			<saml:Subject>
				<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">user125343</saml:NameID>
				<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
					<saml:SubjectConfirmationData InResponseTo="__REQUEST_ID__" NotOnOrAfter="{not_on_or_after_str}" Recipient="https://opsi.acme.corp:4447/auth/saml/callback/login" />
				</saml:SubjectConfirmation>
			</saml:Subject>
			<saml:Conditions NotBefore="{not_before_str}" NotOnOrAfter="{not_on_or_after_str}">
				<saml:AudienceRestriction>
					<saml:Audience>{get_configserver_id()}</saml:Audience>
				</saml:AudienceRestriction>
			</saml:Conditions>
			<saml:AuthnStatement AuthnInstant="{not_before_str}" SessionIndex="5804e342-7dee-4cdd-a0fe-8c087ec447df::44dd6da6-bce0-4b76-be42-3ced873ad01f" SessionNotOnOrAfter="{not_on_or_after_str}">
				<saml:AuthnContext>
					<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef>
				</saml:AuthnContext>
			</saml:AuthnStatement>
			<saml:AttributeStatement>
				<saml:Attribute FriendlyName="Nachname" Name="sn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
					<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
						xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Doe</saml:AttributeValue>
				</saml:Attribute>
				<saml:Attribute FriendlyName="Anzeigename" Name="displayName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
					<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
						xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Doe, John</saml:AttributeValue>
				</saml:Attribute>
				<saml:Attribute FriendlyName="Vorname" Name="givenName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
					<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
						xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">John</saml:AttributeValue>
				</saml:Attribute>
				<saml:Attribute FriendlyName="Gruppenzugehoerigkeit" Name="groupMembership" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
					<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
						xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">cn=opsi-admin,ou=abc,ou=PermissionGroups,ou=Services,o=acms,c=corp</saml:AttributeValue>
					<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
						xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">cn=keycloak-admin,ou=keycloak,ou=PermissionGroups,ou=Services,o=acms,c=corp</saml:AttributeValue>
				</saml:Attribute>
				<saml:Attribute FriendlyName="E-Mail-Adresse" Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
					<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
						xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">John.Doe@acme.corp</saml:AttributeValue>
				</saml:Attribute>
			</saml:AttributeStatement>
		</saml:Assertion>
	</samlp:Response>
	"""
	redis = redis_client()
	saml_idp_sso_url = "https://keycloak.opsi.test/realms/master/protocol/saml"
	with (
		patch("minisaml.response.extract_verified_element_and_certificate", fake_extract_verified_element_and_certificate),
		get_config(
			{
				"saml-idp-entity-id": "https://sso.acme.corp/auth/realms/CORP-REALM",
				"saml-idp-x509-cert": create_test_certificate()[0],
				"saml-idp-sso-url": saml_idp_sso_url,
				"saml-role-group-mappings": ["CN=opsi-admin,OU=abc,OU=PermissionGroups,OU=Services,O=acms,C=corp =  opsiadmin"],
			}
		),
	):
		res = test_client.get("/auth/saml/login", follow_redirects=False)
		assert res.status_code == 307
		assert res.headers["location"].startswith(saml_idp_sso_url + "?")
		cookie = next(iter(test_client.cookies.jar))
		session_id = cookie.value

		request_id = get_saml_request_id(res.headers["location"])
		saml_response = saml_response.replace("__REQUEST_ID__", request_id)

		data: dict[str, str] = {
			"SAMLResponse": b64encode(saml_response.encode()).decode(),
			"RelayState": json.dumps({"session_id": session_id}),
		}

		redis_session_key = f"{config.redis_key('session')}:{session_id}"
		session_data = OPSISession.deserialize(redis.hgetall(redis_session_key))
		assert session_data
		assert session_data["username"] == ""
		assert session_data["authenticated"] is False
		assert session_data["is_admin"] is False
		assert not session_data["user_groups"]

		res = test_client.post("/auth/saml/callback/login", data=data)

		assert res.status_code == 200
		assert "url=/admin" in res.text
		session_data = OPSISession.deserialize(redis.hgetall(redis_session_key))
		assert session_data
		assert session_data["username"] == "user125343"
		assert session_data["user_groups"] == {"cn=keycloak-admin,ou=keycloak,ou=permissiongroups,ou=services,o=acms,c=corp", "opsiadmin"}
		assert session_data["authenticated"] is True
		assert session_data["is_admin"] is True
		assert session_data["auth_methods"] == {"saml"}


@pytest.mark.parametrize("saml_sp_client_signature", (False, True))
def test_saml_get_sp_metadata_xml(
	test_client: OpsiconfdTestClient,  # noqa: F811
	saml_sp_client_signature: bool,
) -> None:
	with get_config(
		{
			"saml-idp-entity-id": "https://keycloak.opsi.test/realms/master",
			"saml-idp-sso-url": "https://keycloak.opsi.test/realms/master/protocol/saml",
			"saml-idp-slo-url": "https://keycloak.opsi.test/realms/master/protocol/saml",
			"saml-idp-x509-cert": "== IDP_CERT ==",
			"saml-sp-x509-cert": "== SP_CERT ==",
			"saml-sp-private-key": "== SP_KEY ==",
			"saml-sp-client-signature": saml_sp_client_signature,
		}
	):
		metadata = get_sp_metadata_xml(login_callback_path="/login___callback", logout_callback_path="/logout___callback")
		assert metadata.startswith('<?xml version="1.0" ?>\n')
		assert metadata.count("<?xml") == 1
		assert "login___callback" in metadata
		assert "logout___callback" in metadata
		# minisaml always requires signed responses / assertions
		assert 'WantAssertionsSigned="true"' in metadata
		if saml_sp_client_signature:
			assert 'AuthnRequestsSigned="true"' in metadata
			assert '<md:KeyDescriptor use="signing">' in metadata
		else:
			assert 'AuthnRequestsSigned="false"' in metadata
			assert '<md:KeyDescriptor use="signing">' not in metadata

		# Encrypted assertions are no longer supported
		assert '<md:KeyDescriptor use="encryption">' not in metadata

		assert metadata.count("<ds:X509Certificate>==SP_CERT==</ds:X509Certificate>") == int(saml_sp_client_signature)

		res = test_client.get("/auth/saml/sp-meta.xml")
		assert res.status_code == 200
		assert res.headers["content-type"] == "application/xml"
		metadata2 = res.text
		assert metadata == metadata2.replace("/auth/saml/callback/login", "/login___callback").replace(
			"/auth/saml/callback/logout", "/logout___callback"
		)


def test_saml_login_redirect_url_signature() -> None:
	cert_b64, key_b64 = create_test_certificate()
	with get_config(
		{
			"saml-idp-entity-id": "https://keycloak.opsi.test/realms/master",
			"saml-idp-sso-url": "https://keycloak.opsi.test/realms/master/protocol/saml",
			"saml-idp-x509-cert": cert_b64,
			"saml-sp-x509-cert": cert_b64,
			"saml-sp-private-key": key_b64,
			"saml-sp-client-signature": True,
		}
	):
		redirect_url = build_login_redirect_url(request_id="id-test-request", relay_state="relay-state-data")
		query = urlparse(redirect_url).query
		signed_query, _, signature_b64 = query.rpartition("&Signature=")
		assert "SAMLRequest=" in signed_query
		assert "RelayState=" in signed_query
		assert signed_query.endswith("SigAlg=" + "http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256")
		assert get_saml_request_id(redirect_url) == "id-test-request"

		certificate = x509.load_der_x509_certificate(b64decode(cert_b64))
		public_key = certificate.public_key()
		assert isinstance(public_key, rsa.RSAPublicKey)
		# Raises InvalidSignature if the signature is invalid
		public_key.verify(b64decode(unquote(signature_b64)), signed_query.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())


IDP_METDATA_XML = """
<md:EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
	xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
	xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
	xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://keycloak.acme.corp/realms/master">
	<md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
		<md:KeyDescriptor use="signing">
			<ds:KeyInfo>
				<ds:KeyName>keyname</ds:KeyName>
				<ds:X509Data>
					<ds:X509Certificate>==cert==</ds:X509Certificate>
				</ds:X509Data>
			</ds:KeyInfo>
		</md:KeyDescriptor>
		<md:ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://keycloak.acme.corp/realms/master/protocol/saml/resolve" index="0"/>
		<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://keycloak.acme.corp/realms/master/protocol/saml"/>
		<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://keycloak.acme.corp/realms/master/protocol/saml"/>
		<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://keycloak.acme.corp/realms/master/protocol/saml"/>
		<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://keycloak.acme.corp/realms/master/protocol/saml"/>
		<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
		<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
		<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
		<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
		<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://keycloak.acme.corp/realms/master/protocol/saml"/>
		<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://keycloak.acme.corp/realms/master/protocol/saml"/>
		<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://keycloak.acme.corp/realms/master/protocol/saml"/>
		<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://keycloak.acme.corp/realms/master/protocol/saml"/>
	</md:IDPSSODescriptor>
</md:EntityDescriptor>
"""


def test_update_config_from_idp_metadata_xml(tmp_path: Path) -> None:
	conf_file = tmp_path / "opsiconfd.conf"
	with get_config(["--config-file", str(conf_file)]):
		update_config_from_idp_metadata_xml(IDP_METDATA_XML)
		lines = conf_file.read_text(encoding="utf-8").splitlines()
		assert "saml-idp-entity-id = https://keycloak.acme.corp/realms/master" in lines
		assert "saml-idp-x509-cert = ==cert==" in lines
		assert "saml-idp-sso-url = https://keycloak.acme.corp/realms/master/protocol/saml" in lines
		assert "saml-idp-slo-url = https://keycloak.acme.corp/realms/master/protocol/saml" in lines


def test_setup_saml_configuration(tmp_path: Path, capsys: CaptureFixture) -> None:
	conf_file = tmp_path / "opsiconfd.conf"
	conf = {
		"config_file": str(conf_file),
		"setup": True,
		"configure_saml": True,
		"non_interactive": True,
	}
	with get_config(conf), pytest.raises(ValueError, match="Interactive setup or unattended configuration required"):
		setup()

	conf["unattended"] = '{"url": "https://keycloak.opsi.test/realms/master/protocol/saml/descriptor"}'
	with get_config(conf), pytest.raises(ValueError, match="idp_metadata_url not set in unattended configuration"):
		setup()

	with http_test_server(response_body=IDP_METDATA_XML.encode("utf-8")) as server:
		conf["unattended"] = f'{{"idp_metadata_url": "http://localhost:{server.port}/saml/descriptor"}}'
		with get_config(conf):
			setup()
			lines = conf_file.read_text(encoding="utf-8").splitlines()
			assert "saml-idp-entity-id = https://keycloak.acme.corp/realms/master" in lines
			assert "saml-idp-x509-cert = ==cert==" in lines
			assert "saml-idp-sso-url = https://keycloak.acme.corp/realms/master/protocol/saml" in lines
			assert "saml-idp-slo-url = https://keycloak.acme.corp/realms/master/protocol/saml" in lines

			captured = capsys.readouterr()
			assert "Fetching metadata from" in captured.out
			assert "opsiconfd SP XML metadata." in captured.out
			assert "<md:EntityDescriptor" in captured.out
