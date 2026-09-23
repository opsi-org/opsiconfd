# opsiconfd is part of the device management solution opsi http://www.opsi.org
# Copyright (c) 2008-2026 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0-only

import json
from base64 import b64encode
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree

import pytest
from _pytest.capture import CaptureFixture
from opsi.testing.helper import http_test_server
from saml2.s_utils import UnsupportedBinding

from opsiconfd.auth.saml import get_saml_settings, get_sp_entity_id, get_sp_metadata_xml, get_sp_url, update_config_from_idp_metadata_xml
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


@pytest.mark.parametrize("slo_url", (None, "https://idp.test/slo"))
@pytest.mark.parametrize("sign_messages", (False, True))
def test_get_saml_settings(slo_url: str | None, sign_messages: bool) -> None:
	with (
		patch("opsiconfd.auth.saml.module_available", return_value=True),
		patch("opsiconfd.auth.saml.get_sp_entity_id", return_value="sp.test"),
		get_config(
			{
				"external-url": "https://sp.test:4447",
				"saml-idp-entity-id": "https://idp.test",
				"saml-idp-sso-url": "https://idp.test/sso",
				"saml-idp-slo-url": slo_url,
				"saml-idp-x509-cert": "CERTIFICATE",
				"saml-sp-client-signature": sign_messages,
				"saml-sp-x509-cert": "SP CERTIFICATE" if sign_messages else None,
				"saml-sp-private-key": "SP PRIVATE KEY" if sign_messages else None,
			}
		),
	):
		settings = get_saml_settings()

	assert settings.entityid == "sp.test"
	assert settings.metadata_key_usage == "signing"
	assert settings.endpoint(
		"assertion_consumer_service",
		binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		context="sp",
	) == ["https://sp.test:4447/auth/saml/callback/login"]
	for setting in (
		"authn_requests_signed",
		"logout_requests_signed",
		"logout_responses_signed",
		"want_response_signed",
		"want_assertions_signed",
	):
		assert settings.getattr(setting, "sp") is sign_messages

	metadata = settings.metadata
	assert metadata is not None
	assert metadata.identity_providers() == ["https://idp.test"]
	idp_sso = metadata.single_sign_on_service("https://idp.test", binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
	assert idp_sso[0]["location"] == "https://idp.test/sso"
	sp_slo = settings.endpoint(
		"single_logout_service",
		binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		context="sp",
	)
	if slo_url:
		idp_slo = metadata.single_logout_service(
			"https://idp.test", binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", typ="idpsso"
		)
		assert idp_slo[0]["location"] == slo_url
		assert sp_slo == ["https://sp.test:4447/auth/saml/callback/logout"]
	else:
		with pytest.raises(UnsupportedBinding):
			metadata.single_logout_service("https://idp.test", binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", typ="idpsso")
		assert sp_slo == []


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
	# PySAML2 validates Destination and Audience
	acs_url = get_sp_url("/auth/saml/callback/login")
	sp_entity_id = get_sp_entity_id()
	saml_response = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Destination="{acs_url}" ID="ID_f347561d-180c-46c6-8840-f44fc12d6d2e" InResponseTo="ONELOGIN_b153d66c2d481283663e72adee0c576657c907d6" IssueInstant="{not_before_str}" Version="2.0">
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
					<saml:SubjectConfirmationData InResponseTo="ONELOGIN_b153d66c2d481283663e72adee0c576657c907d6" NotOnOrAfter="{not_on_or_after_str}" Recipient="{acs_url}"/>
				</saml:SubjectConfirmation>
			</saml:Subject>
			<saml:Conditions NotBefore="{not_before_str}" NotOnOrAfter="{not_on_or_after_str}">
				<saml:AudienceRestriction>
					<saml:Audience>{sp_entity_id}</saml:Audience>
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
		patch("saml2.sigver.SecurityContext._check_signature", lambda _self, _decoded_xml, item, *args, **kwargs: item),
		get_config(
			{
				"saml-idp-entity-id": "https://keycloak.opsi.test/realms/master",
				"saml-idp-x509-cert": "==",
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
				if res.status_code == 200:
					redis_key = f"{config.redis_key('saml_processed_assertion_ids')}:{assertion_id}"
					assert redis.get(redis_key) == b"1"
					exp = redis.ttl(redis_key)
					assert exp > expiration_seconds
					assert exp < expiration_seconds + 70

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

	# PySAML2 validates Destination and Audience
	acs_url = get_sp_url("/auth/saml/callback/login")
	sp_entity_id = get_sp_entity_id()
	saml_response = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Destination="{acs_url}" ID="ID_2289cf5d-f901-4222-a4a7-1f14887fb8af" InResponseTo="ONELOGIN_9c52a28bfda30cbb55f91e57bb3158ecd6caec5b" IssueInstant="{not_before_str}" Version="2.0">
		<saml:Issuer>https://sso.acme.corp/auth/realms/CORP-REALM</saml:Issuer>
		<dsig:Signature xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
			<dsig:SignedInfo>
				<dsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
				<dsig:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
				<dsig:Reference URI="#ID_2289cf5d-f901-4222-a4a7-1f14887fb8af">
					<dsig:Transforms>
						<dsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
						<dsig:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
					</dsig:Transforms>
					<dsig:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
					<dsig:DigestValue>==</dsig:DigestValue>
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
			<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
		</samlp:Status>
		<saml:Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="ID_d8e2bcf4-aff4-42a8-9284-9bda77887cbe" IssueInstant="{not_before_str}" Version="2.0">
			<saml:Issuer>https://sso.acme.corp/auth/realms/CORP-REALM</saml:Issuer>
			<saml:Subject>
				<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">user125343</saml:NameID>
				<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
					<saml:SubjectConfirmationData InResponseTo="ONELOGIN_9c52a28bfda30cbb55f91e57bb3158ecd6caec5b" NotOnOrAfter="{not_on_or_after_str}" Recipient="{acs_url}" />
				</saml:SubjectConfirmation>
			</saml:Subject>
			<saml:Conditions NotBefore="{not_before_str}" NotOnOrAfter="{not_on_or_after_str}">
				<saml:AudienceRestriction>
					<saml:Audience>{sp_entity_id}</saml:Audience>
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
		patch("saml2.sigver.SecurityContext._check_signature", lambda _self, _decoded_xml, item, *args, **kwargs: item),
		get_config(
			{
				"saml-idp-entity-id": "https://keycloak.opsi.test/realms/master",
				"saml-idp-x509-cert": "==",
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


@pytest.mark.parametrize(
	"saml_sp_client_signature, saml_encrypted_assertions",
	(
		(False, False),
		(True, False),
		(True, True),
	),
)
def test_saml_get_sp_metadata_xml(
	saml_sp_client_signature: bool,
	saml_encrypted_assertions: bool,
) -> None:
	with (
		patch("opsiconfd.auth.saml.module_available", return_value=True),
		patch("opsiconfd.auth.saml.get_sp_entity_id", return_value="sp.test"),
		get_config(
			{
				"external-url": "https://sp.test:4447",
				"saml-idp-entity-id": "https://idp.test",
				"saml-idp-sso-url": "https://idp.test/sso",
				"saml-idp-slo-url": "https://idp.test/slo",
				"saml-idp-x509-cert": "IDP CERTIFICATE",
				"saml-sp-x509-cert": "SP CERTIFICATE",
				"saml-sp-private-key": "SP PRIVATE KEY",
				"saml-sp-client-signature": saml_sp_client_signature,
				"saml-encrypted-assertions": saml_encrypted_assertions,
			}
		),
	):
		metadata = get_sp_metadata_xml(login_callback_path="/login___callback", logout_callback_path="/logout___callback")

	assert metadata.startswith('<?xml version="1.0" ?>\n')
	root = ElementTree.fromstring(metadata)
	assert root.attrib["entityID"] == "sp.test"
	valid_until = datetime.strptime(root.attrib["validUntil"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
	assert timedelta(hours=47, minutes=59) < valid_until - datetime.now(tz=UTC) <= timedelta(hours=48)

	metadata_namespace = "{urn:oasis:names:tc:SAML:2.0:metadata}"
	descriptor = root.find(f"{metadata_namespace}SPSSODescriptor")
	assert descriptor is not None
	assert descriptor.attrib["AuthnRequestsSigned"] == str(saml_sp_client_signature).lower()
	assert descriptor.attrib["WantAssertionsSigned"] == str(saml_sp_client_signature).lower()
	assertion_consumer_service = descriptor.find(f"{metadata_namespace}AssertionConsumerService")
	assert assertion_consumer_service is not None
	assert assertion_consumer_service.attrib["Location"] == "https://sp.test:4447/login___callback"
	single_logout_service = descriptor.find(f"{metadata_namespace}SingleLogoutService")
	assert single_logout_service is not None
	assert single_logout_service.attrib["Location"] == "https://sp.test:4447/logout___callback"
	key_descriptors = descriptor.findall(f"{metadata_namespace}KeyDescriptor")
	assert [key_descriptor.attrib["use"] for key_descriptor in key_descriptors] == (
		(["signing"] if saml_sp_client_signature else []) + (["encryption"] if saml_encrypted_assertions else [])
	)


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
