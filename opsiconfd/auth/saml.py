# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.auth.saml
"""

from typing import Any

from fastapi import Request

from opsiconfd.config import config, get_configserver_id


def get_saml_settings(
	login_callback_path: str = "/auth/saml/callback/login", logout_callback_path: str = "/auth/saml/callback/logout"
) -> dict[str, Any]:
	if not config.saml_idp_entity_id:
		raise ValueError("saml-idp-entity-id not set in config")
	if not config.saml_idp_sso_url:
		raise ValueError("saml-idp-sso-url not set in config")
	if not config.saml_idp_x509_cert:
		raise ValueError("saml-idp-x509-cert not set in config")

	settings: dict[str, Any] = {
		"strict": False,
		"debug": True,
		"security": {"allowRepeatAttributeName": True},
		# Identity Provider
		"idp": {
			"entityId": config.saml_idp_entity_id,
			"singleSignOnService": {
				"url": config.saml_idp_sso_url,
				"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
			"x509cert": config.saml_idp_x509_cert,
		},
		# Service Provider
		"sp": {
			"entityId": get_configserver_id(),
			"assertionConsumerService": {
				"url": f"{config.external_url}{login_callback_path}",
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
			"url": f"{config.external_url}{logout_callback_path}",
			"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		}
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
		params["get_data"] = request.query_params
	if "SAMLResponse" in form_data:
		SAMLResponse = form_data["SAMLResponse"]
		params["post_data"]["SAMLResponse"] = SAMLResponse
	if "RelayState" in form_data:
		RelayState = form_data["RelayState"]
		params["post_data"]["RelayState"] = RelayState
	return params
