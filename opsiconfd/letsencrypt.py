# -*- coding: utf-8 -*-

# opsiconfd is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2008-2024 uib GmbH <info@uib.de>
# All rights reserved.
# License: AGPL-3.0

"""
opsiconfd.letsencrypt
"""
# Based on https://github.com/certbot/certbot/blob/master/acme/examples/http01_example.py

from __future__ import annotations

import re
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Generator
from urllib.parse import urlparse

import josepy as jose
from acme import challenges, client, errors, messages, standalone
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from opsiconfd import __version__
from opsiconfd.config import LETSENCRYPT_DATA_DIR, config
from opsiconfd.logging import logger

CHALLENGE_TIMEOUT_SECONDS = 90
ISRG_ROOT_X1_CRT = """
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
"""


def _get_acme_client(contact_email: str) -> client.ClientV2:
	url = urlparse(config.letsencrypt_directory_url)
	directory_id = url.hostname
	assert directory_id

	account_data_path = Path(LETSENCRYPT_DATA_DIR) / "accounts" / directory_id
	account_private_key_data_path = account_data_path / "private_key.json"
	account_registration_resource_data_path = account_data_path / "regr.json"

	account_data_path.mkdir(parents=True, exist_ok=True)

	try:
		account_key = jose.JWKRSA.json_loads(account_private_key_data_path.read_bytes())
	except Exception as err:
		log = logger.debug if isinstance(err, FileNotFoundError) else logger.error
		log("Failed to load account key from '%s': %s", account_private_key_data_path, err)
		if account_registration_resource_data_path.exists():
			logger.warning(
				"Deleting existing registration resource '%s' as account key is missing", account_registration_resource_data_path
			)
			account_registration_resource_data_path.unlink()
		logger.notice("Creating new account key for directory '%s'", directory_id)
		account_key = jose.JWKRSA(key=rsa.generate_private_key(public_exponent=65537, key_size=2048))
		account_private_key_data_path.write_text(account_key.json_dumps(), encoding="utf-8")
		account_private_key_data_path.chmod(0o600)

	network = client.ClientNetwork(key=account_key, user_agent=f"opsiconfd/{__version__}")
	directory = client.ClientV2.get_directory(url=config.letsencrypt_directory_url, net=network)
	acme_client = client.ClientV2(directory=directory, net=network)

	update_registration = False
	try:
		registration_resource = messages.RegistrationResource.json_loads(account_registration_resource_data_path.read_bytes())
		registration_resource = acme_client.query_registration(registration_resource)
		if contact_email not in registration_resource.body.emails:
			logger.info(
				"Contact email %r for account in directory %r currently not registered (%s), updating registration",
				contact_email,
				directory_id,
				registration_resource.body.emails,
			)
			update_registration = True
	except Exception as err:
		log = logger.debug if isinstance(err, FileNotFoundError) else logger.error
		log("Failed to use stored registration from '%s': %s", account_registration_resource_data_path, err)
		logger.info("Registering new account for directory '%s' with contact email %r", directory_id, contact_email)
		try:
			registration_resource = acme_client.new_account(
				messages.NewRegistration.from_data(email=contact_email, terms_of_service_agreed=True)
			)
			account_registration_resource_data_path.write_text(registration_resource.json_dumps(), encoding="utf-8")
			account_registration_resource_data_path.chmod(0o600)
		except errors.ConflictError as err:
			logger.info("Account already exists: %s, updating registration data", err)
			registration_resource = messages.RegistrationResource().from_json({"body": "", "uri": err.location})
			update_registration = True

	if update_registration:
		registration_resource = registration_resource.update(body=registration_resource.body.update(contact=[f"mailto:{contact_email}"]))
		registration_resource = acme_client.update_registration(registration_resource)
		account_registration_resource_data_path.write_text(registration_resource.json_dumps(), encoding="utf-8")
		account_registration_resource_data_path.chmod(0o600)

	return acme_client


def _select_http01_challenge_body(order_resource: messages.OrderResource) -> messages.ChallengeBody:
	"""Extract authorization resource from within order resource."""
	for authz in order_resource.authorizations:
		for challenge_body in authz.body.challenges:
			if isinstance(challenge_body.chall, challenges.HTTP01):
				return challenge_body

	raise RuntimeError("HTTP-01 challenge was not offered by the CA server.")


@contextmanager
def _http_01_challenge_server(
	http_01_resources: set[standalone.HTTP01RequestHandler.HTTP01Resource],
) -> Generator[standalone.HTTP01DualNetworkedServers, None, None]:
	"""Manage webserver start and shutdown."""
	try:
		logger.info("Starting HTTP-01 challenge server on port 80")
		servers = standalone.HTTP01DualNetworkedServers(server_address=("", 80), resources=http_01_resources)
		servers.serve_forever()
		yield servers
	finally:
		logger.info("Shutting down HTTP-01 challenge server")
		servers.shutdown_and_server_close()


def _perform_http01(acme_client: client.ClientV2, challenge_body: messages.ChallengeBody, order_resource: messages.OrderResource) -> str:
	"""Start webserver and perform HTTP-01 challenge."""
	response, validation = challenge_body.response_and_validation(acme_client.net.key)
	resource = standalone.HTTP01RequestHandler.HTTP01Resource(chall=challenge_body.chall, response=response, validation=validation)
	with _http_01_challenge_server({resource}):
		# Let the CA server know that we are ready for the challenge.
		acme_client.answer_challenge(challenge_body, response)
		# Wait for challenge status and then issue a certificate.
		deadline = datetime.now() + timedelta(seconds=CHALLENGE_TIMEOUT_SECONDS)
		finalized_orderr = acme_client.poll_and_finalize(order_resource, deadline=deadline)

	return finalized_orderr.fullchain_pem


def perform_certificate_signing_request(
	certificate_signing_request: x509.CertificateSigningRequest,
	contact_email: str,
) -> list[x509.Certificate]:
	try:
		acme_client = _get_acme_client(contact_email=contact_email)
		certificate_signing_request_pem = certificate_signing_request.public_bytes(serialization.Encoding.PEM)
		order_resource = acme_client.new_order(certificate_signing_request_pem)
		challenge_body = _select_http01_challenge_body(order_resource)
		fullchain_pem = _perform_http01(acme_client, challenge_body, order_resource)
		logger.info("Let's Encrypt certificate signing request successfully completed")
		certs = [
			x509.load_pem_x509_certificate(match.group(1).encode("utf-8"))
			for match in re.finditer(r"(-+BEGIN CERTIFICATE-+.*?-+END CERTIFICATE-+)", fullchain_pem, re.DOTALL)
		]
		certs.append(x509.load_pem_x509_certificate(ISRG_ROOT_X1_CRT.encode("utf-8")))
		return certs
	except Exception as err:
		err_msg = str(err)
		if isinstance(err, errors.ValidationError):
			logger.debug(err.failed_authzrs)
			err_msg = ",".join(str(chall.error) for authzr in err.failed_authzrs for chall in authzr.body.challenges)

		err_msg = f"Failed to perform Let's Encrypt certificate signing request: {err_msg}"
		logger.error(err_msg, exc_info=True)
		raise RuntimeError(err_msg)
