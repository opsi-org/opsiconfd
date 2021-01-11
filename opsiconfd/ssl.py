
import os
import datetime
import random
import shutil

from OpenSSL import crypto
from typing import Tuple

from OPSI.Util import getfqdn
from OPSI.Config import OPSI_ADMIN_GROUP

from .config import config
from .logging import logger
from .utils import get_ip_addresses

def check_ssl_expiry():
	for cert in (config.ssl_ca_cert, config.ssl_server_cert):
		if os.path.exists(cert):
			logger.info("Checking expiry of certificate: %s", cert)

			with open(cert, "r") as file:
				cert = crypto.load_certificate(crypto.FILETYPE_PEM,  file.read())

			enddate = datetime.datetime.strptime(cert.get_notAfter().decode("utf-8"), "%Y%m%d%H%M%SZ")
			diff = (enddate - datetime.datetime.now()).days

			if (diff <= 0):
				logger.error("Certificate '%s' expired on %s", cert, enddate)
			elif (diff < 30):
				logger.warning("Certificate '%s' will expire in %d days", cert, diff)

def renew_ca() -> Tuple[crypto.X509, crypto.PKey]:

	ca_key = None
	if os.path.exists(config.ssl_ca_key):
		logger.info("Using existing key to create new ca.")
		with open(config.ssl_ca_key, "r") as file:
			ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM,  file.read())
	else:
		logger.info("Key not found. Create new ca with new key.")
		ca_key = crypto.PKey()
		ca_key.generate_key(crypto.TYPE_RSA, 4096)

	return create_ca(ca_key)

def create_ca(ca_key: crypto.PKey = None, ca_subject: crypto.X509Name = None) -> Tuple[crypto.X509, crypto.PKey]:
	ca_days = 730
	

	logger.info("Creating opsi CA")

	if not ca_key:
		ca_key = crypto.PKey()
		ca_key.generate_key(crypto.TYPE_RSA, 4096)

	ca_crt = crypto.X509()
	random_number = random.getrandbits(32)
	ca_serial_number = int.from_bytes(f"opsica-{random_number}".encode(), byteorder="big")
	ca_crt.set_serial_number(ca_serial_number)
	ca_crt.gmtime_adj_notBefore(0)
	ca_crt.gmtime_adj_notAfter(ca_days * 60 * 60 * 24)

	ca_crt.set_version(2)
	ca_crt.set_pubkey(ca_key)

	logger.devel("SUBJECT: %s", ca_crt.get_subject())
	if not ca_subject:
		ca_subject = create_x590Name()
	
	ca_crt.set_issuer(ca_subject)
	ca_crt.set_subject(ca_subject)
	logger.devel("SUBJECT: %s", ca_crt.get_subject())

	ca_crt.add_extensions([
		crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_crt),
		crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE")
	])
	ca_crt.sign(ca_key, 'sha256')

	return (ca_crt, ca_key)

def create_x590Name(subject: dict = None) -> crypto.X509Name:

	fqdn = getfqdn()
	domain = '.'.join(fqdn.split('.')[1:])

	if not subject:
		subject = {
			"C": "DE",
			"ST": "RP",
			"L": "MAINZ",
			"O": "uib",
			"OU": f"opsi@{domain}",
			"CN": "opsi CA",
			"emailAddress": f"opsi@{domain}"
		}

	x509_name = crypto.X509Name(crypto.X509().get_subject())
	if subject.get("countryName"):
		x509_name.countryName = subject.get("countryName")
	if subject.get("C"):
		x509_name.C = subject.get("C")
	if subject.get("stateOrProvinceName"):
		x509_name.stateOrProvinceName = subject.get("stateOrProvinceName")
	if subject.get("ST"):
		x509_name.ST = subject.get("ST")
	if subject.get("localityName"):
		x509_name.localityName = subject.get("localityName")
	if subject.get("L"):
		x509_name.L = subject.get("L")
	if subject.get("organizationName"):
		x509_name.organizationName = subject.get("organizationName")
	if subject.get("O"):
		x509_name.O = subject.get("O")
	if subject.get("organizationalUnitName"):
		x509_name.organizationalUnitName = subject.get("organizationalUnitName")
	if subject.get("OU"):
		x509_name.OU = subject.get("OU")
	if subject.get("commonName"):
		x509_name.commonName = subject.get("commonName")
	if subject.get("CN"):
		x509_name.CN = subject.get("CN")
	if subject.get("emailAddress"):
		x509_name.emailAddress = subject.get("emailAddress")

	logger.devel(x509_name)

	return x509_name

def setup_ssl():
	logger.info("Setup ssl")
	if (
		os.path.exists(config.ssl_ca_key) and os.path.exists(config.ssl_ca_cert) and
		os.path.exists(config.ssl_server_key) and os.path.exists(config.ssl_server_cert)
	):
		return
	
	cert_days = 365
	fqdn = getfqdn()
	domain = '.'.join(fqdn.split('.')[1:])
	
	ca_key = None
	ca_crt = None
		
	if not os.path.exists(config.ssl_ca_key) or not os.path.exists(config.ssl_ca_cert):
		logger.info("Creating opsi CA")

		ca_crt, ca_key = create_ca()

		if os.path.exists(config.ssl_ca_key):
			os.unlink(config.ssl_ca_key)
		if not os.path.exists(os.path.dirname(config.ssl_ca_key)):
			os.makedirs(os.path.dirname(config.ssl_ca_key))
			os.chmod(path=os.path.dirname(config.ssl_ca_key), mode=0o700)
		with open(config.ssl_ca_key, "ab") as out:
			out.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))
		
		if os.path.exists(config.ssl_ca_cert):
			os.unlink(config.ssl_ca_cert)
		if not os.path.exists(os.path.dirname(config.ssl_ca_cert)):
			os.makedirs(os.path.dirname(config.ssl_ca_cert))
			os.chmod(path=os.path.dirname(config.ssl_ca_cert), mode=0o700)
		with open(config.ssl_ca_cert, "ab") as out:
			out.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_crt))
		
		setup_ssl_file_permissions()
		
	if os.path.exists(config.ssl_server_key) or not os.path.exists(config.ssl_server_cert):

		if not ca_key:
			with open(config.ssl_ca_key, "r") as file:
				ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM,  file.read())
		if not ca_crt:
			with open(config.ssl_ca_cert, "r") as file:
				ca_crt = crypto.load_certificate(crypto.FILETYPE_PEM,  file.read())

		# Chrome requires Subject Alt Name
		ips = ["127.0.0.1", "::1"]
		for a in get_ip_addresses():
			if a["family"] == "ipv4" and a["address"] not in ips:
				ips.append(a["address"])
		ips = ", ".join([f"IP:{ip}" for ip in ips])

		alt_names = f"DNS:{fqdn}, DNS:localhost, {ips}"

		srv_key = crypto.PKey()
		srv_key.generate_key(crypto.TYPE_RSA, 4096)

		srv_crt = crypto.X509()
		srv_crt.set_version(2)

		srv_subject= srv_crt.get_subject()
		srv_subject.C = "DE"
		srv_subject.ST = "RP"
		srv_subject.L = "MAINZ"
		srv_subject.O = "uib"
		srv_subject.OU = f"opsi@{domain}"
		srv_subject.CN = f"{fqdn}"
		srv_subject.emailAddress = f"opsi@{domain}"

		ca_srl = os.path.splitext(config.ssl_ca_key)[0] + ".srl"
		used_serial_numbers = []
		if os.path.exists(ca_srl):
			with open(ca_srl, "r") as file:
				used_serial_numbers = [serial_number.rstrip() for serial_number in file]
		srv_serial_number = None
		count = 0
		while not srv_serial_number or hex(srv_serial_number)[2:] in used_serial_numbers:
			count += 1
			random_number = random.getrandbits(32)
			srv_serial_number = int.from_bytes(f"opsiconfd-{random_number}".encode(), byteorder="big") 
			if count > 10:
				logger.warning("No new serial number for ssl cert found!")
				break

		srv_crt.set_serial_number(srv_serial_number)
		srv_crt.gmtime_adj_notBefore(0)
		srv_crt.gmtime_adj_notAfter(cert_days * 60 * 60 * 24)
		srv_crt.set_issuer(ca_crt.get_subject())
		srv_crt.set_subject(srv_subject)

		srv_crt.add_extensions([
			crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_crt),
			crypto.X509Extension(b"basicConstraints", True, b"CA:FALSE"),
			crypto.X509Extension(b"keyUsage", True, b"nonRepudiation, digitalSignature, keyEncipherment"),
			crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth, clientAuth, codeSigning, emailProtection"),
			crypto.X509Extension(b"subjectAltName", False, alt_names.encode())
		])

		srv_crt.set_pubkey(srv_key)
		srv_crt.sign(ca_key, "sha256")
		
		logger.info("Creating opsiconfd cert")

		if os.path.exists(config.ssl_server_key):
			os.unlink(config.ssl_server_key)
		if os.path.exists(config.ssl_server_cert):
			os.unlink(config.ssl_server_cert)
		
		if not os.path.exists(os.path.dirname(config.ssl_server_key)):
			os.makedirs(os.path.dirname(config.ssl_server_key))
			os.chmod(path=os.path.dirname(config.ssl_server_key), mode=0o700)

		with open(ca_srl, "a") as out:
			out.write(hex(srv_serial_number)[2:])
			out.write("\n")

		with open(config.ssl_server_key, "ab") as out:
			out.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, srv_key))
		if not os.path.exists(os.path.dirname(config.ssl_server_cert)):
			os.makedirs(os.path.dirname(config.ssl_server_cert))
			os.chmod(path=os.path.dirname(config.ssl_server_cert), mode=0o700)

		with open(config.ssl_server_cert, "ab") as out:
			out.write(crypto.dump_certificate(crypto.FILETYPE_PEM, srv_crt))
		
		setup_ssl_file_permissions()

def setup_ssl_file_permissions():
	# Key and cert can be the same file.
	# Order is important!
	# Set permission of cert first, key afterwards.
	for fn in (config.ssl_ca_cert, config.ssl_ca_key):
		if os.path.exists(fn):
			shutil.chown(path=fn, user=config.run_as_user, group=OPSI_ADMIN_GROUP)
			mode = 0o644 if fn == config.ssl_ca_cert else 0o600
			os.chmod(path=fn, mode=mode)
			dn = os.path.dirname(fn)
			if dn.count('/') >= 3:
				shutil.chown(path=dn, user=config.run_as_user, group=OPSI_ADMIN_GROUP)
				os.chmod(path=dn, mode=0o770)
	
	for fn in (config.ssl_server_cert, config.ssl_server_key):
		if os.path.exists(fn):
			shutil.chown(path=fn, user=config.run_as_user, group=OPSI_ADMIN_GROUP)
			mode = 0o644 if fn == config.ssl_server_cert else 0o600
			os.chmod(path=fn, mode=mode)
			dn = os.path.dirname(fn)
			if dn.count('/') >= 3:
				shutil.chown(path=dn, user=config.run_as_user, group=OPSI_ADMIN_GROUP)
				os.chmod(path=dn, mode=0o770)