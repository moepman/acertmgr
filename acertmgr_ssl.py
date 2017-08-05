#!/usr/bin/env python
# -*- coding: utf-8 -*-

# acertmgr - ssl management functions
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# available under the ISC license, see LICENSE

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
import base64
import binascii
import copy
import json
import time
import os
import re
try:
	from urllib.request import urlopen # Python 3
except ImportError:
	from urllib2 import urlopen # Python 2

# @brief retrieve notBefore and notAfter dates of a certificate file
# @param cert_file the path to the certificate
# @return the tuple of dates: (notBefore, notAfter)
def cert_valid_times(cert_file):
	with open(cert_file, 'r') as f:
		cert_data = f.read()
	cert = x509.load_pem_x509_certificate(cert_data, default_backend())
	return (cert.not_valid_before, cert.not_valid_after)

# @brief create a certificate signing request
# @param names list of domain names the certificate should be valid for
# @param key the key to use with the certificate in cryptography format
# @return the CSR in cryptography format
def cert_request(names, key):
	primary_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0].decode('utf8'))])
	all_names = x509.SubjectAlternativeName([x509.DNSName(name.decode('utf8')) for name in names])
	req = x509.CertificateSigningRequestBuilder()
	req = req.subject_name(primary_name)
	req = req.add_extension(all_names, critical=False)
	req = req.sign(key, hashes.SHA256(), default_backend())
	return req

# @brief convert certificate to PEM format
# @param cert certificate object in cryptography format
# @return the certificate in PEM format
def cert_to_pem(cert):
	return cert.public_bytes(serialization.Encoding.PEM).decode('utf8')

# @brief read a key from file
# @param path path to key file
# @return the key in cryptography format
def read_key(path):
	with open(path, 'r') as f:
		key_data = f.read()
	return serialization.load_pem_private_key(key_data, None, default_backend())

# @brief convert numbers to byte-string
# @param num number to convert
# @return byte-string containing the number
# @todo better code welcome
def byte_string_format(num):
	n = format(num, 'x')
	n = "0{0}".format(n) if len(n) % 2 else n
	return binascii.unhexlify(n)

# @brief create the header information for ACME communication
# @param key the account key
# @return the header for ACME
def acme_header(key):
	numbers = key.public_key().public_numbers()
	header = {
		"alg": "RS256",
		"jwk": {
			"e": base64_enc(byte_string_format(numbers.e)),
			"kty": "RSA",
			"n": base64_enc(byte_string_format(numbers.n)),
		},
	}
	return header

# @brief register an account over ACME
# @param account_key the account key to register
# @param CA the certificate authority to register with
# @return True if new account was registered, False otherwise
def register_account(account_key, CA):
	header = acme_header(account_key)
	code, result = send_signed(account_key, CA, CA + "/acme/new-reg", header, {
		"resource": "new-reg",
		"agreement": "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf",
	})
	if code == 201:
		print("Registered!")
		return True
	elif code == 409:
		print("Already registered!")
		return False
	else:
		raise ValueError("Error registering: {0} {1}".format(code, result))

# @brief helper function to base64 encode for JSON objects
# @param b the string to encode
# @return the encoded string
def base64_enc(b):
	return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")


# @brief helper function to make signed requests
# @param CA the certificate authority
# @param url the request URL
# @param header the message header
# @param payload the message
# @return tuple of return code and request answer
def send_signed(account_key, CA, url, header, payload):
	payload64 = base64_enc(json.dumps(payload).encode('utf8'))
	protected = copy.deepcopy(header)
	protected["nonce"] = urlopen(CA + "/directory").headers['Replay-Nonce']
	protected64 = base64_enc(json.dumps(protected).encode('utf8'))
	# @todo check why this padding is not working
	#pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
	pad = padding.PKCS1v15()
	out = account_key.sign('.'.join([protected64, payload64]).encode('utf8'), pad, hashes.SHA256())
	data = json.dumps({
		"header": header, "protected": protected64,
		"payload": payload64, "signature": base64_enc(out),
	})
	try:
		resp = urlopen(url, data.encode('utf8'))
		return resp.getcode(), resp.read()
	except IOError as e:
		return getattr(e, "code", None), getattr(e, "read", e.__str__)()

# @brief function to fetch certificate using ACME
# @param account_key the account key in pyopenssl format
# @param csr the certificate signing request in pyopenssl format
# @param domains list of domains in the certificate, first is CN
# @param acme_dir directory for ACME challanges
# @param CA which signing CA to use
# @return the certificate in pyopenssl format
# @note algorithm and parts of the code are from acme-tiny
def get_crt_from_csr(account_key, csr, domains, acme_dir, CA):
	header = acme_header(account_key)
	accountkey_json = json.dumps(header['jwk'], sort_keys=True, separators=(',', ':'))
	account_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
	account_hash.update(accountkey_json.encode('utf8'))
	account_thumbprint = base64_enc(account_hash.finalize())

	# verify each domain
	for domain in domains:
		print("Verifying {0}...".format(domain))

		# get new challenge
		code, result = send_signed(account_key, CA, CA + "/acme/new-authz", header, {
			"resource": "new-authz",
			"identifier": {"type": "dns", "value": domain},
		})
		if code != 201:
			raise ValueError("Error requesting challenges: {0} {1}".format(code, result))

		# make the challenge file
		challenge = [c for c in json.loads(result.decode('utf8'))['challenges'] if c['type'] == "http-01"][0]
		token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
		keyauthorization = "{0}.{1}".format(token, account_thumbprint)
		wellknown_path = os.path.join(acme_dir, token)
		with open(wellknown_path, "w") as wellknown_file:
			wellknown_file.write(keyauthorization)

		# check that the file is in place
		wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(domain, token)
		try:
			resp = urlopen(wellknown_url)
			resp_data = resp.read().decode('utf8').strip()
			assert resp_data == keyauthorization
		except (IOError, AssertionError):
			os.remove(wellknown_path)
			raise ValueError("Wrote file to {0}, but couldn't download {1}".format(
				wellknown_path, wellknown_url))

		# notify challenge are met
		code, result = send_signed(account_key, CA, challenge['uri'], header, {
			"resource": "challenge",
			"keyAuthorization": keyauthorization,
		})
		if code != 202:
			raise ValueError("Error triggering challenge: {0} {1}".format(code, result))

		# wait for challenge to be verified
		while True:
			try:
				resp = urlopen(challenge['uri'])
				challenge_status = json.loads(resp.read().decode('utf8'))
			except IOError as e:
				raise ValueError("Error checking challenge: {0} {1}".format(
					e.code, json.loads(e.read().decode('utf8'))))
			if challenge_status['status'] == "pending":
				time.sleep(2)
			elif challenge_status['status'] == "valid":
				print("{0} verified!".format(domain))
				os.remove(wellknown_path)
				break
			else:
				raise ValueError("{0} challenge did not pass: {1}".format(
					domain, challenge_status))

	# get the new certificate
	print("Signing certificate...")
	csr_der = csr.public_bytes(serialization.Encoding.DER)
	code, result = send_signed(account_key, CA, CA + "/acme/new-cert", header, {
		"resource": "new-cert",
		"csr": base64_enc(csr_der),
	})
	if code != 201:
		raise ValueError("Error signing certificate: {0} {1}".format(code, result))

	# return signed certificate!
	print("Certificate signed!")
	cert = x509.load_der_x509_certificate(result, default_backend())
	return cert

