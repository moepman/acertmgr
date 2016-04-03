#!/usr/bin/env python
# -*- coding: utf-8 -*-

# acertmgr - ssl management functions
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# available under the ISC license, see LICENSE

from OpenSSL import crypto
import base64
import binascii
import copy
import datetime
import hashlib
import json
import subprocess
import textwrap
import time
import os
import re
try:
	from urllib.request import urlopen # Python 3
except ImportError:
	from urllib2 import urlopen # Python 2

DEFAULT_CA = "https://acme-staging.api.letsencrypt.org"
#DEFAULT_CA = "https://acme-v01.api.letsencrypt.org"

# @brief retrieve notBefore and notAfter dates of a certificate file
# @param cert_file the path to the certificate
# @return the tuple of dates: (notBefore, notAfter)
def cert_valid_times(cert_file):
	with open(cert_file) as f:
		cert_data = f.read()
	cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
	asn1time = str('%Y%m%d%H%M%SZ'.encode('utf8'))
	not_before = datetime.datetime.strptime(str(cert.get_notBefore()), asn1time)
	not_after = datetime.datetime.strptime(str(cert.get_notAfter()), asn1time)
	return (not_before, not_after)

# @brief create a certificate signing request
# @param names list of domain names the certificate should be valid for
# @param key_data the key to use with the certificate in PEM format
# @return the CSR in PEM format
def cert_request(names, key_data):
	req = crypto.X509Req()
	req.get_subject().commonName = names[0]
	entries = ['DNS:'+name for name in names]
	extensions = [crypto.X509Extension('subjectAltName', False, ', '.join(entries))]
	req.add_extensions(extensions)
	key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_data)
	req.set_pubkey(key)
	req.sign(key, 'sha256')
	#return crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
	return req


# @brief helper function base64 encode for jose spec
# @param b the string to encode
# @return the encoded string
def base64_enc(b):
	return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

# @brief function to fetch certificate using ACME
# @param account_key_file the path to the account key
# @param csr the certificate signing request in pyopenssl format
# @param domains list of domains in the certificate, first is CN
# @param acme_dir directory for ACME challanges
# @param CA which signing CA to use
# @return the certificate in PEM format
# @note algorithm and parts of the code are from acme-tiny
def get_crt_from_csr(account_key_file, csr, domains, acme_dir, CA=DEFAULT_CA):
	print("Reading account key...")
	with open(account_key_file) as f:
		account_key_data = f.read()
	account_key = crypto.load_privatekey(crypto.FILETYPE_PEM, account_key_data)
	proc = subprocess.Popen(['openssl', 'rsa', '-modulus', '-noout', '-text'],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = proc.communicate(account_key_data)
	if proc.returncode != 0:
		raise IOError("OpenSSL Error: {0}".format(err))
	pub_exp, pub_hex = re.search(
		r"publicExponent: [0-9]+ \(0x([0-9A-F]+)\).+Modulus=([0-9A-F]+)",
		out.decode('utf8'), re.DOTALL).groups()
	pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
	header = {
		"alg": "RS256",
		"jwk": {
			"e": base64_enc(binascii.unhexlify(pub_exp.encode("utf-8"))),
			"kty": "RSA",
			"n": base64_enc(binascii.unhexlify(pub_hex.encode("utf-8"))),
		},
	}
	accountkey_json = json.dumps(header['jwk'], sort_keys=True, separators=(',', ':'))
	thumbprint = base64_enc(hashlib.sha256(accountkey_json.encode('utf8')).digest())

	# helper function make signed requests
	def _send_signed_request(url, payload):
		payload64 = base64_enc(json.dumps(payload).encode('utf8'))
		protected = copy.deepcopy(header)
		protected["nonce"] = urlopen(CA + "/directory").headers['Replay-Nonce']
		protected64 = base64_enc(json.dumps(protected).encode('utf8'))
		out = crypto.sign(account_key, '.'.join([protected64, payload64]), 'sha256')
		data = json.dumps({
			"header": header, "protected": protected64,
			"payload": payload64, "signature": base64_enc(out),
		})
		try:
			resp = urlopen(url, data.encode('utf8'))
			return resp.getcode(), resp.read()
		except IOError as e:
			return getattr(e, "code", None), getattr(e, "read", e.__str__)()

	code, result = _send_signed_request(CA + "/acme/new-reg", {
		"resource": "new-reg",
		"agreement": "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf",
	})
	if code == 201:
		print("Registered!")
	elif code == 409:
		print("Already registered!")
	else:
		raise ValueError("Error registering: {0} {1}".format(code, result))

	# verify each domain
	for domain in domains:
		print("Verifying {0}...".format(domain))

		# get new challenge
		code, result = _send_signed_request(CA + "/acme/new-authz", {
			"resource": "new-authz",
			"identifier": {"type": "dns", "value": domain},
		})
		if code != 201:
			raise ValueError("Error requesting challenges: {0} {1}".format(code, result))

		# make the challenge file
		challenge = [c for c in json.loads(result.decode('utf8'))['challenges'] if c['type'] == "http-01"][0]
		token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
		keyauthorization = "{0}.{1}".format(token, thumbprint)
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
		code, result = _send_signed_request(challenge['uri'], {
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
	csr_der = crypto.dump_certificate_request(crypto.FILETYPE_ASN1, csr)
	code, result = _send_signed_request(CA + "/acme/new-cert", {
		"resource": "new-cert",
		"csr": base64_enc(csr_der),
	})
	if code != 201:
		raise ValueError("Error signing certificate: {0} {1}".format(code, result))

	# return signed certificate!
	print("Certificate signed!")
	cert = crypto.load_certificate(crypto.FILETYPE_ASN1, result)
	return crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

