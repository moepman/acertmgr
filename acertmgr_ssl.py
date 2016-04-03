#!/usr/bin/env python
# -*- coding: utf-8 -*-

# acertmgr - ssl management functions
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# available under the ISC license, see LICENSE

from OpenSSL import crypto

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
	return crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)

