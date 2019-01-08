#!/usr/bin/env python
# -*- coding: utf-8 -*-

# acertmgr - ssl management functions
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE

import tools
import base64
import copy
import json
import os
import re
import time

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

try:
    from urllib.request import urlopen  # Python 3
except ImportError:
    from urllib2 import urlopen  # Python 2


# @brief create the header information for ACME communication
# @param key the account key
# @return the header for ACME
def acme_header(key):
    numbers = key.public_key().public_numbers()
    header = {
        "alg": "RS256",
        "jwk": {
            "e": tools.to_json_base64(tools.byte_string_format(numbers.e)),
            "kty": "RSA",
            "n": tools.to_json_base64(tools.byte_string_format(numbers.n)),
        },
    }
    return header


# @brief register an account over ACME
# @param account_key the account key to register
# @param CA the certificate authority to register with
# @return True if new account was registered, False otherwise
def register_account(account_key, ca):
    header = acme_header(account_key)
    code, result = send_signed(account_key, ca, ca + "/acme/new-reg", header, {
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


# @brief helper function to make signed requests
# @param CA the certificate authority
# @param url the request URL
# @param header the message header
# @param payload the message
# @return tuple of return code and request answer
def send_signed(account_key, ca, url, header, payload):
    payload64 = tools.to_json_base64(json.dumps(payload).encode('utf8'))
    protected = copy.deepcopy(header)
    protected["nonce"] = urlopen(ca + "/directory").headers['Replay-Nonce']
    protected64 = tools.to_json_base64(json.dumps(protected).encode('utf8'))
    # @todo check why this padding is not working
    # pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    pad = padding.PKCS1v15()
    out = account_key.sign('.'.join([protected64, payload64]).encode('utf8'), pad, hashes.SHA256())
    data = json.dumps({
        "header": header, "protected": protected64,
        "payload": payload64, "signature": tools.to_json_base64(out),
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
def get_crt_from_csr(account_key, csr, domains, acme_dir, ca):
    header = acme_header(account_key)
    accountkey_json = json.dumps(header['jwk'], sort_keys=True, separators=(',', ':'))
    account_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    account_hash.update(accountkey_json.encode('utf8'))
    account_thumbprint = tools.to_json_base64(account_hash.finalize())

    # verify each domain
    for domain in domains:
        print("Verifying {0}...".format(domain))

        # get new challenge
        code, result = send_signed(account_key, ca, ca + "/acme/new-authz", header, {
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
        code, result = send_signed(account_key, ca, challenge['uri'], header, {
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
    code, result = send_signed(account_key, ca, ca + "/acme/new-cert", header, {
        "resource": "new-cert",
        "csr": tools.to_json_base64(csr_der),
    })
    if code != 201:
        raise ValueError("Error signing certificate: {0} {1}".format(code, result))

    # return signed certificate!
    print("Certificate signed!")
    cert = x509.load_der_x509_certificate(result, default_backend())
    return cert
