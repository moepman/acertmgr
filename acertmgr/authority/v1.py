#!/usr/bin/env python
# -*- coding: utf-8 -*-

# acertmgr - acme api v1 functions
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE

import copy
import datetime
import json
import re
import time

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from acertmgr import tools
from acertmgr.tools import byte_string_format

try:
    from urllib.request import urlopen  # Python 3
except ImportError:
    from urllib2 import urlopen  # Python 2

from acertmgr.authority.acme import ACMEAuthority as AbstractACMEAuthority


class ACMEAuthority(AbstractACMEAuthority):
    # @brief create the header information for ACME communication
    # @param key the account key
    # @return the header for ACME
    def _prepare_header(self):
        numbers = self.key.public_key().public_numbers()
        header = {
            "alg": "RS256",
            "jwk": {
                "e": tools.to_json_base64(byte_string_format(numbers.e)),
                "kty": "RSA",
                "n": tools.to_json_base64(byte_string_format(numbers.n)),
            },
        }
        return header

    # @brief helper function to make signed requests
    # @param url the request URL
    # @param header the message header
    # @param payload the message
    # @return tuple of return code and request answer
    def _send_signed(self, url, header, payload):
        payload64 = tools.to_json_base64(json.dumps(payload).encode('utf8'))
        protected = copy.deepcopy(header)
        protected["nonce"] = urlopen(self.ca + "/directory").headers['Replay-Nonce']
        protected64 = tools.to_json_base64(json.dumps(protected).encode('utf8'))
        # @todo check why this padding is not working
        # pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
        pad = padding.PKCS1v15()
        out = self.key.sign('.'.join([protected64, payload64]).encode('utf8'), pad, hashes.SHA256())
        data = json.dumps({
            "header": header, "protected": protected64,
            "payload": payload64, "signature": tools.to_json_base64(out),
        })
        try:
            resp = urlopen(url, data.encode('utf8'))
            return resp.getcode(), resp.read()
        except IOError as e:
            return getattr(e, "code", None), getattr(e, "read", e.__str__)()

    # @brief register an account over ACME
    # @return True if new account was registered, False otherwise
    def register_account(self):
        header = self._prepare_header()
        code, result = self._send_signed(self.ca + "/acme/new-reg", header, {
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

    # @brief function to fetch certificate using ACME
    # @param csr the certificate signing request in pyopenssl format
    # @param domains list of domains in the certificate, first is CN
    # @param challenge_handlers a dict containing challenge for all given domains
    # @return the certificate in pyopenssl format
    # @note algorithm and parts of the code are from acme-tiny
    def get_crt_from_csr(self, csr, domains, challenge_handlers):
        header = self._prepare_header()
        accountkey_json = json.dumps(header['jwk'], sort_keys=True, separators=(',', ':'))
        account_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        account_hash.update(accountkey_json.encode('utf8'))
        account_thumbprint = tools.to_json_base64(account_hash.finalize())

        challenges = dict()
        tokens = dict()
        valid_times = list()
        # verify each domain
        try:
            for domain in domains:
                print("Verifying {0}...".format(domain))

                # get new challenge
                code, result = self._send_signed(self.ca + "/acme/new-authz", header, {
                    "resource": "new-authz",
                    "identifier": {"type": "dns", "value": domain},
                })
                if code != 201:
                    raise ValueError("Error requesting challenges: {0} {1}".format(code, result))

                # create the challenge
                challenges[domain] = [c for c in json.loads(result.decode('utf8'))['challenges'] if
                                      c['type'] == challenge_handlers[domain].get_challenge_type()][0]
                tokens[domain] = re.sub(r"[^A-Za-z0-9_\-]", "_", challenges[domain]['token'])

                if domain not in challenge_handlers:
                    raise ValueError("No challenge handler given for domain: {0}".format(domain))

                valid_times.append(
                    challenge_handlers[domain].create_challenge(domain, account_thumbprint, tokens[domain]))

            print("Waiting until challenges are valid ({})".format(",".join([str(x) for x in valid_times])))
            for valid_time in valid_times:
                while datetime.datetime.now() < valid_time:
                    time.sleep(1)

            for domain in domains:
                challenge_handlers[domain].start_challenge()
                try:
                    print("Starting key authorization")
                    # notify challenge are met
                    keyauthorization = "{0}.{1}".format(tokens[domain], account_thumbprint)
                    code, result = self._send_signed(challenges[domain]['uri'], header, {
                        "resource": "challenge",
                        "keyAuthorization": keyauthorization,
                    })
                    if code != 202:
                        raise ValueError("Error triggering challenge: {0} {1}".format(code, result))

                    # wait for challenge to be verified
                    while True:
                        try:
                            resp = urlopen(challenges[domain]['uri'])
                            challenge_status = json.loads(resp.read().decode('utf8'))
                        except IOError as e:
                            raise ValueError("Error checking challenge: {0} {1}".format(
                                e.code, json.loads(e.read().decode('utf8'))))
                        if challenge_status['status'] == "pending":
                            time.sleep(2)
                        elif challenge_status['status'] == "valid":
                            print("{0} verified!".format(domain))
                            break
                        else:
                            raise ValueError("{0} challenge did not pass: {1}".format(
                                domain, challenge_status))
                finally:
                    challenge_handlers[domain].stop_challenge()
        finally:
            # Destroy challenge handlers in reverse order to replay
            # any saved state information in the handlers correctly
            for domain in reversed(domains):
                try:
                    challenge_handlers[domain].destroy_challenge(domain, account_thumbprint, tokens[domain])
                except:
                    pass

        # get the new certificate
        print("Signing certificate...")
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        code, result = self._send_signed(self.ca + "/acme/new-cert", header, {
            "resource": "new-cert",
            "csr": tools.to_json_base64(csr_der),
        })
        if code != 201:
            raise ValueError("Error signing certificate: {0} {1}".format(code, result))

        # return signed certificate!
        print("Certificate signed!")
        cert = x509.load_der_x509_certificate(result, default_backend())
        return cert
