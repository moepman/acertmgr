#!/usr/bin/env python
# -*- coding: utf-8 -*-

# acertmgr - acme api v1 functions
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE

import copy
import json
import re
import time

from acertmgr import tools
from acertmgr.authority.acme import ACMEAuthority as AbstractACMEAuthority
from acertmgr.tools import log


class ACMEAuthority(AbstractACMEAuthority):
    # @brief Init class with config
    # @param config Configuration data
    # @param key Account key data
    def __init__(self, config, key):
        log('You currently use ACMEv1 which is deprecated, consider using ACMEv2 (RFC8555) if at all possible.',
            warning=True)
        AbstractACMEAuthority.__init__(self, config, key)
        self.registered_account = False
        self.ca = config['authority']
        self.agreement = config['authority_tos_agreement']

    # @brief create the header information for ACME communication
    # @param key the account key
    # @return the header for ACME
    def _prepare_header(self):
        alg, jwk = tools.get_key_alg_and_jwk(self.key)
        header = {
            "alg": alg,
            "jwk": jwk,
        }
        return header

    # @brief helper function to make signed requests
    # @param url the request URL
    # @param header the message header
    # @param payload the message
    # @return tuple of return code and request answer
    def _send_signed(self, url, header, payload):
        payload64 = tools.bytes_to_base64url(json.dumps(payload).encode('utf8'))
        protected = copy.deepcopy(header)
        protected["nonce"] = tools.get_url(self.ca + "/directory").headers['Replay-Nonce']
        protected64 = tools.bytes_to_base64url(json.dumps(protected).encode('utf8'))
        out = tools.signature_of_str(self.key, '.'.join([protected64, payload64]))
        data = json.dumps({
            "header": header, "protected": protected64,
            "payload": payload64, "signature": tools.bytes_to_base64url(out),
        })
        try:
            resp = tools.get_url(url, data.encode('utf8'))
            return resp.getcode(), resp.read()
        except IOError as e:
            return getattr(e, "code", None), getattr(e, "read", e.__str__)()

    # @brief register an account over ACME
    # @return True if new account was registered, False otherwise
    def register_account(self):
        if self.registered_account:
            # We already have registered with this authority, just return
            return

        header = self._prepare_header()
        code, result = self._send_signed(self.ca + "/acme/new-reg", header, {
            "resource": "new-reg",
            "agreement": self.agreement,
        })
        if code == 201:
            log("Registered!")
            self.registered_account = True
            return True
        elif code == 409:
            log("Already registered!")
            self.registered_account = True
            return False
        else:
            raise ValueError("Error registering: {0} {1}".format(code, result))

    # @brief function to fetch certificate using ACME
    # @param csr the certificate signing request in pyopenssl format
    # @param domains list of domains in the certificate, first is CN
    # @param challenge_handlers a dict containing challenge for all given domains
    # @return the certificate and corresponding ca as a tuple
    # @note algorithm and parts of the code are from acme-tiny
    def get_crt_from_csr(self, csr, domains, challenge_handlers):
        header = self._prepare_header()
        account_thumbprint = tools.bytes_to_base64url(
            tools.hash_of_str(json.dumps(header['jwk'], sort_keys=True, separators=(',', ':'))))

        challenges = dict()
        tokens = dict()
        authdomains = list()
        # verify each domain
        try:
            for domain in domains:
                log("Verifying {0}...".format(domain))

                # get new challenge
                code, result = self._send_signed(self.ca + "/acme/new-authz", header, {
                    "resource": "new-authz",
                    "identifier": {"type": "dns", "value": domain},
                })
                if code != 201:
                    raise ValueError("Error requesting challenges: {0} {1}".format(code, result))

                # create the challenge
                authz = json.loads(result.decode('utf8'))
                if authz.get('status', 'no-status-found') == 'valid':
                    log("{} has already been verified".format(domain))
                    continue
                challenges[domain] = [c for c in authz['challenges'] if
                                      c['type'] == challenge_handlers[domain].get_challenge_type()][0]
                tokens[domain] = re.sub(r"[^A-Za-z0-9_\-]", "_", challenges[domain]['token'])

                if domain not in challenge_handlers:
                    raise ValueError("No challenge handler given for domain: {0}".format(domain))

                challenge_handlers[domain].create_challenge(domain, account_thumbprint, tokens[domain])
                authdomains.append(domain)

            # after all challenges are created, start processing authorizations
            for domain in authdomains:
                try:
                    challenge_handlers[domain].start_challenge(domain, account_thumbprint, tokens[domain])
                    # notify challenge are met
                    log("Starting key authorization")
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
                            resp = tools.get_url(challenges[domain]['uri'])
                            challenge_status = json.loads(resp.read().decode('utf8'))
                        except IOError as e:
                            raise ValueError("Error checking challenge: {0} {1}".format(
                                e.code, json.loads(e.read().decode('utf8'))))
                        if challenge_status['status'] == "pending":
                            time.sleep(2)
                        elif challenge_status['status'] == "valid":
                            log("{0} verified!".format(domain))
                            break
                        else:
                            raise ValueError("{0} challenge did not pass: {1}".format(
                                domain, challenge_status))
                finally:
                    challenge_handlers[domain].stop_challenge(domain, account_thumbprint, tokens[domain])
        finally:
            # Destroy challenge handlers in reverse order to replay
            # any saved state information in the handlers correctly
            for domain in reversed(domains):
                try:
                    challenge_handlers[domain].destroy_challenge(domain, account_thumbprint, tokens[domain])
                except Exception as e:
                    log('Challenge destruction failed: {}'.format(e), error=True)

        # get the new certificate
        log("Signing certificate...")
        code, result = self._send_signed(self.ca + "/acme/new-cert", header, {
            "resource": "new-cert",
            "csr": tools.bytes_to_base64url(tools.convert_cert_to_der_bytes(csr)),
        })
        if code != 201:
            raise ValueError("Error signing certificate: {0} {1}".format(code, result))

        # return signed certificate!
        log("Certificate signed!")
        cert = tools.convert_der_bytes_to_cert(result)
        return cert, tools.download_issuer_ca(cert)

    # @brief function to revoke a certificate using ACME
    # @param crt certificate to revoke
    # @param reason (int) optional certificate revoke reason (see https://tools.ietf.org/html/rfc5280#section-5.3.1)
    def revoke_crt(self, crt, reason=None):
        header = self._prepare_header()
        payload = {"resource": "revoke-cert",
                   "certificate": tools.bytes_to_base64url(tools.convert_cert_to_der_bytes(crt))}
        if reason:
            payload['reason'] = int(reason)
        code, result = self._send_signed(self.ca + "/acme/revoke-cert", header, payload)
        if code < 400:
            log("Revocation successful")
        else:
            raise ValueError("Revocation failed: {}".format(result))
