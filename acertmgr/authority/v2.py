#!/usr/bin/env python
# -*- coding: utf-8 -*-

# acertmgr - acme api v2 functions
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
from acertmgr.authority.acme import ACMEAuthority as AbstractACMEAuthority
from acertmgr.tools import byte_string_format

try:
    from urllib.request import urlopen, Request  # Python 3
except ImportError:
    from urllib2 import urlopen, Request  # Python 2


class ACMEAuthority(AbstractACMEAuthority):
    # @brief Init class with config
    # @param config Configuration data
    # @param key Account key data
    def __init__(self, config, key):
        AbstractACMEAuthority.__init__(self, config, key)
        # Initialize config vars
        self.ca = config['authority']
        self.agreement = str(config.get('authority_agreement')) == 'true'
        contact_email = config.get('authority_contact_email')
        if contact_email is None:
            self.contact = None
        elif isinstance(contact_email, list):
            self.contact = ["mailto:{}".format(contact) for contact in contact_email]
        else:
            self.contact = ["mailto:{}".format(contact_email)]

        # Initialize runtime vars
        _, self.directory, _ = self._request_url(self.ca + '/directory')
        self._request_endpoint('newNonce')  # cache the first nonce

        # @todo: Add support for key-types other than RSA
        numbers = key.public_key().public_numbers()
        self.algorithm = "RS256"
        self.account_protected = {
            "alg": self.algorithm,
            "jwk": {
                "kty": "RSA",
                "e": tools.to_json_base64(byte_string_format(numbers.e)),
                "n": tools.to_json_base64(byte_string_format(numbers.n)),
            },
        }
        self.account_id = None  # will be updated to correct value during account registration

    # @brief fetch a given url
    def _request_url(self, url, data=None, raw_result=False):
        header = {'Content-Type': 'application/jose+json'}
        if data:
            data = data.encode('utf-8')

        resp = urlopen(Request(url, data=data, headers=header))
        if raw_result:
            return resp.getcode(), resp.read(), resp.headers

        body = resp.read()
        if len(body) > 0:
            try:
                body = json.loads(body.decode('utf-8'))
            except json.JSONDecodeError as e:
                raise ValueError('Could not parse non-raw result (expected JSON)', e)
        # Store next Replay-Nonce if it is in the header
        if 'Replay-Nonce' in resp.headers:
            self.nonce = resp.headers['Replay-Nonce']

        return resp.getcode(), body, resp.headers

    # @brief helper function to make signed requests
    def _request_acme_url(self, url, payload=None, protected=None, raw_result=False):
        if not payload:
            payload = {}
        if not protected:
            protected = {}
        payload64 = tools.to_json_base64(json.dumps(payload).encode('utf8'))

        # Request a new nonce if there is none in cache
        if not self.nonce:
            self._request_endpoint('newNonce')

        protected["nonce"] = self.nonce
        protected["url"] = url
        if self.algorithm:
            protected["alg"] = self.algorithm
        if self.account_id:
            protected["kid"] = self.account_id
        protected64 = tools.to_json_base64(json.dumps(protected).encode('utf8'))
        pad = padding.PKCS1v15()
        out = self.key.sign('.'.join([protected64, payload64]).encode('utf8'), pad, hashes.SHA256())
        data = json.dumps({
            "protected": protected64,
            "payload": payload64,
            "signature": tools.to_json_base64(out),
        })
        try:
            return self._request_url(url, data, raw_result)
        except IOError as e:
            return getattr(e, "code", None), getattr(e, "read", e.__str__)(), {}
        finally:
            # Dispose of nonce after it was used
            self.nonce = None

    # @brief send a request to authority
    def _request_endpoint(self, request, data=None, raw_result=False):
        return self._request_url(self.directory[request], data, raw_result)

    # @brief send a signed request to authority
    def _request_acme_endpoint(self, request, payload=None, protected=None, raw_result=False):
        return self._request_acme_url(self.directory[request], payload, protected, raw_result)

    # @brief register an account over ACME
    def register_account(self):
        protected = copy.deepcopy(self.account_protected)
        payload = {
            "termsOfServiceAgreed": self.agreement,
            "onlyReturnExisting": False,
        }
        if self.contact:
            payload["contact"] = self.contact
        code, result, headers = self._request_acme_endpoint("newAccount", payload, protected)
        if code < 400 and result['status'] == 'valid':
            self.account_id = headers['Location']
            if 'meta' in self.directory and 'termsOfService' in self.directory['meta']:
                print("ToS at {} have been accepted.".format(self.directory['meta']['termsOfService']))
            print("Account registered and valid.".format())
        else:
            raise ValueError("Error registering account: {0} {1}".format(code, result))

    # @brief function to fetch certificate using ACME
    # @param csr the certificate signing request in pyopenssl format
    # @param domains list of domains in the certificate, first is CN
    # @param challenge_handlers a dict containing challenge for all given domains
    # @return the certificate
    # @note algorithm and parts of the code are from acme-tiny
    def get_crt_from_csr(self, csr, domains, challenge_handlers):
        accountkey_json = json.dumps(self.account_protected['jwk'], sort_keys=True, separators=(',', ':'))
        account_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        account_hash.update(accountkey_json.encode('utf8'))
        account_thumbprint = tools.to_json_base64(account_hash.finalize())

        print("Ordering certificate for {}".format(domains))
        identifiers = [{'type': 'dns', 'value': domain} for domain in domains]
        code, order, headers = self._request_acme_endpoint('newOrder', {'identifiers': identifiers})
        if code >= 400:
            raise ValueError("Error with certificate order: {0} {1}".format(code, order))

        order_url = headers['Location']
        authorizations = list()
        # verify each domain
        try:
            valid_times = list()
            for authorizationUrl in order['authorizations']:
                # get new challenge
                code, authorization, _ = self._request_url(authorizationUrl)
                if code >= 400:
                    raise ValueError("Error requesting authorization: {0} {1}".format(code, authorization))

                authorization['_domain'] = \
                    "*.{}".format(authorization['identifier']['value']) \
                        if 'wildcard' in authorization and authorization['wildcard'] \
                        else authorization['identifier']['value']
                print("Authorizing {0}".format(authorization['_domain']))

                # create the challenge
                matching_challenges = [c for c in authorization['challenges'] if
                                       c['type'] == challenge_handlers[authorization['_domain']].get_challenge_type()]
                if len(matching_challenges) == 0:
                    raise ValueError("Error no challenge matching {0} found: {1}".format(
                        challenge_handlers[authorization['_domain']].get_challenge_type(), authorization))
                authorization['_challenge'] = matching_challenges[0]
                authorization['_token'] = re.sub(r"[^A-Za-z0-9_\-]", "_", authorization['_challenge']['token'])

                if authorization['_domain'] not in challenge_handlers:
                    raise ValueError("No challenge handler given for domain: {0}".format(authorization['_domain']))

                valid_times.append(
                    challenge_handlers[authorization['_domain']].create_challenge(authorization['identifier']['value'],
                                                                                  account_thumbprint,
                                                                                  authorization['_token']))
                authorizations.append(authorization)

            print("Waiting until challenges are valid ({})".format(",".join([str(x) for x in valid_times])))
            for valid_time in valid_times:
                while datetime.datetime.now() < valid_time:
                    time.sleep(1)

            for authorization in authorizations:
                print("Starting verification of {}".format(authorization['_domain']))
                challenge_handlers[authorization['_domain']].start_challenge()
                try:
                    # notify challenge is met
                    code, challenge_status, _ = self._request_acme_url(authorization['_challenge']['url'], {
                        "keyAuthorization": "{0}.{1}".format(authorization['_token'], account_thumbprint),
                    })
                    # wait for challenge to be verified
                    while code < 400 and challenge_status.get('status') == "pending":
                        time.sleep(5)
                        code, challenge_status, _ = self._request_url(authorization['_challenge']['url'])

                    if challenge_status.get('status') == "valid":
                        print("{0} verified".format(authorization['_domain']))
                    else:
                        raise ValueError("{0} challenge did not pass: {1}".format(
                            authorization['_domain'], challenge_status))
                finally:
                    challenge_handlers[authorization['_domain']].stop_challenge()
        finally:
            # Destroy challenge handlers in reverse order to replay
            # any saved state information in the handlers correctly
            for authorization in reversed(authorizations):
                try:
                    challenge_handlers[authorization['_domain']].destroy_challenge(
                        authorization['identifier']['value'], account_thumbprint, authorization['_token'])
                except (KeyboardInterrupt, SystemError, SystemExit):
                    # Re-raise runtime/system exceptions
                    raise
                except:
                    pass

        # check order status and retry once
        code, order, _ = self._request_url(order_url)
        if code < 400 and order.get('status') == 'pending':
            time.sleep(5)
            code, order, _ = self._request_url(order_url)
        if code >= 400:
            raise ValueError("Order is still pending: {0} {1}".format(code, order))

        # get the new certificate
        print("Finalizing certificate")
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        code, finalize, _ = self._request_acme_url(order['finalize'], {
            "csr": tools.to_json_base64(csr_der),
        })
        while code < 400 and (finalize.get('status') == 'pending' or finalize.get('status') == 'processing'):
            time.sleep(5)
            code, finalize, _ = self._request_url(order_url)
        if code >= 400:
            raise ValueError("Error finalizing certificate: {0} {1}".format(code, finalize))
        print("Certificate ready!")

        # return certificate
        code, certificate, _ = self._request_url(finalize['certificate'], raw_result=True)
        if code >= 400:
            raise ValueError("Error downloading certificate: {0} {1}".format(code, certificate))
        cert = x509.load_pem_x509_certificate(certificate, default_backend())
        return cert