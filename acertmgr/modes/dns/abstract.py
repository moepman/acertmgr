#!/usr/bin/env python
# -*- coding: utf-8 -*-
# dns.nsupdate - rfc2136 based challenge handler
# Copyright (c) Rudolf Mayerhofer, 2018-2019
# available under the ISC license, see LICENSE

import dns
import dns.query
import dns.resolver
import dns.tsigkeyring
import dns.update
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from acertmgr import tools
from acertmgr.modes.abstract import AbstractChallengeHandler


class DNSChallengeHandler(AbstractChallengeHandler):
    @staticmethod
    def get_challenge_type():
        return "dns-01"

    def __init__(self, config):
        AbstractChallengeHandler.__init__(self, config)
        self.dns_updatedomain = config.get("dns_updatedomain")
        self.dns_ttl = int(config.get("dns_ttl",60))

    def _determine_challenge_domain(self, domain):
        if self.dns_updatedomain:
            domain = self.dns_updatedomain
        else:
            domain = "_acme-challenge.{0}".format(domain)

        domain = dns.name.from_text(domain)
        if not domain.is_absolute():
            domain = domain.concatenate(dns.name.root)

        return domain.to_text()

    @staticmethod
    def _determine_txtvalue(thumbprint, token):
        keyauthorization = "{0}.{1}".format(token, thumbprint)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(keyauthorization.encode('utf8'))
        return tools.to_json_base64(digest.finalize())

    def create_challenge(self, domain, thumbprint, token):
        domain = self._determine_challenge_domain(domain)
        txtvalue = self._determine_txtvalue(thumbprint, token)
        return self.add_dns_record(domain, txtvalue)

    def add_dns_record(self, domain, txtvalue):
        raise NotImplementedError

    def destroy_challenge(self, domain, thumbprint, token):
        domain = self._determine_challenge_domain(domain)
        txtvalue = self._determine_txtvalue(thumbprint, token)
        return self.remove_dns_record(domain, txtvalue)

    def remove_dns_record(self, domain, txtvalue):
        raise NotImplementedError
