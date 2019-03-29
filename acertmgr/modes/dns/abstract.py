#!/usr/bin/env python
# -*- coding: utf-8 -*-
# dns.nsupdate - rfc2136 based challenge handler
# Copyright (c) Rudolf Mayerhofer, 2018-2019
# available under the ISC license, see LICENSE

import time
from datetime import datetime, timedelta

import dns
import dns.query
import dns.resolver
import dns.tsigkeyring
import dns.update

from acertmgr import tools
from acertmgr.modes.abstract import AbstractChallengeHandler


class DNSChallengeHandler(AbstractChallengeHandler):
    @staticmethod
    def _determine_txtvalue(thumbprint, token):
        return tools.bytes_to_base64url(tools.hash_of_str("{0}.{1}".format(token, thumbprint)))

    @staticmethod
    def get_challenge_type():
        return "dns-01"

    def __init__(self, config):
        AbstractChallengeHandler.__init__(self, config)
        self.dns_updatedomain = config.get("dns_updatedomain")
        self.dns_ttl = int(config.get("dns_ttl", 60))
        self.dns_verify_waittime = int(config.get("dns_verify_waittime", 2 * self.dns_ttl))
        self.dns_verify_failtime = int(config.get("dns_verify_failtime", self.dns_verify_waittime + 1))
        self.dns_verify_interval = int(config.get("dns_verify_interval", 10))

        self._valid_times = {}

    def _determine_challenge_domain(self, domain):
        if self.dns_updatedomain:
            domain = self.dns_updatedomain
        else:
            domain = "_acme-challenge.{0}".format(domain)

        domain = dns.name.from_text(domain)
        if not domain.is_absolute():
            domain = domain.concatenate(dns.name.root)

        return domain.to_text()

    def create_challenge(self, domain, thumbprint, token):
        domain = self._determine_challenge_domain(domain)
        txtvalue = self._determine_txtvalue(thumbprint, token)
        self.add_dns_record(domain, txtvalue)
        self._valid_times[domain] = datetime.now() + timedelta(seconds=self.dns_verify_waittime)

    def add_dns_record(self, domain, txtvalue):
        raise NotImplementedError

    def destroy_challenge(self, domain, thumbprint, token):
        domain = self._determine_challenge_domain(domain)
        txtvalue = self._determine_txtvalue(thumbprint, token)
        self.remove_dns_record(domain, txtvalue)

    def remove_dns_record(self, domain, txtvalue):
        raise NotImplementedError

    def start_challenge(self, domain, thumbprint, token):
        domain = self._determine_challenge_domain(domain)
        txtvalue = self._determine_txtvalue(thumbprint, token)
        failtime = datetime.now() + timedelta(seconds=self.dns_verify_failtime)
        if self.verify_dns_record(domain, txtvalue):
            return
        else:
            print("Waiting until TXT record '{}' is ready".format(domain))
            while failtime > datetime.now():
                time.sleep(self.dns_verify_interval)
                if self.verify_dns_record(domain, txtvalue):
                    return
            raise ValueError("DNS challenge is not ready after waiting {} seconds".format(self.dns_verify_waittime))

    def verify_dns_record(self, domain, txtvalue):
        if domain not in self._valid_times:
            return False
        return datetime.now() >= self._valid_times[domain]
