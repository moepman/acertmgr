#!/usr/bin/env python
# -*- coding: utf-8 -*-
# dns.nsupdate - rfc2136 based challenge handler
# Copyright (c) Rudolf Mayerhofer, 2018-2019
# available under the ISC license, see LICENSE

import ipaddress
import re
import socket
import time
from datetime import datetime, timedelta

import dns
import dns.query
import dns.resolver
import dns.tsigkeyring
import dns.update

from acertmgr import tools
from acertmgr.modes.abstract import AbstractChallengeHandler
from acertmgr.tools import log

QUERY_TIMEOUT = 60  # seconds are the maximum for any query (otherwise the DNS server will be considered dead)
REGEX_IP4 = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
REGEX_IP6 = r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}' \
            r':|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}' \
            r'(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}' \
            r'|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}' \
            r'(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})' \
            r'|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}' \
            r'|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}' \
            r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}' \
            r':((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'
_lookup_ip_cache = {}
_lookup_ns_ip_cache = {}
_lookup_zone_cache = {}


class DNSChallengeHandler(AbstractChallengeHandler):
    @staticmethod
    def _lookup_ip(domain_or_ip):
        if domain_or_ip in _lookup_ip_cache:
            return _lookup_ip_cache[domain_or_ip]

        try:
            if re.search(REGEX_IP4, domain_or_ip.strip()) or re.search(REGEX_IP6, domain_or_ip.strip()):
                return str(ipaddress.ip_address(domain_or_ip))
        except ValueError:
            pass
        # No valid ip found so far, try to resolve using system resolver
        result = socket.getaddrinfo(domain_or_ip, 53)
        if len(result) > 0:
            retval = result[0][4][0]
            _lookup_ip_cache[domain_or_ip] = retval
            return retval
        else:
            raise ValueError("Could not lookup dns ip for {}".format(domain_or_ip))

    @staticmethod
    def _lookup_ns_ip(domain, nameserver=None):
        zone, zonemaster = DNSChallengeHandler._lookup_zone(domain, nameserver)
        cache_key = "{}${}".format(zone, zonemaster)
        if cache_key in _lookup_ns_ip_cache:
            return _lookup_ns_ip_cache[cache_key]

        if not nameserver:
            nameserver = DNSChallengeHandler._lookup_ip(zonemaster)

        request = dns.message.make_query(zone, dns.rdatatype.NS)
        response = dns.query.udp(request, nameserver, timeout=QUERY_TIMEOUT)
        retval = set()
        if response.rcode() == dns.rcode.NOERROR:
            for answer in response.answer:
                for item in answer:
                    if item.rdtype == dns.rdatatype.NS:
                        retval.add(DNSChallengeHandler._lookup_ip(item.to_text()))
            _lookup_ns_ip_cache[cache_key] = retval
        return retval

    @staticmethod
    def _lookup_zone(domain, nameserver=None):
        cache_key = "{}${}".format(domain, nameserver)
        if cache_key in _lookup_zone_cache:
            return _lookup_zone_cache[cache_key]

        if nameserver:
            nameservers = [nameserver]
        else:
            nameservers = dns.resolver.get_default_resolver().nameservers

        domain = dns.name.from_text(domain)
        if not domain.is_absolute():
            domain = domain.concatenate(dns.name.root)

        while domain.parent() != dns.name.root:
            request = dns.message.make_query(domain, dns.rdatatype.SOA)
            for nameserver in nameservers:
                try:
                    response = dns.query.udp(request, nameserver, timeout=QUERY_TIMEOUT)
                    if response.rcode() == dns.rcode.NOERROR:
                        for answer in response.answer:
                            for item in answer:
                                if item.rdtype == dns.rdatatype.SOA:
                                    zone = domain.to_text()
                                    authoritative_ns = item.mname.to_text().split(' ')[0]
                                    retval = zone, authoritative_ns
                                    _lookup_zone_cache[cache_key] = retval
                                    return retval
                    else:
                        break
                except dns.exception.Timeout:
                    # Go to next nameserver on timeout
                    continue
                except dns.exception.DNSException:
                    # Break loop on any other error
                    break
            domain = domain.parent()
        raise ValueError('No zone SOA for "{0}"'.format(domain))

    @staticmethod
    def _check_txt_record_value(domain, txtvalue, nameserverip, use_tcp=False):
        try:
            request = dns.message.make_query(domain, dns.rdatatype.TXT)
            if use_tcp:
                response = dns.query.tcp(request, nameserverip, timeout=QUERY_TIMEOUT)
            else:
                response = dns.query.udp(request, nameserverip, timeout=QUERY_TIMEOUT)
            for rrset in response.answer:
                for answer in rrset:
                    if answer.to_text().strip('"') == txtvalue:
                        return True
        except dns.exception.DNSException:
            # Ignore DNS errors and return failure
            return False

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
        self.dns_verify_all_ns = str(config.get("dns_verify_all_ns")).lower() == "true"
        self.dns_verify_server = config.get("dns_verify_server")

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
            log("Waiting until TXT record '{}' is ready".format(domain))
            while failtime > datetime.now():
                time.sleep(self.dns_verify_interval)
                if self.verify_dns_record(domain, txtvalue):
                    return
            raise ValueError("DNS challenge is not ready after waiting {} seconds".format(self.dns_verify_waittime))

    def verify_dns_record(self, domain, txtvalue):
        if self.dns_verify_all_ns:
            try:
                nameserverip = None
                if self.dns_verify_server:
                    # Use the specific dns server to determine NS for domain, will otherwise default to SOA master
                    nameserverip = self._lookup_ip(self.dns_verify_server)
                ns_ip = self._lookup_ns_ip(domain, nameserverip)
                if len(ns_ip) > 0 and all(self._check_txt_record_value(domain, txtvalue, ip) for ip in ns_ip):
                    # All NS servers have the necessary TXT record. Succeed immediately!
                    log("All NS ({}) for '{}' have the correct TXT record".format(','.join(ns_ip), domain))
                    return True
            except (ValueError, dns.exception.DNSException):
                # Fall back to next verification
                pass

        if self.dns_verify_server and not self.dns_verify_all_ns:
            try:
                # Verify using specific dns server
                nameserverip = self._lookup_ip(self.dns_verify_server)
                if self._check_txt_record_value(domain, txtvalue, nameserverip):
                    # Verify server confirms the necessary TXT record. Succeed immediately!
                    log("DNS server '{}' found correct TXT record for '{}'".format(self.dns_verify_server, domain))
                    return True
            except (ValueError, dns.exception.DNSException):
                # Fall back to next verification
                pass

        if domain not in self._valid_times:
            # No valid wait time for domain. Verification fails!
            return False
        # Verification fails or succeeds based on valid wait time set by add_dns_record
        return datetime.now() >= self._valid_times[domain]
