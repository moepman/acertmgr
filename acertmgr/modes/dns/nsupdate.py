#!/usr/bin/env python
# -*- coding: utf-8 -*-

# dns.nsupdate - rfc2136 based challenge handler
# Copyright (c) Rudolf Mayerhofer, 2019
# available under the ISC license, see LICENSE
import io
import re

import dns
import dns.query
import dns.tsigkeyring
import dns.update

from acertmgr.modes.dns.abstract import DNSChallengeHandler, QUERY_TIMEOUT
from acertmgr.tools import log

DEFAULT_KEY_ALGORITHM = "HMAC-MD5.SIG-ALG.REG.INT"


class ChallengeHandler(DNSChallengeHandler):
    @staticmethod
    def _read_tsigkey(tsig_key_file, key_name=None):
        try:
            with io.open(tsig_key_file) as key_file:
                key_struct = key_file.read()
                if not key_name:
                    key_name = re.search(r"key \"?([^\"{ ]+?)\"? {.*};", key_struct, re.DOTALL).group(1)
                key_data = re.search(r"key \"?%s\"? {(.*?)};" % key_name, key_struct, re.DOTALL).group(1)
                algorithm = re.search(r"algorithm ([a-zA-Z0-9_-]+?);", key_data, re.DOTALL).group(1)
                tsig_secret = re.search(r"secret \"(.*?)\"", key_data, re.DOTALL).group(1)
        except IOError as exc:
            raise ValueError("A problem was encountered opening your keyfile '{}': {}".format(tsig_key_file, exc))
        except AttributeError as exc:
            raise ValueError("Unable to decipher data from your keyfile: {}".format(exc))

        keyring = dns.tsigkeyring.from_text({
            key_name: tsig_secret
        })

        if not algorithm:
            algorithm = DEFAULT_KEY_ALGORITHM

        return keyring, algorithm

    def __init__(self, config):
        DNSChallengeHandler.__init__(self, config)
        if 'nsupdate_keyfile' in config:
            nsupdate_keyname = config.get("nsupdate_keyname", None)
            self.keyring, self.keyalgorithm = self._read_tsigkey(config.get("nsupdate_keyfile"), nsupdate_keyname)
        else:
            self.keyring = dns.tsigkeyring.from_text({
                config.get("nsupdate_keyname"): config.get("nsupdate_keyvalue")
            })
            self.keyalgorithm = config.get("nsupdate_keyalgorithm", DEFAULT_KEY_ALGORITHM)
        self.nsupdate_server = config.get("nsupdate_server")
        self.nsupdate_verify = config.get("nsupdate_verify", "true") == "true"
        self.nsupdate_verified = False

    def _determine_zone_and_nameserverip(self, domain):
        nameserver = self.nsupdate_server
        if nameserver:
            nameserverip = self._lookup_ip(nameserver)
            zone, _ = self._lookup_zone(domain, nameserverip)
        else:
            zone, nameserver = self._lookup_zone(domain)
            nameserverip = self._lookup_ip(nameserver)
        return zone, nameserverip

    def add_dns_record(self, domain, txtvalue):
        zone, nameserverip = self._determine_zone_and_nameserverip(domain)
        update = dns.update.Update(zone, keyring=self.keyring, keyalgorithm=self.keyalgorithm)
        update.add(domain, self.dns_ttl, dns.rdatatype.TXT, txtvalue)
        log('Adding \'{} {} IN TXT "{}"\' to {}'.format(domain, self.dns_ttl, txtvalue, nameserverip))
        dns.query.tcp(update, nameserverip, timeout=QUERY_TIMEOUT)

    def remove_dns_record(self, domain, txtvalue):
        zone, nameserverip = self._determine_zone_and_nameserverip(domain)
        update = dns.update.Update(zone, keyring=self.keyring, keyalgorithm=self.keyalgorithm)
        update.delete(domain, dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, txtvalue))
        log('Deleting \'{} {} IN TXT "{}"\' from {}'.format(domain, self.dns_ttl, txtvalue, nameserverip))
        dns.query.tcp(update, nameserverip, timeout=QUERY_TIMEOUT)

    def verify_dns_record(self, domain, txtvalue):
        if self.nsupdate_verify and not self.dns_verify_all_ns and not self.nsupdate_verified:
            # Verify master DNS only if we don't do a full NS check and it has not yet been verified
            _, nameserverip = self._determine_zone_and_nameserverip(domain)
            if self._check_txt_record_value(domain, txtvalue, nameserverip, use_tcp=True):
                log('Verified \'{} {} IN TXT "{}"\' on {}'.format(domain, self.dns_ttl, txtvalue, nameserverip))
                self.nsupdate_verified = True
            else:
                # Master DNS verification failed. Return immediately and try again.
                return False

        return DNSChallengeHandler.verify_dns_record(self, domain, txtvalue)
