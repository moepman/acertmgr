#!/usr/bin/env python
# -*- coding: utf-8 -*-

# dns.nsupdate - rfc2136 based challenge handler
# Copyright (c) Rudolf Mayerhofer, 2019
# available under the ISC license, see LICENSE
import datetime
import ipaddress
import re
import socket
import io

import dns
import dns.query
import dns.resolver
import dns.tsigkeyring
import dns.update

from modes.dns.abstract import DNSChallengeHandler


DEFAULT_KEY_ALGORITHM = "HMAC-MD5.SIG-ALG.REG.INT"


class ChallengeHandler(DNSChallengeHandler):
    @staticmethod
    def _find_first_key_name(tsig_key_file):
        try:
            with io.open(tsig_key_file) as key_file:
                key_struct = key_file.read()
                return re.search(r"key \"?([^\"{ ]+?)\"? {.*};", key_struct, re.DOTALL).group(1)
        except IOError as exc:
            print(exc)
            raise Exception(
                "A problem was encountered opening your keyfile, %s." % tsig_key_file)
        except AttributeError as exc:
            print(exc)
            raise Exception("Failed to find first key name")

    @staticmethod
    def _read_tsigkey(tsig_key_file, key_name):
        try:
            with io.open(tsig_key_file) as key_file:
                key_struct = key_file.read()
                key_data = re.search(r"key \"?%s\"? {(.*?)};" % key_name, key_struct, re.DOTALL).group(1)
                algorithm = re.search(r"algorithm ([a-zA-Z0-9_-]+?);", key_data, re.DOTALL).group(1)
                tsig_secret = re.search(r"secret \"(.*?)\"", key_data, re.DOTALL).group(1)
        except IOError as exc:
            print(exc)
            raise Exception(
                "A problem was encountered opening your keyfile, %s." % tsig_key_file)
        except AttributeError as exc:
            print(exc)
            raise Exception("Unable to decipher the keyname and secret from your keyfile.")

        keyring = dns.tsigkeyring.from_text({
            key_name: tsig_secret
        })

        if not algorithm:
            algorithm = DEFAULT_KEY_ALGORITHM

        return keyring, algorithm

    @staticmethod
    def _lookup_dns_server(domain_or_ip):
        try:
            return str(ipaddress.ip_address(domain_or_ip))
        except ValueError:
            result = socket.getaddrinfo(domain_or_ip, 53)
            if len(result) > 0:
                return result[0][4][0]
            else:
                raise ValueError("Could not lookup dns ip for {}".format(domain_or_ip))

    @staticmethod
    def _get_soa(domain, nameserver=None):
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
                    response = dns.query.udp(request, nameserver)
                    if response.rcode() == dns.rcode.NOERROR:
                        for answer in response.answer:
                            for item in answer:
                                if item.rdtype == dns.rdatatype.SOA:
                                    zone = domain.to_text()
                                    authoritative_ns = item.mname.to_text().split(' ')[0]
                                    return zone, authoritative_ns
                    else:
                        break
                except dns.exception.Timeout:
                    # Go to next nameserver on timeout
                    continue
                except dns.exception.DNSException:
                    # Break loop on any other error
                    break
            domain = domain.parent()
        raise Exception('Could not find Zone SOA for "{0}"'.format(domain))

    @staticmethod
    def get_challenge_type():
        return "dns-01"

    def __init__(self, config):
        DNSChallengeHandler.__init__(self, config)
        if 'nsupdate_keyfile' in config:
            if 'nsupdate_keyname' in config:
                nsupdate_keyname = config.get("nsupdate_keyname")
            else:
                nsupdate_keyname = self._find_first_key_name(config.get("nsupdate_keyfile"))

            self.keyring, self.keyalgorithm = self._read_tsigkey(config.get("nsupdate_keyfile"), nsupdate_keyname)
        else:
            self.keyring = dns.tsigkeyring.from_text({
                config.get("nsupdate_keyname"): config.get("nsupdate_keyvalue")
            })
            self.keyalgorithm = config.get("nsupdate_keyalgorithm", DEFAULT_KEY_ALGORITHM)
        self.dns_server = config.get("nsupdate_server")
        self.dns_ttl = int(config.get("nsupdate_ttl", "60"))

    def _determine_zone_and_nameserverip(self, domain):
        nameserver = self.dns_server
        if nameserver:
            nameserverip = self._lookup_dns_server(nameserver)
            zone, _ = self._get_soa(domain, nameserverip)
        else:
            zone, nameserver = self._get_soa(domain)
            nameserverip = self._lookup_dns_server(nameserver)

        return zone, nameserverip

    def add_dns_record(self, domain, txtvalue):
        zone, nameserverip = self._determine_zone_and_nameserverip(domain)
        update = dns.update.Update(zone, keyring=self.keyring, keyalgorithm=self.keyalgorithm)
        update.add(domain, self.dns_ttl, 'TXT', txtvalue)
        print('Adding \'{} 60 IN TXT "{}"\' to {}'.format(domain, txtvalue, nameserverip))
        dns.query.tcp(update, nameserverip)
        return datetime.datetime.now() + datetime.timedelta(seconds=2 * self.dns_ttl)

    def remove_dns_record(self, domain, txtvalue):
        zone, nameserverip = self._determine_zone_and_nameserverip(domain)
        update = dns.update.Update(zone, keyring=self.keyring, keyalgorithm=self.keyalgorithm)
        update.delete(domain, dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, txtvalue))
        print('Deleting \'{} 60 IN TXT "{}"\' from {}'.format(domain, txtvalue, nameserverip))
        dns.query.tcp(update, nameserverip)
