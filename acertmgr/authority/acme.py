#!/usr/bin/env python
# -*- coding: utf-8 -*-

# acertmgr - generic acme api functions
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE


class ACMEAuthority:
    # @brief Init class with config
    # @param config Configuration data
    # @param key Account key data
    def __init__(self, config, key):
        self.key = key
        self.config = config

    # @brief register an account over ACME
    def register_account(self):
        raise NotImplementedError

    # @brief function to fetch certificate using ACME
    # @param csr the certificate signing request in pyopenssl format
    # @param domains list of domains in the certificate, first is CN
    # @param challenge_handlers a dict containing challenge for all given domains
    # @return the certificate
    def get_crt_from_csr(self, csr, domains, challenge_handlers):
        raise NotImplementedError

    # @brief function to revoke a certificate using ACME
    # @param crt certificate to revoke
    # @param reason (int) optional certificate revoke reason (see https://tools.ietf.org/html/rfc5280#section-5.3.1)
    def revoke_crt(self, crt, reason=None):
        raise NotImplementedError
