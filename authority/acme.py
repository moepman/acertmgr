#!/usr/bin/env python
# -*- coding: utf-8 -*-

# acertmgr - generic acme api functions
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE


class ACMEAuthority:
    # @brief Init class with config
    # @param ca Certificate authority uri
    # @param account_key Account key file
    def __init__(self, ca, key):
        self.ca = ca
        self.key = key

    # @brief register an account over ACME
    # @param account_key the account key to register
    # @param CA the certificate authority to register with
    # @return True if new account was registered, False otherwise
    def register_account(self):
        raise NotImplementedError

    # @brief function to fetch certificate using ACME
    # @param account_key the account key in pyopenssl format
    # @param csr the certificate signing request in pyopenssl format
    # @param domains list of domains in the certificate, first is CN
    # @param challenge_handlers a dict containing challenge for all given domains
    # @param CA which signing CA to use
    # @return the certificate in pyopenssl format
    # @note algorithm and parts of the code are from acme-tiny
    def get_crt_from_csr(self, csr, domains, challenge_handlers):
        raise NotImplementedError
