#!/usr/bin/env python
# -*- coding: utf-8 -*-

# web - http based challenge handler
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE

import os

from acertmgr import tools
from acertmgr.modes.abstract import AbstractChallengeHandler


class HTTPChallengeHandler(AbstractChallengeHandler):
    @staticmethod
    def get_challenge_type():
        return "http-01"

    def __init__(self, config):
        AbstractChallengeHandler.__init__(self, config)
        self.http_verify = str(config.get("http_verify", "true")).lower() == "true"

    def create_challenge(self, domain, thumbprint, token):
        raise NotImplementedError

    def destroy_challenge(self, domain, thumbprint, token):
        raise NotImplementedError

    def start_challenge(self, domain, thumbprint, token):
        if self.http_verify:
            keyauthorization = "{0}.{1}".format(token, thumbprint)
            wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(domain, token)
            try:
                resp = tools.get_url(wellknown_url)
                resp_data = resp.read().decode('utf8').strip()
                if resp_data != keyauthorization:
                    raise ValueError("keyauthorization and response data do NOT match")
            except (IOError, ValueError):
                raise ValueError("keyauthorization verification failed")


class ChallengeHandler(HTTPChallengeHandler):
    def __init__(self, config):
        HTTPChallengeHandler.__init__(self, config)
        self.challenge_directory = config.get("webdir", "/var/www/acme-challenge/")
        if not os.path.isdir(self.challenge_directory):
            raise FileNotFoundError("Challenge directory (%s) does not exist!" % self.challenge_directory)

    def create_challenge(self, domain, thumbprint, token):
        keyauthorization = "{0}.{1}".format(token, thumbprint)
        wellknown_path = os.path.join(self.challenge_directory, token)
        with open(wellknown_path, "w") as wellknown_file:
            wellknown_file.write(keyauthorization)

    def destroy_challenge(self, domain, thumbprint, token):
        os.remove(os.path.join(self.challenge_directory, token))
