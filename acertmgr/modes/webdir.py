#!/usr/bin/env python
# -*- coding: utf-8 -*-

# web - http based challenge handler
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE

import datetime
import os

from modes.abstract import AbstractChallengeHandler

try:
    from urllib.request import urlopen  # Python 3
except ImportError:
    from urllib2 import urlopen  # Python 2


class ChallengeHandler(AbstractChallengeHandler):
    def __init__(self, config):
        AbstractChallengeHandler.__init__(self, config)
        self.challenge_directory = config.get("webdir", "/var/www/acme-challenge/")
        if not os.path.isdir(self.challenge_directory):
            raise FileNotFoundError("Challenge directory (%s) does not exist!" % self.challenge_directory)

    @staticmethod
    def get_challenge_type():
        return "http-01"

    def create_challenge(self, domain, thumbprint, token):
        keyauthorization = "{0}.{1}".format(token, thumbprint)
        wellknown_path = os.path.join(self.challenge_directory, token)
        with open(wellknown_path, "w") as wellknown_file:
            wellknown_file.write(keyauthorization)

        # check that the file is in place
        wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(domain, token)
        try:
            resp = urlopen(wellknown_url)
            resp_data = resp.read().decode('utf8').strip()
            assert resp_data == keyauthorization
        except (IOError, AssertionError):
            os.remove(wellknown_path)
            raise ValueError("Wrote file to {0}, but couldn't download {1}".format(
                wellknown_path, wellknown_url))
        return datetime.datetime.now()

    def destroy_challenge(self, domain, thumbprint, token):
        os.remove(os.path.join(self.challenge_directory, token))
