#!/usr/bin/env python
# -*- coding: utf-8 -*-

# abstract - abstract base classes for challenge handlers
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE


class AbstractChallengeHandler:
    def __init__(self, config):
        self.config = config

    @staticmethod
    def get_challenge_type():
        raise NotImplemented

    # @return datetime after which the challenge is valid
    def create_challenge(self, domain, thumbprint, token):
        raise NotImplemented

    def destroy_challenge(self, domain, thumbprint, token):
        raise NotImplemented

    # Optional: Indicate when a challenge request is imminent
    def start_challenge(self):
        pass

    # Optional: Indicate when a challenge response has been received
    def stop_challenge(self):
        pass
