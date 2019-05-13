#!/usr/bin/env python
# -*- coding: utf-8 -*-

# authority - authority api package
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE

import importlib
import json
import os

from acertmgr import tools
from acertmgr.tools import log

authorities = dict()


# @brief find or create a suitable authority for the given settings
# @param settings the authority configuration options
def authority(settings):
    key = json.dumps(settings, sort_keys=True)
    if key in authorities:
        return authorities[key]
    else:
        acc_file = settings['account_key']
        if os.path.isfile(acc_file):
            log("Reading account key from {}".format(acc_file))
            acc_key = tools.read_pem_file(acc_file, key=True)
        else:
            log("Account key not found at '{0}'. Creating key.".format(acc_file))
            acc_key = tools.new_account_key(acc_file, settings['account_key_algorithm'], settings['account_key_length'])

        authority_module = importlib.import_module("acertmgr.authority.{0}".format(settings["api"]))
        authority_class = getattr(authority_module, "ACMEAuthority")
        authority_obj = authority_class(settings, acc_key)
        authorities[key] = authority_obj
        return authority_obj
