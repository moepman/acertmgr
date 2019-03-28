#!/usr/bin/env python
# -*- coding: utf-8 -*-

# modes - challenge handler modes package
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE

import importlib
import json

challenge_handlers = dict()


# @brief find or create a challenge handler for the given settings
# @param settings the domain's configuration options
def challenge_handler(settings):
    key = json.dumps(settings, sort_keys=True)
    if key in challenge_handlers:
        return challenge_handlers[key]
    else:
        if "mode" in settings:
            mode = settings["mode"]
        else:
            mode = "standalone"

        handler_module = importlib.import_module("acertmgr.modes.{0}".format(mode))
        handler_class = getattr(handler_module, "ChallengeHandler")
        handler_obj = handler_class(settings)
        challenge_handlers[key] = handler_obj
        return handler_obj
