#!/usr/bin/env python
# -*- coding: utf-8 -*-

# config - acertmgr config parser
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE

import copy
import io
import os

from acertmgr import tools

ACME_DIR = "/etc/acme"
ACME_CONF = os.path.join(ACME_DIR, "acme.conf")
ACME_CONFD = os.path.join(ACME_DIR, "domains.d")

ACME_DEFAULT_ACCOUNT_KEY = os.path.join(ACME_DIR, "account.key")
ACME_DEFAULT_KEY_LENGTH = 4096  # bits
ACME_DEFAULT_TTL = 15  # days


# @brief augment configuration with defaults
# @param domainconfig the domain configuration
# @param defaults the default configuration
# @return the augmented configuration
def complete_action_config(domainconfig, config):
    defaults = config['defaults']
    domainconfig['ca_file'] = config['ca_file']
    domainconfig['cert_file'] = config['cert_file']
    domainconfig['key_file'] = config['key_file']
    for name, value in defaults.items():
        if name not in domainconfig:
            domainconfig[name] = value
    if 'action' not in domainconfig:
        domainconfig['action'] = None
    return domainconfig


# @brief load the configuration from a file
def parse_config_entry(entry, globalconfig):
    config = dict()

    # Basic domain information
    config['domains'], data = entry
    config['domainlist'] = config['domains'].split(' ')
    config['id'] = tools.to_unique_id(config['domains'])

    # Defaults
    config['defaults'] = globalconfig.get('defaults', {})

    # API version
    apis = [x for x in entry if 'api' in x]
    if len(apis) > 0:
        config['api'] = apis[0]

    # Certificate authority
    authorities = [x for x in entry if 'authority' in x]
    if len(authorities) > 0:
        config['authority'] = authorities[0]
    else:
        config['authority'] = globalconfig.get('authority')

    # Account key
    acc_keys = [x for x in entry if 'account_key' in x]
    if len(acc_keys) > 0:
        config['account_key'] = acc_keys[0]
    else:
        config['account_key'] = globalconfig.get('account_key', ACME_DEFAULT_ACCOUNT_KEY)

    # Certificate directory
    cert_dirs = [x for x in entry if 'cert_dir' in x]
    if len(cert_dirs) > 0:
        config['cert_dir'] = cert_dirs[0]
    else:
        config['cert_dir'] = globalconfig.get('cert_dir', ACME_DIR)

    # SSL CA location
    ca_files = [x for x in entry if 'ca_file' in x]
    if len(ca_files) > 0:
        config['static_ca'] = True
        config['ca_file'] = ca_files[0]
    elif 'server_ca' in globalconfig:
        config['static_ca'] = True
        config['ca_file'] = globalconfig['server_ca']
    else:
        config['static_ca'] = False
        config['ca_file'] = os.path.join(config['cert_dir'], "{}.ca".format(config['id']))

    # SSL cert location
    cert_files = [x for x in entry if 'cert_file' in x]
    if len(cert_files) > 0:
        config['cert_file'] = cert_files[0]
    else:
        config['cert_file'] = globalconfig.get('server_cert',
                                               os.path.join(config['cert_dir'], "{}.crt".format(config['id'])))

    # SSL key location
    key_files = [x for x in entry if 'key_file' in x]
    if len(key_files) > 0:
        config['key_file'] = key_files[0]
    else:
        config['key_file'] = globalconfig.get('server_key',
                                              os.path.join(config['cert_dir'], "{}.key".format(config['id'])))

    # SSL key length (if it has to be generated)
    key_lengths = [x for x in entry if 'key_file' in x]
    if len(key_lengths) > 0:
        config['key_length'] = int(key_lengths[0])
    else:
        config['key_length'] = ACME_DEFAULT_KEY_LENGTH

    # Domain action configuration
    config['actions'] = list()
    for actioncfg in [x for x in data if 'path' in x]:
        config['actions'].append(complete_action_config(actioncfg, config))

    # Domain challenge handler configuration
    config['handlers'] = dict()
    handlerconfigs = [x for x in data if 'mode' in x]
    for domain in config['domainlist']:
        # Use global config as base handler config
        cfg = copy.deepcopy(globalconfig)

        # Determine generic domain handler config values
        genericfgs = [x for x in handlerconfigs if 'domain' not in x]
        if len(genericfgs) > 0:
            cfg.update(genericfgs[0])

        # Update handler config with more specific values
        specificcfgs = [x for x in handlerconfigs if ('domain' in x and x['domain'] == domain)]
        if len(specificcfgs) > 0:
            cfg.update(specificcfgs[0])

        config['handlers'][domain] = cfg

    return config


# @brief load the configuration from a file
def load():
    globalconfig = dict()
    # load global configuration
    if os.path.isfile(ACME_CONF):
        with io.open(ACME_CONF) as config_fd:
            try:
                import json
                globalconfig = json.load(config_fd)
            except ValueError:
                import yaml
                config_fd.seek(0)
                globalconfig = yaml.load(config_fd)

    config = list()
    # load domain configuration
    for config_file in os.listdir(ACME_CONFD):
        if config_file.endswith(".conf"):
            with io.open(os.path.join(ACME_CONFD, config_file)) as config_fd:
                try:
                    import json
                    for entry in json.load(config_fd).items():
                        config.append(parse_config_entry(entry, globalconfig))
                except ValueError:
                    import yaml
                    config_fd.seek(0)
                    for entry in yaml.load(config_fd).items():
                        config.append(parse_config_entry(entry, globalconfig))

    return config
