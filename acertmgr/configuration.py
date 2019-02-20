#!/usr/bin/env python
# -*- coding: utf-8 -*-

# config - acertmgr config parser
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE

import argparse
import copy
import io
import hashlib
import os

# Backward compatiblity for older versions/installations of acertmgr
LEGACY_WORK_DIR = "/etc/acme"
LEGACY_CONF_FILE = os.path.join(LEGACY_WORK_DIR, "acme.conf")
LEGACY_CONF_DIR = os.path.join(LEGACY_WORK_DIR, "domains.d")

# Configuration defaults to use if not specified otherwise
DEFAULT_CONF_FILE = "/etc/acertmgr/acertmgr.conf"
DEFAULT_CONF_DIR = "/etc/acertmgr"
DEFAULT_KEY_LENGTH = 4096  # bits
DEFAULT_TTL = 15  # days
DEFAULT_API = "v1"
DEFAULT_AUTHORITY = "https://acme-v01.api.letsencrypt.org"


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
def parse_config_entry(entry, globalconfig, work_dir):
    config = dict()

    # Basic domain information
    config['domains'], data = entry
    config['domainlist'] = config['domains'].split(' ')
    config['id'] = hashlib.md5(config['domains'].encode('utf-8')).hexdigest()

    # Action config defaults
    config['defaults'] = globalconfig.get('defaults', {})

    # API version
    apis = [x for x in entry if 'api' in x]
    if len(apis) > 0:
        config['api'] = apis[0]
    else:
        config['api'] = globalconfig.get('api', DEFAULT_API)

    # Certificate authority
    authorities = [x for x in entry if 'authority' in x]
    if len(authorities) > 0:
        config['authority'] = authorities[0]
    else:
        config['authority'] = globalconfig.get('authority', DEFAULT_AUTHORITY)

    # Account key
    acc_keys = [x for x in entry if 'account_key' in x]
    if len(acc_keys) > 0:
        config['account_key'] = acc_keys[0]
    else:
        config['account_key'] = globalconfig.get('account_key', os.path.join(work_dir, "account.key"))

    # Certificate directory
    cert_dirs = [x for x in entry if 'cert_dir' in x]
    if len(cert_dirs) > 0:
        config['cert_dir'] = cert_dirs[0]
    else:
        config['cert_dir'] = globalconfig.get('cert_dir', work_dir)

    # TTL days
    cert_dirs = [x for x in entry if 'ttl_days' in x]
    if len(cert_dirs) > 0:
        config['ttl_days'] = cert_dirs[0]
    else:
        config['ttl_days'] = globalconfig.get('ttl_days', DEFAULT_TTL)

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
        config['key_length'] = DEFAULT_KEY_LENGTH

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
    parser = argparse.ArgumentParser(description="acertmgr - Automated Certificate Manager using ACME/Let's Encrypt")
    parser.add_argument("-c", "--config-file", nargs="?",
                        help="global configuration file (default='{}')".format(DEFAULT_CONF_FILE))
    parser.add_argument("-d", "--config-dir", nargs="?",
                        help="domain configuration directory (default='{}')".format(DEFAULT_CONF_DIR))
    parser.add_argument("-w", "--work-dir", nargs="?",
                        help="persistent work data directory (default=config_dir)")
    args = parser.parse_args()

    # Determine global configuration file
    if args.config_file:
        global_config_file = args.config_file
    elif os.path.isfile(LEGACY_CONF_FILE):
        global_config_file = LEGACY_CONF_FILE
    else:
        global_config_file = DEFAULT_CONF_FILE

    # Determine domain configuration directory
    if args.config_dir:
        domain_config_dir = args.config_dir
    elif os.path.isdir(LEGACY_CONF_DIR):
        domain_config_dir = LEGACY_CONF_DIR
    else:
        domain_config_dir = DEFAULT_CONF_DIR

    # Determine work directory...
    if args.work_dir:
        work_dir = args.work_dir
    elif os.path.isdir(LEGACY_WORK_DIR):
        work_dir = LEGACY_WORK_DIR
    else:
        # .. or use the domain configuration directory otherwise
        work_dir = domain_config_dir

    # load global configuration
    globalconfig = dict()
    if os.path.isfile(global_config_file):
        with io.open(global_config_file) as config_fd:
            try:
                import json
                globalconfig = json.load(config_fd)
            except ValueError:
                import yaml
                config_fd.seek(0)
                globalconfig = yaml.load(config_fd)

    # create work directory if it does not exist
    if not os.path.isdir(work_dir):
        os.mkdir(work_dir, int("0700", 8))

    # load domain configuration
    config = list()
    if os.path.isdir(domain_config_dir):
        for domain_config_file in os.listdir(domain_config_dir):
            # check file extension and skip if global config file
            if domain_config_file.endswith(".conf") and domain_config_file != global_config_file:
                with io.open(os.path.join(domain_config_dir, domain_config_file)) as config_fd:
                    try:
                        import json
                        for entry in json.load(config_fd).items():
                            config.append(parse_config_entry(entry, globalconfig, work_dir))
                    except ValueError:
                        import yaml
                        config_fd.seek(0)
                        for entry in yaml.load(config_fd).items():
                            config.append(parse_config_entry(entry, globalconfig, work_dir))

    return config
