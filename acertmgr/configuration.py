#!/usr/bin/env python
# -*- coding: utf-8 -*-

# config - acertmgr config parser
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE

import argparse
import copy
import hashlib
import io
import json
import os

from acertmgr.tools import idna_convert

# Configuration defaults to use if not specified otherwise
DEFAULT_CONF_DIR = "/etc/acertmgr"
DEFAULT_CONF_FILENAME = "acertmgr.conf"
DEFAULT_TTL = 30  # days
DEFAULT_VALIDATE_OCSP = "sha1" # mandated by RFC5019
DEFAULT_API = "v2"
DEFAULT_AUTHORITY = "https://acme-v02.api.letsencrypt.org"


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


# @brief update config[name] with value from localconfig>globalconfig>default
def update_config_value(config, name, localconfig, globalconfig, default):
    values = [x[name] for x in localconfig if name in x]
    if len(values) > 0:
        config[name] = values[0]
    else:
        config[name] = globalconfig.get(name, default)


# @brief parse authority from config
def parse_authority(localconfig, globalconfig, runtimeconfig):
    authority = {}
    # - API version
    update_config_value(authority, 'api', localconfig, globalconfig, DEFAULT_API)

    # - Certificate authority
    update_config_value(authority, 'authority', localconfig, globalconfig, DEFAULT_AUTHORITY)

    # - Certificate authority ToS agreement
    update_config_value(authority, 'authority_tos_agreement', localconfig, globalconfig,
                        runtimeconfig['authority_tos_agreement'])

    # - Certificate authority contact email addresses
    update_config_value(authority, 'authority_contact_email', localconfig, globalconfig, None)

    # - Account key path
    update_config_value(authority, 'account_key', localconfig, globalconfig,
                        os.path.join(runtimeconfig['work_dir'], "account.key"))

    # - Account key algorithm (if key has to be (re-)generated)
    update_config_value(authority, 'account_key_algorithm', localconfig, globalconfig, None)

    # - Account key length (if key has to be (re-)generated, converted to int)
    update_config_value(authority, 'account_key_length', localconfig, globalconfig, None)
    authority['account_key_length'] = int(authority['account_key_length']) if authority['account_key_length'] else None

    return authority


# @brief load the configuration from a file
def parse_config_entry(entry, globalconfig, runtimeconfig):
    config = dict()

    # Basic domain information
    domains, localconfig = entry
    config['domainlist'] = domains.split(' ')
    config['id'] = hashlib.md5(domains.encode('utf-8')).hexdigest()

    # Convert unicode to IDNA domains
    config['domaintranslation'] = idna_convert(config['domainlist'])
    if len(config['domaintranslation']) > 0:
        config['domainlist'] = [x for x, _ in config['domaintranslation']]

    # Action config defaults
    config['defaults'] = globalconfig.get('defaults', {})

    # Authority related config options
    config['authority'] = parse_authority(localconfig, globalconfig, runtimeconfig)

    # Certificate directory
    update_config_value(config, 'cert_dir', localconfig, globalconfig, runtimeconfig['work_dir'])

    # TTL days
    update_config_value(config, 'ttl_days', localconfig, globalconfig, DEFAULT_TTL)
    config['ttl_days'] = int(config['ttl_days'])

    # Validate OCSP on certificate verification
    update_config_value(config, 'validate_ocsp', localconfig, globalconfig, DEFAULT_VALIDATE_OCSP)

    # Revoke old certificate with reason superseded after renewal
    update_config_value(config, 'cert_revoke_superseded', localconfig, globalconfig, "false")

    # Whether to include request for OCSP must-staple in the certificate
    update_config_value(config, 'cert_must_staple', localconfig, globalconfig, "false")

    # Use a static cert request
    update_config_value(config, 'csr_static', localconfig, globalconfig, "false")

    # SSL cert request location
    update_config_value(config, 'csr_file', localconfig, globalconfig,
                        os.path.join(config['cert_dir'], "{}.csr".format(config['id'])))

    # SSL cert location (with compatibility to older versions)
    update_config_value(config, 'cert_file', localconfig, globalconfig,
                        os.path.join(config['cert_dir'], "{}.crt".format(config['id'])))

    # SSL key location (with compatibility to older versions)
    update_config_value(config, 'key_file', localconfig, globalconfig,
                        os.path.join(config['cert_dir'], "{}.key".format(config['id'])))

    # SSL key algorithm (if key has to be (re-)generated)
    update_config_value(config, 'key_algorithm', localconfig, globalconfig, None)

    # SSL key length (if key has to be (re-)generated, converted to int)
    update_config_value(config, 'key_length', localconfig, globalconfig, None)
    config['key_length'] = int(config['key_length']) if config['key_length'] else None

    # SSL CA location / use static
    update_config_value(config, 'ca_file', localconfig, globalconfig,
                        os.path.join(config['cert_dir'], "{}.ca".format(config['id'])))
    update_config_value(config, 'ca_static', localconfig, globalconfig, "false")

    # Domain action configuration
    config['actions'] = list()
    for actioncfg in [x for x in localconfig if 'path' in x]:
        config['actions'].append(complete_action_config(actioncfg, config))

    # Domain challenge handler configuration
    config['handlers'] = dict()
    handlerconfigs = [x for x in localconfig if 'mode' in x]
    _domaintranslation_dict = {x: y for x, y in config.get('domaintranslation', [])}
    for domain in config['domainlist']:
        # Use global config as base handler config
        cfg = copy.deepcopy(globalconfig)

        # Determine generic domain handler config values
        genericfgs = [x for x in handlerconfigs if 'domain' not in x]
        if len(genericfgs) > 0:
            cfg.update(genericfgs[0])

        # Update handler config with more specific values (use original names for translated unicode domains)
        _domain = _domaintranslation_dict.get(domain, domain)
        specificcfgs = [x for x in handlerconfigs if 'domain' in x and x['domain'] == _domain]
        if len(specificcfgs) > 0:
            cfg.update(specificcfgs[0])

        config['handlers'][domain] = cfg

    return config


# @brief load the configuration from a file
def load():
    runtimeconfig = dict()
    parser = argparse.ArgumentParser(description="acertmgr - Automated Certificate Manager using ACME/Let's Encrypt")
    parser.add_argument("-c", "--config-file", nargs="?",
                        help="global configuration file (default='$config_dir/{}')".format(DEFAULT_CONF_FILENAME))
    parser.add_argument("-d", "--config-dir", nargs="?",
                        help="domain configuration directory (default='{}')".format(DEFAULT_CONF_DIR))
    parser.add_argument("-w", "--work-dir", nargs="?",
                        help="persistent work data directory (default='$config_dir')")
    parser.add_argument("--authority-tos-agreement", "--tos-agreement", "--tos", nargs="?",
                        help="Agree to the authorities Terms of Service (value required depends on authority)")
    parser.add_argument("--force-renew", "--renew-now", nargs="?",
                        help="Renew all domain configurations matching the given value immediately")
    parser.add_argument("--revoke", nargs="?",
                        help="Revoke a certificate file issued with the currently configured account key.")
    parser.add_argument("--revoke-reason", nargs="?", type=int,
                        help="Provide a revoke reason, see https://tools.ietf.org/html/rfc5280#section-5.3.1")
    args = parser.parse_args()

    # Determine domain configuration directory
    if args.config_dir:
        domain_config_dir = args.config_dir
    else:
        domain_config_dir = DEFAULT_CONF_DIR

    # Determine global configuration file
    if args.config_file:
        global_config_file = args.config_file
    else:
        global_config_file = os.path.join(domain_config_dir, DEFAULT_CONF_FILENAME)

    # Runtime configuration: Get from command-line options
    # - work_dir
    if args.work_dir:
        runtimeconfig['work_dir'] = args.work_dir
    else:
        runtimeconfig['work_dir'] = domain_config_dir
    #  create work_dir if it does not exist yet
    if not os.path.isdir(runtimeconfig['work_dir']):
        os.mkdir(runtimeconfig['work_dir'], int("0700", 8))

    # - authority_tos_agreement
    if args.authority_tos_agreement:
        runtimeconfig['authority_tos_agreement'] = args.authority_tos_agreement
    else:
        runtimeconfig['authority_tos_agreement'] = None

    # - force-rewew
    if args.force_renew:
        domaintranslation = idna_convert(args.force_renew.split(' '))
        if len(domaintranslation) > 0:
            runtimeconfig['force_renew'] = [x for x, _ in domaintranslation]
        else:
            runtimeconfig['force_renew'] = args.force_renew.split(' ')

    # - revoke
    if args.revoke:
        runtimeconfig['mode'] = 'revoke'
        runtimeconfig['revoke'] = args.revoke
        runtimeconfig['revoke_reason'] = args.revoke_reason

    # Global configuration: Load from file
    globalconfig = dict()
    if os.path.isfile(global_config_file):
        with io.open(global_config_file) as config_fd:
            try:
                globalconfig = json.load(config_fd)
            except ValueError:
                import yaml
                config_fd.seek(0)
                globalconfig = yaml.safe_load(config_fd)

    # Domain configuration(s): Load from file(s)
    domainconfigs = list()
    if os.path.isdir(domain_config_dir):
        for domain_config_file in os.listdir(domain_config_dir):
            domain_config_file = os.path.join(domain_config_dir, domain_config_file)
            # check file extension and skip if global config file
            if domain_config_file.endswith(".conf") and \
                    os.path.abspath(domain_config_file) != os.path.abspath(global_config_file):
                with io.open(domain_config_file) as config_fd:
                    try:
                        for entry in json.load(config_fd).items():
                            domainconfigs.append(parse_config_entry(entry, globalconfig, runtimeconfig))
                    except ValueError:
                        import yaml
                        config_fd.seek(0)
                        for entry in yaml.safe_load(config_fd).items():
                            domainconfigs.append(parse_config_entry(entry, globalconfig, runtimeconfig))

    # Define a fallback authority from global configuration / defaults
    runtimeconfig['fallback_authority'] = parse_authority([], globalconfig, runtimeconfig)

    return runtimeconfig, domainconfigs
