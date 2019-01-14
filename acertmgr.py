#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Automated Certificate Manager using ACME
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE


import grp
import hashlib
import importlib
import os
import pwd
import shutil
import stat
import subprocess
import tempfile

import tools

ACME_DIR = "/etc/acme"
ACME_CONF = os.path.join(ACME_DIR, "acme.conf")
ACME_CONFD = os.path.join(ACME_DIR, "domains.d")

ACME_DEFAULT_SERVER_KEY = os.path.join(ACME_DIR, "server.key")
ACME_DEFAULT_ACCOUNT_KEY = os.path.join(ACME_DIR, "account.key")


# @brief check whether existing target file is still valid or source crt has been updated
# @param target string containing the path to the target file
# @param crt_file string containing the path to the certificate file
# @return True if target file is at least as new as the certificate, False otherwise
def target_is_current(target, crt_file):
    if not os.path.isfile(target):
        return False
    target_date = os.path.getmtime(target)
    crt_date = os.path.getmtime(crt_file)
    return target_date >= crt_date


# @brief create a authority for the given configuration
# @param config the authority configuration options
def create_authority(config):
    if "apiversion" in config:
        apiversion = config["apiversion"]
    else:
        apiversion = "v1"

    acc_file = config['account_key']
    if not os.path.isfile(acc_file):
        print("Account key not found at '{0}'. Creating RSA key.".format(acc_file))
        tools.new_rsa_key(acc_file)
    acc_key = tools.read_key(acc_file)

    authority_module = importlib.import_module("authority.{0}".format(apiversion))
    authority_class = getattr(authority_module, "ACMEAuthority")
    return authority_class(config.get('authority'),acc_key)


# @brief create a challenge handler for the given configuration
# @param config the domain's configuration options
def create_challenge_handler(config):
    if "mode" in config:
        mode = config["mode"]
    else:
        mode = "standalone"

    handler_module = importlib.import_module("modes.{0}".format(mode))
    handler_class = getattr(handler_module, "ChallengeHandler")
    return handler_class(config)


# @brief fetch new certificate from letsencrypt
# @param domains string containing all domain names
# @param globalconfig the global configuration options
# @param handlerconfigs the domain's handler configuration options
def cert_get(domains, globalconfig, handlerconfigs):
    print("Getting certificate for '%s'." % domains)

    key_file = globalconfig['server_key']
    if not os.path.isfile(key_file):
        print("Server key not found at '{0}'. Creating RSA key.".format(key_file))
        tools.new_rsa_key(key_file)

    acme = create_authority(globalconfig)

    filename = hashlib.md5(domains).hexdigest()
    _, csr_file = tempfile.mkstemp(".csr", "%s." % filename)
    _, crt_file = tempfile.mkstemp(".crt", "%s." % filename)

    # find challenge handlers for this certificate
    challenge_handlers = dict()
    domainlist = domains.split(' ')
    for domain in domainlist:
        # Use global config as base handler config
        cfg = globalconfig.deepcopy()

        # Determine generic domain handler config values
        genericfgs = [x for x in handlerconfigs if 'domain' not in x]
        if len(genericfgs) > 0:
            cfg = cfg.update(genericfgs[0])

        # Update handler config with more specific values
        specificcfgs = [x for x in handlerconfigs if ('domain' in x and x['domain'] == domain)]
        if len(specificcfgs) > 0:
            cfg = cfg.update(specificcfgs[0])

        # Create the challenge handler
        challenge_handlers[domain] = create_challenge_handler(cfg)

    try:
        key = tools.read_key(key_file)
        cr = tools.new_cert_request(domainlist, key)
        print("Reading account key...")
        acme.register_account()
        crt = acme.get_crt_from_csr(cr, domainlist, challenge_handlers)
        with open(crt_file, "w") as crt_fd:
            crt_fd.write(tools.convert_cert_to_pem(crt))

        #  if resulting certificate is valid: store in final location
        if tools.is_cert_valid(crt_file, 60):
            crt_final = os.path.join(ACME_DIR, (hashlib.md5(domains).hexdigest() + ".crt"))
            shutil.copy2(crt_file, crt_final)
            os.chmod(crt_final, stat.S_IREAD)

    finally:
        os.remove(csr_file)
        os.remove(crt_file)


# @brief put new certificate in place
# @param settings the domain's configuration options
# @return the action to be executed after the certificate update
def cert_put(settings):
    # TODO error handling
    ca_file = settings.get("cafile", "")
    crt_user = settings['user']
    crt_group = settings['group']
    crt_perm = settings['perm']
    crt_path = settings['path']
    crt_format = settings['format'].split(",")
    crt_format = [str.strip(x) for x in crt_format]
    crt_action = settings['action']

    key_file = settings['server_key']
    crt_final = os.path.join(ACME_DIR, (hashlib.md5(domains).hexdigest() + ".crt"))

    with open(crt_path, "w+") as crt_fd:
        for fmt in crt_format:
            if fmt == "crt":
                src_fd = open(crt_final, "r")
                crt_fd.write(src_fd.read())
                src_fd.close()
            if fmt == "key":
                src_fd = open(key_file, "r")
                crt_fd.write(src_fd.read())
                src_fd.close()
            if fmt == "ca":
                if not os.path.isfile(ca_file):
                    raise FileNotFoundError("The CA certificate file (%s) is missing!" % ca_file)
                src_fd = open(ca_file, "r")
                crt_fd.write(src_fd.read())
                src_fd.close()
            else:
                # TODO error handling
                pass

    # set owner and permissions
    uid = pwd.getpwnam(crt_user).pw_uid
    gid = grp.getgrnam(crt_group).gr_gid
    try:
        os.chown(crt_path, uid, gid)
    except OSError:
        print('Warning: Could not set certificate file ownership!')
    try:
        os.chmod(crt_path, int(crt_perm, 8))
    except OSError:
        print('Warning: Could not set certificate file permissions!')

    return crt_action


# @brief augment configuration with defaults
# @param domainconfig the domain configuration
# @param defaults the default configuration
# @return the augmented configuration
def complete_config(domainconfig, globalconfig):
    defaults = globalconfig['defaults']
    domainconfig['server_key'] = globalconfig['server_key']
    for name, value in defaults.items():
        if name not in domainconfig:
            domainconfig[name] = value
    if 'action' not in domainconfig:
        domainconfig['action'] = None
    return domainconfig


if __name__ == "__main__":
    config = dict()
    # load global configuration
    if os.path.isfile(ACME_CONF):
        with open(ACME_CONF) as config_fd:
            try:
                import json

                config = json.load(config_fd)
            except json.JSONDecodeError:
                import yaml

                config = yaml.load(config_fd)
    if 'defaults' not in config:
        config['defaults'] = {}
    if 'server_key' not in config:
        config['server_key'] = ACME_DEFAULT_SERVER_KEY
    if 'account_key' not in config:
        config['account_key'] = ACME_DEFAULT_ACCOUNT_KEY

    config['domains'] = []
    # load domain configuration
    for config_file in os.listdir(ACME_CONFD):
        if config_file.endswith(".conf"):
            with open(os.path.join(ACME_CONFD, config_file)) as config_fd:
                try:
                    import json

                    for entry in json.load(config_fd).items():
                        config['domains'].append(entry)
                except json.JSONDecodeError:
                    import yaml

                    for entry in yaml.load(config_fd).items():
                        config['domains'].append(entry)

    # post-update actions (run only once)
    actions = set()

    # check certificate validity and obtain/renew certificates if needed
    for domains, domaincfgs in config['domains']:
        # skip domains without any output files
        if domaincfgs is None:
            continue
        crt_file = os.path.join(ACME_DIR, (hashlib.md5(domains).hexdigest() + ".crt"))
        ttl_days = int(config.get('ttl_days', 15))
        if not tools.is_cert_valid(crt_file, ttl_days):
            # Get certificates using handler configs (contain element 'mode')
            cert_get(domains, config, [x for x in domaincfgs if 'mode' in x])
        # Run actions from config (contain element 'path')
        for actioncfg in [x for x in domaincfgs if 'path' in x]:
            actioncfg = complete_config(actioncfg, config)
            if not target_is_current(actioncfg['path'], crt_file):
                actions.add(cert_put(actioncfg))

    # run post-update actions
    for action in actions:
        if action is not None:
            subprocess.call(action.split())
