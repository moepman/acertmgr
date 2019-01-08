#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Automated Certificate Manager using ACME
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE

import acme
import tools
import grp
import hashlib
import os
import pwd
import shutil
import stat
import subprocess
import tempfile

import yaml

import acertmgr_web

ACME_DIR = "/etc/acme"
ACME_CONF = os.path.join(ACME_DIR, "acme.conf")
ACME_CONFD = os.path.join(ACME_DIR, "domains.d")

ACME_DEFAULT_SERVER_KEY = os.path.join(ACME_DIR, "server.key")
ACME_DEFAULT_ACCOUNT_KEY = os.path.join(ACME_DIR, "account.key")


class FileNotFoundError(OSError):
    pass


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


# @brief fetch new certificate from letsencrypt
# @param domain string containing the domain name
# @param settings the domain's configuration options
def cert_get(domains, settings):
    print("Getting certificate for %s." % domains)

    key_file = settings['server_key']
    if not os.path.isfile(key_file):
        print("Server key not found at '{0}'. Creating RSA key.".format(key_file))
        tools.new_rsa_key(key_file)

    acc_file = settings['account_key']
    if not os.path.isfile(acc_file):
        print("Account key not found at '{0}'. Creating RSA key.".format(acc_file))
        tools.new_rsa_key(acc_file)

    filename = hashlib.md5(domains).hexdigest()
    _, csr_file = tempfile.mkstemp(".csr", "%s." % filename)
    _, crt_file = tempfile.mkstemp(".crt", "%s." % filename)

    challenge_dir = settings.get("webdir", "/var/www/acme-challenge/")
    if not os.path.isdir(challenge_dir):
        raise FileNotFoundError("Challenge directory (%s) does not exist!" % challenge_dir)

    current_dir = '.'
    server = None
    if settings['mode'] == 'standalone':
        port = settings.get('port', 80)

        current_dir = os.getcwd()
        os.chdir(challenge_dir)
        server = acertmgr_web.ACMEHTTPServer(port)
        server.start()
    try:
        key = tools.read_key(key_file)
        cr = tools.new_cert_request(domains.split(), key)
        print("Reading account key...")
        acc_key = tools.read_key(acc_file)
        acme.register_account(acc_key, settings['authority'])
        crt = acme.get_crt_from_csr(acc_key, cr, domains.split(), challenge_dir, settings['authority'])
        with open(crt_file, "w") as crt_fd:
            crt_fd.write(tools.convert_cert_to_pem(crt))

        #  if resulting certificate is valid: store in final location
        if tools.is_cert_valid(crt_file, 60):
            crt_final = os.path.join(ACME_DIR, ("%s.crt" % domains.split(" ")[0]))
            shutil.copy2(crt_file, crt_final)
            os.chmod(crt_final, stat.S_IREAD)

    finally:
        if settings['mode'] == 'standalone':
            server.stop()
            os.chdir(current_dir)
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
    # load global configuration
    config = {}
    if os.path.isfile(ACME_CONF):
        with open(ACME_CONF) as config_fd:
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
            cert_get(domains, config)
        for domaincfg in domaincfgs:
            cfg = complete_config(domaincfg, config)
            if not target_is_current(cfg['path'], crt_file):
                actions.add(cert_put(cfg))

    # run post-update actions
    for action in actions:
        if action is not None:
            subprocess.call(action.split())
