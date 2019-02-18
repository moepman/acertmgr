#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Automated Certificate Manager using ACME
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE

import grp
import importlib
import io
import os
import pwd
import shutil
import stat
import subprocess
import tempfile

import configuration
import tools


# @brief check whether existing target file is still valid or source crt has been updated
# @param target string containing the path to the target file
# @param file string containing the path to the certificate file
# @return True if target file is at least as new as the certificate, False otherwise
def target_is_current(target, file):
    if not os.path.isfile(target):
        return False
    target_date = os.path.getmtime(target)
    crt_date = os.path.getmtime(file)
    return target_date >= crt_date


# @brief create a authority for the given configuration
# @param settings the authority configuration options
def create_authority(settings):
    if "api" in settings:
        api = settings["api"]
    else:
        api = "v1"

    acc_file = settings['account_key']
    if not os.path.isfile(acc_file):
        print("Account key not found at '{0}'. Creating RSA key.".format(acc_file))
        tools.new_rsa_key(acc_file)
    acc_key = tools.read_key(acc_file)

    authority_module = importlib.import_module("authority.{0}".format(api))
    authority_class = getattr(authority_module, "ACMEAuthority")
    return authority_class(settings.get('authority'), acc_key)


# @brief create a challenge handler for the given configuration
# @param settings the domain's configuration options
def create_challenge_handler(settings):
    if "mode" in settings:
        mode = settings["mode"]
    else:
        mode = "standalone"

    handler_module = importlib.import_module("modes.{0}".format(mode))
    handler_class = getattr(handler_module, "ChallengeHandler")
    return handler_class(settings)


# @brief fetch new certificate from letsencrypt
# @param settings the domain's configuration options
def cert_get(settings):
    print("Getting certificate for '%s'." % settings['domains'])

    key_file = settings['key_file']
    key_length = settings['key_length']
    if not os.path.isfile(key_file):
        print("SSL key not found at '{0}'. Creating {1} bit RSA key.".format(key_file, key_length))
        tools.new_rsa_key(key_file, key_length)

    acme = create_authority(settings)

    filename = settings['id']
    _, csr_file = tempfile.mkstemp(".csr", "%s." % filename)
    _, crt_file = tempfile.mkstemp(".crt", "%s." % filename)

    # find challenge handlers for this certificate
    challenge_handlers = dict()
    for domain in settings['domainlist']:
        # Create the challenge handler
        challenge_handlers[domain] = create_challenge_handler(settings['handlers'][domain])

    try:
        key = tools.read_key(key_file)
        cr = tools.new_cert_request(settings['domainlist'], key)
        print("Reading account key...")
        acme.register_account()
        crt = acme.get_crt_from_csr(cr, settings['domainlist'], challenge_handlers)
        with io.open(crt_file, "w") as crt_fd:
            crt_fd.write(tools.convert_cert_to_pem(crt))

        #  if resulting certificate is valid: store in final location
        if tools.is_cert_valid(crt_file, 60):
            crt_final = settings['cert_file']
            shutil.copy2(crt_file, crt_final)
            os.chmod(crt_final, stat.S_IREAD)
            # download current ca file for the new certificate if no static ca is configured
            if "static_ca" in settings and not settings['static_ca']:
                tools.download_issuer_ca(crt_final, settings['ca_file'])

    finally:
        os.remove(csr_file)
        os.remove(crt_file)


# @brief put new certificate in place
# @param settings the domain's configuration options
# @return the action to be executed after the certificate update
def cert_put(settings):
    # TODO error handling
    ca_file = settings['ca_file']
    crt_user = settings['user']
    crt_group = settings['group']
    crt_perm = settings['perm']
    crt_path = settings['path']
    crt_format = settings['format'].split(",")
    crt_format = [str.strip(x) for x in crt_format]
    crt_action = settings['action']

    key_file = settings['key_file']
    crt_final = settings['cert_file']

    with io.open(crt_path, "w+") as crt_fd:
        for fmt in crt_format:
            if fmt == "crt":
                src_fd = io.open(crt_final, "r")
                crt_fd.write(src_fd.read())
                src_fd.close()
            if fmt == "key":
                src_fd = io.open(key_file, "r")
                crt_fd.write(src_fd.read())
                src_fd.close()
            if fmt == "ca":
                if not os.path.isfile(ca_file):
                    raise FileNotFoundError("The CA certificate file (%s) is missing!" % ca_file)
                src_fd = io.open(ca_file, "r")
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


if __name__ == "__main__":
    # load config
    configs = configuration.load()

    # post-update actions (run only once)
    actions = set()

    # check certificate validity and obtain/renew certificates if needed
    for config in configs:
        cert_file = config['cert_file']
        ttl_days = int(config.get('ttl_days', configuration.ACME_DEFAULT_TTL))
        if not tools.is_cert_valid(cert_file, ttl_days):
            cert_get(config)
            for cfg in config['actions']:
                if not target_is_current(cfg['path'], cert_file):
                    actions.add(cert_put(cfg))

    # run post-update actions
    for action in actions:
        if action is not None:
            subprocess.call(action.split())
