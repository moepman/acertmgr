#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Automated Certificate Manager using ACME
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE

import grp
import io
import os
import pwd
import stat
import subprocess

from acertmgr import configuration, tools
from acertmgr.authority import authority
from acertmgr.modes import challenge_handler
from acertmgr.tools import log


# @brief fetch new certificate from letsencrypt
# @param settings the domain's configuration options
def cert_get(settings):
    log("Getting certificate for %s" % settings['domainlist'])

    acme = authority(settings['authority'])
    acme.register_account()

    # create challenge handlers for this certificate
    challenge_handlers = dict()
    for domain in settings['domainlist']:
        # Create the challenge handler
        challenge_handlers[domain] = challenge_handler(settings['handlers'][domain])

    # create ssl key
    key_file = settings['key_file']
    key_length = settings['key_length']
    if os.path.isfile(key_file):
        key = tools.read_pem_file(key_file, key=True)
    else:
        log("SSL key not found at '{0}'. Creating {1} bit key.".format(key_file, key_length))
        key = tools.new_ssl_key(key_file, key_length)

    # create ssl csr
    csr_file = settings['csr_file']
    if os.path.isfile(csr_file) and str(settings['csr_static']).lower() == 'true':
        log('Loading CSR from {}'.format(csr_file))
        cr = tools.read_pem_file(csr_file, csr=True)
    else:
        log('Generating CSR for {}'.format(settings['domainlist']))
        must_staple = str(settings.get('cert_must_staple')).lower() == "true"
        cr = tools.new_cert_request(settings['domainlist'], key, must_staple)
        tools.write_pem_file(cr, csr_file)

    # request cert with csr
    crt, ca = acme.get_crt_from_csr(cr, settings['domainlist'], challenge_handlers)

    #  if resulting certificate is valid: store in final location
    if tools.is_cert_valid(crt, settings['ttl_days']):
        log("Certificate '{}' renewed and valid until {}".format(tools.get_cert_cn(crt),
                                                                 tools.get_cert_valid_until(crt)))
        tools.write_pem_file(crt, settings['cert_file'], stat.S_IREAD)
        if (not str(settings.get('ca_static')).lower() == 'true' or not os.path.exists(settings['ca_file'])) \
                and ca is not None:
            tools.write_pem_file(ca, settings['ca_file'])


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
        log('Could not set certificate file ownership!', warning=True)
    try:
        os.chmod(crt_path, int(crt_perm, 8))
    except OSError:
        log('Could not set certificate file permissions!', warning=True)

    return crt_action


def cert_revoke(cert, configs, fallback_authority, reason=None):
    domains = set(tools.get_cert_domains(cert))
    acmeconfig = None
    for config in configs:
        if domains == set(config['domainlist']):
            acmeconfig = config['authority']
            break
    if not acmeconfig:
        acmeconfig = fallback_authority
        log("No matching authority found to revoke {}: {}, using globalconfig/defaults".format(tools.get_cert_cn(cert),
            tools.get_cert_domains(cert)), warning=True)
    acme = authority(acmeconfig)
    acme.register_account()
    acme.revoke_crt(cert, reason)


def main():
    # load config
    runtimeconfig, domainconfigs = configuration.load()
    if runtimeconfig.get('mode') == 'revoke':
        # Mode: revoke certificate
        log("Revoking {}".format(runtimeconfig['revoke']))
        cert_revoke(tools.read_pem_file(runtimeconfig['revoke']),
                    domainconfigs,
                    runtimeconfig['fallback_authority'],
                    runtimeconfig['revoke_reason'])
    else:
        # Mode: issue certificates (implicit)
        # post-update actions (run only once)
        actions = set()
        superseded = set()
        exceptions = list()
        # check certificate validity and obtain/renew certificates if needed
        for config in domainconfigs:
            try:
                cert = None
                if os.path.isfile(config['cert_file']):
                    cert = tools.read_pem_file(config['cert_file'])
                if not cert or not tools.is_cert_valid(cert, config['ttl_days']) or (
                        'force_renew' in runtimeconfig and
                        all(d in config['domainlist'] for d in runtimeconfig['force_renew'])):
                    cert_get(config)
                    if str(config.get('cert_revoke_superseded')).lower() == 'true' and cert:
                        superseded.add(cert)
            except Exception as e:
                log("Certificate issue/renew failed", e, error=True)
                exceptions.append(e)

        # deploy new certificates after all are renewed
        deployment_success = True
        for config in domainconfigs:
            try:
                for cfg in config['actions']:
                    if not tools.target_is_current(cfg['path'], config['cert_file']):
                        log("Updating '{}' due to newer version".format(cfg['path']))
                        actions.add(cert_put(cfg))
            except Exception as e:
                log("Certificate deployment failed", e, error=True)
                exceptions.append(e)
                deployment_success = False

        # run post-update actions
        for action in actions:
            if action is not None:
                try:
                    # Run actions in a shell environment (to allow shell syntax) as stated in the configuration
                    output = subprocess.check_output(action, shell=True, stderr=subprocess.STDOUT)
                    log("Executed '{}' successfully: {}".format(action, output))
                except subprocess.CalledProcessError as e:
                    log("Execution of '{}' failed with error '{}': {}".format(e.cmd, e.returncode, e.output), e,
                        error=True)
                    exceptions.append(e)
                    deployment_success = False

        # revoke old certificates as superseded
        if deployment_success:
            for superseded_cert in superseded:
                try:
                    log("Revoking '{}' valid until {} as superseded".format(
                        tools.get_cert_cn(superseded_cert),
                        tools.get_cert_valid_until(superseded_cert)))
                    cert_revoke(superseded_cert, domainconfigs, runtimeconfig['fallback_authority'], reason=4)
                except Exception as e:
                    log("Certificate supersede revoke failed", e, error=True)
                    exceptions.append(e)

        # throw a RuntimeError with all exceptions caught while working if there were any
        if len(exceptions) > 0:
            raise RuntimeError("{} exception(s) occurred during processing".format(len(exceptions)))
