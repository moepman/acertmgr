#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Automated Certificate Manager using ACME
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE

import io
import os
import stat
import subprocess
import sys

from acertmgr import configuration, tools
from acertmgr.authority import authority
from acertmgr.modes import challenge_handler
from acertmgr.tools import log, LOG_REPLACEMENTS

try:
    import pwd
    import grp
except ImportError:
    # Warnings will be reported upon usage below
    pass


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
    if os.path.isfile(key_file):
        key = tools.read_pem_file(key_file, key=True)
    else:
        log("SSL key not found at '{0}'. Creating key.".format(key_file))
        key = tools.new_ssl_key(key_file, settings['key_algorithm'], settings['key_length'])

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
    if 'path' not in settings:
        raise ValueError('Deployment settings are missing required element: path')
    if 'format' not in settings:
        raise ValueError('Deployment settings are missing required element: format')

    with io.open(settings['path'], "w+") as crt_fd:
        for fmt in [str.strip(x) for x in settings['format'].split(",")]:
            if fmt == "crt":
                with io.open(settings['cert_file'], "r") as src_fd:
                    crt_fd.write(src_fd.read())
            elif fmt == "key":
                with io.open(settings['key_file'], "r") as src_fd:
                    crt_fd.write(src_fd.read())
            elif fmt == "ca":
                with io.open(settings['ca_file'], "r") as src_fd:
                    crt_fd.write(src_fd.read())
            else:
                log("Ignored unknown deployment format key: {}".format(fmt), warning=True)

    # set owner and group
    if 'user' in settings or 'group' in settings:
        if 'pwd' in sys.modules and 'grp' in sys.modules and hasattr(os, 'chown') and hasattr(os, 'geteuid') and \
                hasattr(os, 'getegid'):
            try:
                uid = pwd.getpwnam(settings['user']).pw_uid if 'user' in settings else os.geteuid()
                gid = grp.getgrnam(settings['group']).gr_gid if 'group' in settings else os.getegid()
                os.chown(settings['path'], uid, gid)
            except OSError as e:
                log('Could not set certificate file ownership', e, warning=True)
        else:
            log('File user and group handling unavailable on this platform', warning=True)
    # set permissions
    if 'perm' in settings:
        if hasattr(os, 'chmod'):
            try:
                os.chmod(settings['path'], int(settings['perm'], 8))
            except OSError as e:
                log('Could not set certificate file permissions', e, warning=True)
        else:
            log('File permission handling unavailable on this platform', warning=True)

    return settings['action']


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
                                                                                               tools.get_cert_domains(
                                                                                                   cert)), warning=True)
    acme = authority(acmeconfig)
    acme.register_account()
    acme.revoke_crt(cert, reason)


def main():
    # load config
    runtimeconfig, domainconfigs = configuration.load()
    # register idna-mapped domains as LOG_REPLACEMENTS for better readability of log output
    for domainconfig in domainconfigs:
        LOG_REPLACEMENTS.update({k: "{} [{}]".format(k, v) for k, v in domainconfig['domainlist_idna_mapped'].items()})
    # Start processing
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
                validate_ocsp = str(config.get('validate_ocsp')).lower() != 'false'
                if validate_ocsp and cert and os.path.isfile(config['ca_file']):
                    try:
                        issuer = tools.read_pem_file(config['ca_file'])
                    except Exception as e1:
                        log("Failed to retrieve issuer from ca file: {}. Trying to download...".format(e1))
                        try:
                            issuer = tools.download_issuer_ca(cert)
                        except Exception as e2:
                            log("Failed to download issuer for cert file: {}. Cannot validate OCSP.".format(e2))
                            validate_ocsp = False
                if not cert or ('force_renew' in runtimeconfig and all(
                        d in config['domainlist'] for d in runtimeconfig['force_renew'])) \
                        or not tools.is_cert_valid(cert, config['ttl_days']) \
                        or (validate_ocsp and not tools.is_ocsp_valid(cert, issuer, config['validate_ocsp'])):
                    cert_get(config)
                    if str(config.get('cert_revoke_superseded')).lower() == 'true' and cert:
                        superseded.add(cert)
            except Exception as e:
                log("Certificate issue/renew failed", e, error=True)
                exceptions.append(e)

        # deploy new certificates after all are renewed
        deployment_success = True
        for config in domainconfigs:
            for cfg in config['actions']:
                try:
                    if not tools.target_is_current(cfg['path'], config['cert_file']):
                        actions.add(cert_put(cfg))
                        log("Updated '{}' due to newer version".format(cfg['path']))
                except Exception as e:
                    log("Certificate deployment to {} failed".format(cfg['path']), e, error=True)
                    exceptions.append(e)
                    deployment_success = False

        # run post-update actions
        for action in actions:
            if action is not None:
                try:
                    # Run actions in a shell environment (to allow shell syntax) as stated in the configuration
                    output = subprocess.check_output(action, shell=True, stderr=subprocess.STDOUT)
                    logmsg = "Action succeeded: {}".format(action)
                    if len(output) > 0:
                        if getattr(output, 'decode', None):
                            # Decode function available? Use it to get a proper str
                            output = output.decode('utf-8')
                        logmsg += os.linesep + tools.indent(output, 18)  # 18 = len("Action succeeded: ")
                    log(logmsg)
                except subprocess.CalledProcessError as e:
                    output = e.output
                    logmsg = "Action failed: ({}) {}".format(e.returncode, e.cmd)
                    if len(output) > 0:
                        if getattr(output, 'decode', None):
                            # Decode function available? Use it to get a proper str
                            output = output.decode('utf-8')
                        logmsg += os.linesep + tools.indent(output, 15)  # 15 = len("Action failed: ")
                    log(logmsg, error=True)
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
