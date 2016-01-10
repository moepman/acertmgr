#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Automated Certificate Manager using ACME
# Copyright (c) Markus Hauschild, 2016.


import datetime
import dateutil.parser
import dateutil.relativedelta
import os
import re
import subprocess
import yaml


ACME_DIR="/etc/acme/"
ACME_CONF=ACME_DIR + "acme.conf"
ACME_CONFD=ACME_DIR + "domains.d/"


# @brief check whether existing certificate is still valid or expiring soon
# @param domain string containing the domain name
# @param settings the domain's configuration options
# @return True if certificate is still valid for a while, False otherwise
def cert_isValid(domain, settings):
	crt_file = ACME_DIR + domain + ".crt"
	if not os.path.isfile(crt_file):
		return False
	else:
		# check validity using OpenSSL
		vc = subprocess.check_output(['openssl', 'x509', '-in', crt_file, '-noout', '-dates'])

		m = re.search("notBefore=(.+)", vc)
		if m:
			valid_from = dateutil.parser.parse(m.group(1), ignoretz=True)
		else:
			raise "No notBefore date found, something seems wrong!"

		m = re.search("notAfter=(.+)", vc)
		if m:
			valid_to = dateutil.parser.parse(m.group(1), ignoretz=True)
		else:
			raise "No notAfter date found, something seems wrong!"

		now = datetime.datetime.now()
		if valid_from > now:
			raise "A Certificate seems to be from the future, something seems wrong!"

		expiry_limit = now + dateutil.relativedelta.relativedelta(days=+15)
		if valid_to < expiry_limit:
			return False

		return True


# @brief fetch new certificate from letsencrypt
# @param domain string containing the domain name
# @param settings the domain's configuration options
def cert_get(domain, settings):
	key_file = ACME_DIR + "server.key"

	csr_file = "/tmp/%s.csr" % domain
	print("Getting certificate for %s." % domain)

	cr = subprocess.check_output(['openssl', 'req', '-new', '-sha256', '-key', key_file, '-out', csr_file, '-subj', '/CN=%s' % domain])

	# TODO run acme_tiny
	# TODO check if resulting certificate is valid
	# TODO delete temporary files
	# TODO copy cert w/ correct permissions
	# TODO restart/reload service(s)


# @brief augment configuration with defaults
# @param domainconfig the domain configuration
# @param defaults the default configuration
# @return the augmented configuration
def complete_config(domainconfig, defaults):
	for name, value in defaults.iteritems():
		if name not in domainconfig:
			domainconfig[name] = value
	return domainconfig


if __name__ == "__main__":
	# load global configuration
	if os.path.isfile(ACME_CONF):
		with open(ACME_CONF) as config_fd:
			config = yaml.load(config_fd)
	if not config:
		config = {}
	if 'domains' not in config:
		config['domains'] = {}
	if 'defaults' not in config:
		config['defaults'] = {}

	# load domain configuration
	for config_file in os.listdir(ACME_CONFD):
		if config_file.endswith(".conf"):
			with open(ACME_CONFD + config_file) as config_fd:
				config['domains'].update(yaml.load(config_fd))
	#print(str(config))

	# TODO fill up configuration with defaults

	# check certificate validity and obtain/renew certificates if needed
	for domain, domaincfg in config['domains'].iteritems():
		cfg = complete_config(domaincfg, config['defaults'])
		if not cert_isValid(domain, cfg):
			cert_get(domain, cfg)
