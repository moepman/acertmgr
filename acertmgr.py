#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Automated Certificate Manager using ACME
# Copyright (c) Markus Hauschild, 2016.


import acme_tiny
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
CHALLENGE_DIR="/var/www/acme/"
LE_CA="https://acme-staging.api.letsencrypt.org"


class InvalidCertificateError(Exception):
	pass


# @brief check whether existing certificate is still valid or expiring soon
# @param crt_file string containing the path to the certificate file
# @param ttl_days the minimum amount of days for which the certificate must be valid
# @return True if certificate is still valid for at least ttl_days, False otherwise
def cert_isValid(crt_file, ttl_days):
	if not os.path.isfile(crt_file):
		return False
	else:
		# check validity using OpenSSL
		vc = subprocess.check_output(['openssl', 'x509', '-in', crt_file, '-noout', '-dates'])

		m = re.search("notBefore=(.+)", vc)
		if m:
			valid_from = dateutil.parser.parse(m.group(1), ignoretz=True)
		else:
			raise InvalidCertificateError("No notBefore date found")

		m = re.search("notAfter=(.+)", vc)
		if m:
			valid_to = dateutil.parser.parse(m.group(1), ignoretz=True)
		else:
			raise InvalidCertificateError("No notAfter date found")

		now = datetime.datetime.now()
		if valid_from > now:
			raise InvalidCertificateError("Certificate seems to be from the future")

		expiry_limit = now + dateutil.relativedelta.relativedelta(days=+ttl_days)
		if valid_to < expiry_limit:
			return False

		return True


# @brief fetch new certificate from letsencrypt
# @param domain string containing the domain name
# @param settings the domain's configuration options
def cert_get(domain, settings):
	print("Getting certificate for %s." % domain)

	key_file = ACME_DIR + "server.key"
	if not os.path.isfile(key_file):
		raise FileNotFoundError("The server key file (%s) is missing!" % key_file)

	acc_file = ACME_DIR + "account.key"
	if not os.path.isfile(acc_file):
		raise FileNotFoundError("The account key file (%s) is missing!" % acc_file)

	csr_file = "/tmp/%s.csr" % domain
	crt_file = "/tmp/%s.crt" % domain
	if os.path.lexists(csr_file) or os.path.lexists(crt_file):
		raise FileExistsError("A temporary file already exists!")


	try:
		cr = subprocess.check_output(['openssl', 'req', '-new', '-sha256', '-key', key_file, '-out', csr_file, '-subj', '/CN=%s' % domain])

		# get certificate
		crt = acme_tiny.get_crt(acc_file, csr_file, CHALLENGE_DIR, CA = LE_CA)
		with open(crt_file, "w") as crt_fd:
			crt_fd.write(crt)
	except Exception:
		os.remove(csr_file)
		raise

	# TODO check if resulting certificate is valid

	os.remove(csr_file)

	# TODO store resulting certificate at final location


# @brief put new certificate in plcae
# @param domain string containing the domain name
# @param settings the domain's configuration options
def cert_put(domain, settings):
	# TODO copy cert w/ correct permissions
	# TODO restart/reload service
	pass


# @brief augment configuration with defaults
# @param domainconfig the domain configuration
# @param defaults the default configuration
# @return the augmented configuration
def complete_config(domainconfig, defaults):
	for name, value in defaults.items():
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

	# check certificate validity and obtain/renew certificates if needed
	for domain, domaincfgs in config['domains'].items():
		# skip domains without any output files
		if domaincfgs is None:
			continue
		crt_file = ACME_DIR + "%s.crt" % domain
		ttl_days = int(config.get('ttl_days', 15))
		if not cert_isValid(crt_file, ttl_days):
			cert_get(domain, config)
			for domaincfg in domaincfgs:
				cfg = complete_config(domaincfg, config['defaults'])
				cert_put(domain, cfg)
