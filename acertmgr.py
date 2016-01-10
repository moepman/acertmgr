#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Automated Certificate Manager using ACME
# Copyright (c) Markus Hauschild, 2016.


import datetime
import dateutil
import dateutil.parser
import dateutil.relativedelta
import os
import re
import subprocess
import yaml


ACME_DIR="/etc/acme/"
ACME_CONF=ACME_DIR + "acme.conf"
ACME_CONFD=ACME_DIR + "domains.d/"


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

		if valid_from > datetime.datetime.now():
			raise "A Certificate seems to be from the future, something seems wrong!"

		if valid_to < datetime.datetime.now() + dateutil.relativedelta.relativedelta(days=+15):
			return False

		return True


def cert_get(domain, settings):
	key_file = ACME_DIR + "server.key"
	csr_file = "/tmp/%s.csr" % domain
	print("Getting certificate for %s." % domain)

	cr = subprocess.check_output(['openssl', 'req', '-new', '-sha256', '-key', key_file, '-out', csr_file, '-subj', '/CN=%s' % domain])

	# TODO run acme_tiny
	# TODO check if resulting certificate is valid
	# TODO copy cert w/ correct permissions
	# TODO restart/reload service(s)


if __name__ == "__main__":
	# load configuration
	with open(ACME_CONF) as config_fd:
		config = yaml.load(config_fd)
		if not config:
			config = {}
		if 'domains' not in config:
			config['domains'] = {}
	for config_file in os.listdir(ACME_CONFD):
		if config_file.endswith(".conf"):
			with open(ACME_CONFD + config_file) as config_fd:
				config['domains'].update(yaml.load(config_fd))
	#print(str(config))

	# fill up configuration with defaults
	# TODO

	# check certificate validity
	for domain in config['domains']:
		if not cert_isValid(domain, config['domains'][domain]):
			cert_get(domain, config['domains'][domain])
