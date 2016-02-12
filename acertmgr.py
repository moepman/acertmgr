#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Automated Certificate Manager using ACME
# Copyright (c) Markus Hauschild, 2016.


import acme_tiny
import datetime
import dateutil.parser
import dateutil.relativedelta
import grp
import os
import pwd
import re
import shutil
import subprocess
import tempfile
import threading
import yaml

try:
	from SimpleHTTPServer import SimpleHTTPRequestHandler
except ImportError:
	from http.server import SimpleHTTPRequestHandler

try:
	from SocketServer import TCPServer as HTTPServer
except ImportError:
	from http.server import HTTPServer

ACME_DIR="/etc/acme/"
ACME_CONF=ACME_DIR + "acme.conf"
ACME_CONFD=ACME_DIR + "domains.d/"


class FileNotFoundError(OSError):
    pass


class InvalidCertificateError(Exception):
	pass

# @brief custom request handler for ACME challenges
# @note current working directory is temporarily changed by the script before
#       the webserver starts, which allows using SimpleHTTPRequestHandler
class ACMERequestHandler(SimpleHTTPRequestHandler):
	# @brief remove directories from GET URL
	# @details the current working directory contains the challenge files,
	#          there is no need for creating subdirectories for the path
	#          that ACME expects.
	#          Additionally, this allows redirecting the ACME path to this
	#          webserver without having to know which subdirectory is
	#          redirected, which simplifies integration with existing
	#          webservers.
	def translate_path(self, path):
		spath = path.split('/')
		assert(spath[0] == '')
		spath = spath[1:]
		if spath[0] == '.well-known':
			spath = spath[1:]
		if spath[0] == 'acme-challenge':
			spath = spath[1:]
		assert(len(spath) == 1)
		spath.insert(0, '')
		path = '/'.join(spath)
		return SimpleHTTPRequestHandler.translate_path(self, path)

# @brief start the standalone webserver
# @param server the HTTPServer object
# @note this function is used to be passed to threading.Thread
def start_standalone(server):
	server.serve_forever()

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

		m = re.search(b"notBefore=(.+)", vc)
		if m:
			valid_from = dateutil.parser.parse(m.group(1), ignoretz=True)
		else:
			raise InvalidCertificateError("No notBefore date found")

		m = re.search(b"notAfter=(.+)", vc)
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

	_, csr_file = tempfile.mkstemp(".csr", "%s." % domain)
	_, crt_file = tempfile.mkstemp(".crt", "%s." % domain)

	challenge_dir = settings.get("webdir", "/var/www/acme-challenge/")
	if not os.path.isdir(challenge_dir):
		raise FileNotFoundError("Challenge directory (%s) does not exist!" % challenge_dir)

	if settings['mode'] == 'standalone':
		port = settings.get('port', 80)

		current_dir = os.getcwd()
		os.chdir(challenge_dir)
		HTTPServer.allow_reuse_address = True
		server = HTTPServer(("", port), ACMERequestHandler)
		server_thread = threading.Thread(target=start_standalone, args=(server, ))
		server_thread.start()

	try:
		cr = subprocess.check_output(['openssl', 'req', '-new', '-sha256', '-key', key_file, '-out', csr_file, '-subj', '/CN=%s' % domain])

		# get certificate
		crt = acme_tiny.get_crt(acc_file, csr_file, challenge_dir)
		with open(crt_file, "w") as crt_fd:
			crt_fd.write(crt)

		#  if resulting certificate is valid: store in final location
		if cert_isValid(crt_file, 60):
			crt_final = ACME_DIR + "%s.crt" % domain
			shutil.copy2(crt_file, crt_final)

	finally:
		if settings['mode'] == 'standalone':
			os.chdir(current_dir)
			server.shutdown()
			server_thread.join()
		os.remove(csr_file)
		os.remove(crt_file)


# @brief put new certificate in place
# @param domain string containing the domain name
# @param settings the domain's configuration options
def cert_put(domain, settings):
	# TODO error handling
	crt_user = settings['user']
	crt_group = settings['group']
	crt_perm = settings['perm']
	crt_path = settings['path']
	crt_format = settings['format'].split(",")
	crt_notify = settings['notify']

	key_file = ACME_DIR + "server.key"
	crt_final = ACME_DIR + "%s.crt" % domain

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
			else:
				# TODO error handling
				pass

	# set owner and permissions
	uid = pwd.getpwnam(crt_user).pw_uid
	gid = grp.getgrnam(crt_group).gr_gid
	os.chown(crt_path, uid, gid)
	os.chmod(crt_path, int(crt_perm, 8))

	# restart/reload service
	subprocess.call(crt_notify.split())


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
