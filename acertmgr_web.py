#!/usr/bin/env python
# -*- coding: utf-8 -*-

# acertmgr - ACME challenge webserver
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# available under the ISC license, see LICENSE

try:
	from SimpleHTTPServer import SimpleHTTPRequestHandler
except ImportError:
	from http.server import SimpleHTTPRequestHandler

try:
	from SocketServer import TCPServer as HTTPServer
except ImportError:
	from http.server import HTTPServer

import threading

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

# @brief a simple webserver for challanges
class ACMEHTTPServer:
	# @brief create webserver instance
	# @param port the port to listen on
	def __init__(self, port=80):
		HTTPServer.allow_reuse_address = True
		self.server = HTTPServer(("", port), ACMERequestHandler)

	# @brief start the webserver
	def start(self):
		self.server_thread = threading.Thread(target=start_standalone, args=(self.server, ))
		self.server_thread.start()
	
	# @brief stop the webserver
	def stop(self):
		self.server.shutdown()
		self.server_thread.join()
