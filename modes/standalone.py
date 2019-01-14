#!/usr/bin/env python
# -*- coding: utf-8 -*-

# standalone - standalone ACME challenge webserver
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE

try:
    from SimpleHTTPServer import SimpleHTTPRequestHandler
except ImportError:
    from http.server import SimpleHTTPRequestHandler

try:
    from SocketServer import TCPServer as HTTPServer
except ImportError:
    from http.server import HTTPServer

import os
import threading

from modes.webdir import ChallengeHandler as WebChallengeHandler
import datetime


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
        assert (spath[0] == '')
        spath = spath[1:]
        if spath[0] == '.well-known':
            spath = spath[1:]
        if spath[0] == 'acme-challenge':
            spath = spath[1:]
        assert (len(spath) == 1)
        spath.insert(0, '')
        path = '/'.join(spath)
        return SimpleHTTPRequestHandler.translate_path(self, path)


# @brief start the standalone webserver
# @param server the HTTPServer object
# @note this function is used to be passed to threading.Thread
def start_standalone(server):
    server.serve_forever()


HTTPServer.allow_reuse_address = True


class ChallengeHandler(WebChallengeHandler):
    def __init__(self, config):
        WebChallengeHandler.__init__(self, config)
        self.current_directory = os.getcwd()
        if "port" in config:
            port = int(config["port"])
        else:
            port = 80
        self.server_thread = None
        self.server = HTTPServer(("", port), ACMERequestHandler)

    def create_challenge(self, domain, thumbprint, token):
        WebChallengeHandler.create_challenge(self, domain, thumbprint, token)
        self.server_thread = threading.Thread(target=start_standalone, args=(self.server,))
        os.chdir(self.challenge_directory)
        self.server_thread.start()
        return datetime.datetime.now()

    def destroy_challenge(self, domain, thumbprint, token):
        self.server.shutdown()
        self.server_thread.join()
        os.chdir(self.current_directory)
        WebChallengeHandler.destroy_challenge(self, domain, thumbprint, token)
