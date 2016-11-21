#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       httpsclientauth.py
#
#       Hannes Fuchs <hannes.fuchs@gmx.org> / <hannes.fuchs@o-s.de>
#
#       This file is part of Monitoring python library.
#
#           Monitoring python library is free software: you can redistribute it and/or modify
#           it under the terms of the GNU General Public License as published by
#           the Free Software Foundation, either version 3 of the License, or
#           (at your option) any later version.
#
#           Monitoring python library is distributed in the hope that it will be useful,
#           but WITHOUT ANY WARRANTY; without even the implied warranty of
#           MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#           GNU General Public License for more details.
#
#           You should have received a copy of the GNU General Public License
#           along with Monitoring python library.  If not, see <http://www.gnu.org/licenses/>.
import urllib2
import httplib
import socket
import ssl

class HTTPSClientAuthConnection(httplib.HTTPSConnection):
    '''Class to create a https connection with support for full client-based ssl authentication
    If there are no certificates defined, no check will be made. So it is possible to only check the
    server certificate against a ca_certs file. So following is possible:
    1. do a server certificate check (no key_file, no cert_file, only a ca_certs file)
    2a. do client certificate authentication without server certificate check (key_file, cert_file, no ca_certs file)
    2b. do client certificate authentication with server certificate check (key_file, cert_file, ca_certs file)
    See http://code.activestate.com/recipes/577548-https-httplib-client-connection-with-certificate-v/'''
    def __init__(self, host, port=None, key_file=None, cert_file=None, ca_certs=None, timeout=None):
        httplib.HTTPSConnection.__init__(self, host, port=port, key_file=key_file, cert_file=cert_file, timeout=timeout)
        self.key_file = key_file
        self.cert_file = cert_file
        self.ca_certs = ca_certs
        self.timeout = timeout

    def connect(self):
    '''Connect to a host on a given (SSL) port.
    If ca_file is pointing somewhere, use it to check Server Certificate.
    Redefined/copied and extended from httplib.py:1105 (Python 2.6.x).
    This is needed to pass cert_reqs=ssl.CERT_REQUIRED as parameter to ssl.wrap_socket(),
    which forces SSL to check server certificate against our client certificate.'''
        sock = socket.create_connection((self.host, self.port), self.timeout)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()

        # If there's no CA File, don't force Server Certificate Check
        if self.ca_certs:
            self.sock = ssl.wrap_socket(sock, keyfile=self.key_file, certfile=self.cert_file, cert_reqs=ssl.CERT_REQUIRED, ca_certs=self.ca_certs)
        else:
            self.sock = ssl.wrap_socket(sock, keyfile=self.key_file, certfile=self.cert_file, cert_reqs=ssl.CERT_NONE)


class HTTPSClientAuthHandler(urllib2.HTTPSHandler):
    '''Handler to use the customized HTTPSClientAuthConnection, which could be used with the
    urllib2.build_opener().
    see http://stackoverflow.com/questions/1875052/using-paired-certificates-with-urllib2 '''
    def __init__(self, key_file=None, cert_file=None, ca_certs=None):
        urllib2.HTTPSHandler.__init__(self)
        self.key_file = key_file
        self.cert_file = cert_file
        self.ca_certs = ca_certs

    def https_open(self, req):
        return self.do_open(self.get_connection, req)

    def get_connection(self, host, timeout=None):
        return HTTPSClientAuthConnection(host, key_file=self.key_file, cert_file=self.cert_file, ca_certs=self.ca_certs, timeout=timeout)
