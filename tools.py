#!/usr/bin/env python
# -*- coding: utf-8 -*-

# acertmgr - various support functions
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE

import base64
import binascii
import datetime
import os
import hashlib
import io
import six

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID

try:
    from urllib.request import urlopen  # Python 3
except ImportError:
    from urllib2 import urlopen  # Python 2


class InvalidCertificateError(Exception):
    pass


# @brief retrieve notBefore and notAfter dates of a certificate file
# @param cert_file the path to the certificate
# @return the tuple of dates: (notBefore, notAfter)
def get_cert_valid_times(cert_file):
    with io.open(cert_file, 'r') as f:
        cert_data = f.read().encode('utf-8')
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    return cert.not_valid_before, cert.not_valid_after


# @brief check whether existing certificate is still valid or expiring soon
# @param crt_file string containing the path to the certificate file
# @param ttl_days the minimum amount of days for which the certificate must be valid
# @return True if certificate is still valid for at least ttl_days, False otherwise
def is_cert_valid(crt_file, ttl_days):
    if not os.path.isfile(crt_file):
        return False
    else:
        (valid_from, valid_to) = get_cert_valid_times(crt_file)

        now = datetime.datetime.now()
        if valid_from > now:
            raise InvalidCertificateError("Certificate seems to be from the future")

        expiry_limit = now + datetime.timedelta(days=ttl_days)
        if valid_to < expiry_limit:
            return False

        return True


# @brief create a certificate signing request
# @param names list of domain names the certificate should be valid for
# @param key the key to use with the certificate in pyopenssl format
# @return the CSR in pyopenssl format
def new_cert_request(names, key):
    # TODO: There has to be a better way to ensure correct text type (why typecheck, cryptography?)
    primary_name = x509.Name([x509.NameAttribute(
        NameOID.COMMON_NAME,
        names[0] if isinstance(names[0], six.text_type) else names[0].decode('utf-8'))
    ])
    all_names = x509.SubjectAlternativeName([x509.DNSName(
        name if isinstance(name, six.text_type) else name.decode('utf-8')
    ) for name in names])
    req = x509.CertificateSigningRequestBuilder()
    req = req.subject_name(primary_name)
    req = req.add_extension(all_names, critical=False)
    req = req.sign(key, hashes.SHA256(), default_backend())
    return req


# @brief generate a new rsa key
# @param path path where the new key file should be written
def new_rsa_key(path, key_size=4096):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with io.open(path, 'wb') as pem_out:
        pem_out.write(pem)
    try:
        os.chmod(path, int("0400", 8))
    except OSError:
        print('Warning: Could not set file permissions on {0}!'.format(path))


# @brief download the issuer ca for a given certificate
# @param cert_file certificate file
# @param ca_file destination for the ca file
def download_issuer_ca(cert_file, ca_file):
    with io.open(cert_file, 'r') as f:
        cert_data = f.read().encode('utf-8')
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)

    ca_issuers = None
    for data in aia.value:
        if data.access_method == x509.OID_CA_ISSUERS:
            ca_issuers = data.access_location.value
            break

    if not ca_issuers:
        raise Exception("Could not determine issuer CA for {}".format(cert_file))

    print("Downloading CA certificate from {} to {}".format(ca_issuers, ca_file))
    cadata = urlopen(ca_issuers).read()
    cacert = x509.load_der_x509_certificate(cadata, default_backend())
    pem = cacert.public_bytes(encoding=serialization.Encoding.PEM)
    with io.open(ca_file, 'wb') as pem_out:
        pem_out.write(pem)


# @brief convert certificate to PEM format
# @param cert certificate object in pyopenssl format
# @return the certificate in PEM format
def convert_cert_to_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode('utf8')


# @brief read a key from file
# @param path path to key file
# @return the key in pyopenssl format
def read_key(path):
    with io.open(path, 'r') as f:
        key_data = f.read().encode('utf-8')
    return serialization.load_pem_private_key(key_data, None, default_backend())


# @brief helper function to base64 encode for JSON objects
# @param b the string to encode
# @return the encoded string
def to_json_base64(b):
    return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")


# @brief convert numbers to byte-string
# @param num number to convert
# @return byte-string containing the number
def byte_string_format(num):
    n = format(num, 'x')
    n = "0{0}".format(n) if len(n) % 2 else n
    return binascii.unhexlify(n)


# @brief convert a string to an ID
# @param data data to convert to id
# @return unique id string
def to_unique_id(data):
    return hashlib.md5(data.encode('utf-8')).hexdigest()
