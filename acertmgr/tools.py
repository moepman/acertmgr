#!/usr/bin/env python
# -*- coding: utf-8 -*-

# acertmgr - various support functions
# Copyright (c) Markus Hauschild & David Klaftenegger, 2016.
# Copyright (c) Rudolf Mayerhofer, 2019.
# available under the ISC license, see LICENSE

import base64
import binascii
import datetime
import io
import os

import six
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID, ExtensionOID

try:
    from urllib.request import urlopen, Request  # Python 3
except ImportError:
    from urllib2 import urlopen, Request  # Python 2


class InvalidCertificateError(Exception):
    pass


# @brief wrapper for downloading an url
def get_url(url, data=None, headers=None):
    return urlopen(Request(url, data=data, headers={} if headers is None else headers))


# @brief check whether existing certificate is still valid or expiring soon
# @param crt_file string containing the path to the certificate file
# @param ttl_days the minimum amount of days for which the certificate must be valid
# @return True if certificate is still valid for at least ttl_days, False otherwise
def is_cert_valid(cert, ttl_days):
    now = datetime.datetime.now()
    if cert.not_valid_before > now:
        raise InvalidCertificateError("Certificate seems to be from the future")

    expiry_limit = now + datetime.timedelta(days=ttl_days)
    if cert.not_valid_after < expiry_limit:
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


# @brief generate a new account key
# @param path path where the new key file should be written in PEM format (optional)
def new_account_key(path=None, key_size=4096):
    return new_ssl_key(path, key_size)


# @brief generate a new ssl key
# @param path path where the new key file should be written in PEM format (optional)
def new_ssl_key(path=None, key_size=4096):
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
    if path is not None:
        with io.open(path, 'wb') as pem_out:
            pem_out.write(pem)
        try:
            os.chmod(path, int("0400", 8))
        except OSError:
            print('Warning: Could not set file permissions on {0}!'.format(path))
    return private_key


# @brief read a key from file
# @param path path to file
# @param key indicate whether we are loading a key
# @return the key in pyopenssl format
def read_pem_file(path, key=False):
    with io.open(path, 'r') as f:
        if key:
            return serialization.load_pem_private_key(f.read().encode('utf-8'), None, default_backend())
        else:
            return convert_pem_str_to_cert(f.read())


# @brief write cert data to PEM formatted file
def write_pem_file(crt, path, perms=None):
    with io.open(path, "w") as f:
        f.write(convert_cert_to_pem_str(crt))
    if perms:
        try:
            os.chmod(path, perms)
        except OSError:
            print('Warning: Could not set file permissions ({0}) on {1}!'.format(perms, path))


# @brief download the issuer ca for a given certificate
# @param cert certificate data
# @returns ca certificate data
def download_issuer_ca(cert):
    aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    ca_issuers = None
    for data in aia.value:
        if data.access_method == x509.OID_CA_ISSUERS:
            ca_issuers = data.access_location.value
            break

    if not ca_issuers:
        print("Could not determine issuer CA for given certificate: {}".format(cert))
        return None

    print("Downloading CA certificate from {}".format(ca_issuers))
    resp = get_url(ca_issuers)
    code = resp.getcode()
    if code >= 400:
        print("Could not download issuer CA (error {}) for given certificate: {}".format(code, cert))
        return None

    return x509.load_der_x509_certificate(resp.read(), default_backend())


# @brief convert certificate to PEM format
# @param cert certificate object in pyopenssl format
# @return the certificate in PEM format
def convert_cert_to_pem_str(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode('utf8')


# @brief load a PEM certificate from str
def convert_pem_str_to_cert(certdata):
    return x509.load_pem_x509_certificate(certdata.encode('utf8'), default_backend())


# @brief serialize CSR to DER bytes
def convert_csr_to_der_bytes(data):
    return data.public_bytes(serialization.Encoding.DER)


# @brief load a DER certificate from str
def convert_der_bytes_to_cert(data):
    return x509.load_der_x509_certificate(data, default_backend())


# @brief sign string with key
def signature_of_str(key, string):
    # @todo check why this padding is not working
    # pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    pad = padding.PKCS1v15()
    return key.sign(string.encode('utf8'), pad, hashes.SHA256())


# @brief hash a string
def hash_of_str(string):
    account_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    account_hash.update(string.encode('utf8'))
    return account_hash.finalize()


# @brief helper function to base64 encode for JSON objects
# @param b the byte-string to encode
# @return the encoded string
def bytes_to_base64url(b):
    return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")


# @brief convert numbers to byte-string
# @param num number to convert
# @return byte-string containing the number
def number_to_byte_format(num):
    n = format(num, 'x')
    n = "0{0}".format(n) if len(n) % 2 else n
    return binascii.unhexlify(n)


# @brief check whether existing target file is still valid or source crt has been updated
# @param target string containing the path to the target file
# @param file string containing the path to the certificate file
# @return True if target file is at least as new as the certificate, False otherwise
def target_is_current(target, file):
    if not os.path.isfile(target):
        return False
    target_date = os.path.getmtime(target)
    crt_date = os.path.getmtime(file)
    return target_date >= crt_date
