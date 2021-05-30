ACERTMGR
========

This is an automated certificate manager using ACME/letsencrypt with minimal dependencies.

Running ACERTMGR
----------------

The main file acertmgr.py is intended to be run regularly (e.g. as daily cron job / systemd timer) as root or user with enough privileges.

Requirements
------------

  * Python (2.7+ and 3.5+ should work)
  * cryptography>=2.1 (older versions break idna handling)

Optional requirements (to use specified features)
------------------------------------------------------

  * PyYAML: to parse YAML-formatted configuration files
  * dnspython: used by dns.* challenge handlers
  * idna: to allow automatic conversion of unicode domain names to their IDNA2008 counterparts
  * cryptography>=2.1: for creating certificates with the OCSP must-staple flag (cert_must_staple)
  * cryptography>=2.6: for usage of Ed25519/Ed448 keys

Setup
-----

You should decide which challenge mode you want to use with acertmgr:
  * webdir: In this mode, responses to challenges are put into a directory, to be served by an existing webserver
  * standalone: In this mode, challenges are completed by acertmgr directly. This starts a webserver to solve the challenges, which can be used standalone or together with an existing webserver that forwards request to a specified local port/address.
  * dns.*: This mode puts the challenge into a TXT record for the domain (usually _acme-challenge.<domain>) where it will be parsed from by the authority
  * dns.* (Alias mode): Can be used similar to the above but allows redirection of _acme-challenge.<domain> to any other (updatable domain) defined in dns_updatedomain via CNAME (e.g. _acme-challenge.example.net IN CNAME bla.foo.bar with dns_updatedomain="bla.foo.bar" in domainconfig)
  * dns.nsupdate: Updates the TXT record using RFC2136

You can optionally provide the private key files to be used with the ACME protocol (if you do not they will be automatically created):
  * The account private key is (by default) expected at `/etc/acertmgr/account.key` (used to register an account with the authorities server)
  * The domain private keys are (by default) expected at `/etc/acertmgr/{cert_id}.key`
  * If you are missing these keys, they will be created for you (using RSA with the configured key_length) or you can create them using e.g. `openssl genrsa 4096 > /etc/acertmgr/account.key`
  * Do not forget to set proper permissions of the keys using `chmod 0400 /etc/acertmgr/*.key` if you created those manually

Finally, you need to setup the configuration files, as shown in the next section.
While testing, you can use the acme-staging authority instead, in order to avoid issuing too many certificates.

Authorities (e.g. our default Let's Encrypt) will require you to accept their Terms of Service. This can be done either in the optional global config file and/or via a commandline parameter (see acertmgr.py --help).

Configuration
-------------

Configuration examples are included in the `docs/` directory. All configuration files can use yaml (requires PyYAML) or json syntax. (Note: The JSON examples may be incomplete due to inability to express comments in JSON)

Unless specified with a commandline parameter (see acertmgr.py --help) the optional global configuration is read from `/etc/acertmgr/acertmgr.conf`.
Domains for which certificates should be obtained/renewed are be configured in `/etc/acertmgr/*.conf` (the global configuration is always excluded if it is in the same directory).
By default the directory (work_dir) containing the working data (csr,certificate,key and ca files) is located at `/etc/acertmgr/`.

4 configuration contexts are known (*domainconfig (d) > globalconfig (g) > commandline (c) > built-in defaults*) with the following directives (subject to change, usual usage context written bold):

| Directive               | Context           | Description                                                                                                                                  | Built-in Default                     |
| ---                     | ---               | ---                                                                                                                                          | ---                                  |
| -c/--config-file        | **c**             | global configuration file (optional)                                                                                                         | /etc/acertmgr/acertmgr.conf          |
| -d/--config-dir         | **c**             | directory containing domain configuration files (ending with .conf, globalconfig will be excluded automatically if in same directory)        | /etc/acertmgr/*.conf                 |
| -w/--work-dir           | **c**             | working directory containing csr/certificates/keys/ca files                                                                                  | /etc/acertmgr                        |
| --force-renew           | **c**             | (or --renew-now) Immediately renew all certificates containing the given domain(s)                                                           |                                      |
| --revoke                | **c**             | Revoke the certificate at the given path                                                                                                     |                                      |
| --revoke-reason         | **c**             | Provide a reason code for the revocation (see https://tools.ietf.org/html/rfc5280#section-5.3.1 for valid values)                            |                                      |
| domain (san-domain...): | **d**             | (domainconfig section start) Domains to use in the cert request. This value will be MD5-hashed as cert_id.                                   |                                      |
| api                     | d,**g**           | Determines the API version used                                                                                                              | v2                                   |
| authority               | d,**g**           | URL to the certificate authorities API                                                                                                       | https://acme-v02.api.letsencrypt.org |
| authority_tos_agreement | d,**g**,c         | Indicates agreement to the ToS of the certificate authority (--authority-tos-agreement on command line)                                      |                                      |
| authority_contact_email | d,**g**           | (v2 API only) Contact e-mail to be registered with your account key                                                                          |                                      |
| account_key             | d,**g**           | Path to the account key                                                                                                                      | {work_dir}/account.key               |
| account_key_algorithm   | d,**g**           | Key-algorithm for newly generated account keys (RSA, EC, ED25519, ED448)                                                                     | RSA                                  |
| account_key_length      | d,**g**           | Key-length for newly generated RSA account keys (in bits) or EC curve (256=P-256, 384=P-384, 521=P-521)                                      | depends on account_key_algorithm     |
| ttl_days                | d,**g**           | Renew certificate if it has less than this value validity left                                                                               | 30                                   |
| validate_ocsp           | d,**g**           | Renew certificate if it's OCSP status is REVOKED. Allowed values for this key are: false, sha1, sha224, sha256, sha384, sha512               | sha1 (as mandated by RFC5019)        |
| cert_dir                | d,**g**           | Directory containing all certificate related data (crt,key,csr)                                                                              | {work_dir}                           |
| key_algorithm           | d,**g**           | Key-algorithm for newly generated private keys (RSA, EC, ED25519, ED448)                                                                     | RSA                                  |
| key_length              | d,**g**           | Key-length for newly generated RSA private keys (in bits) or EC curve (256=P-256, 384=P-384, 521=P-521)                                      | depends on key_algorithm             |
| csr_static              | **d**,g           | Whether to re-use a static CSR or generate a new dynamic CSR                                                                                 | false                                |
| csr_file                | **d**,g           | Path to store (and load) the certificate CSR file                                                                                            | {cert_dir}/{cert_id}.csr             |
| ca_static               | **d**,g           | Whether to re-use a static CA or download a CA file                                                                                          | false                                |
| ca_file                 | **d**,g           | Path to store (and load) the certificate authority file                                                                                      | {cert_dir}/{cert_id}.ca              |
| cert_file               | **d**             | Path to store (and load) the certificate file                                                                                                | {cert_dir}/{cert_id}.crt             |
| cert_revoke_superseded  | **d**,g           | Revoke the previous certificate with reason "superseded" after successful deployment                                                         | false                                |
| cert_must_staple        | **d**,g           | Generate a certificate (request) with the OCSP must-staple flag (will be honoured on the next newly generated CSR if using csr_static=true)  | false                                |
| key_file                | **d**,g           | Path to store (and load) the private key file                                                                                                | {cert_dir}/{cert_id}.key             |
| mode                    | **d**,g           | Mode of challenge handling used                                                                                                              | standalone                           |
| webdir                  | **d**,g           | [webdir] Put acme challenges into this path                                                                                                  | /var/www/acme-challenge/             |
| http_verify             | **d**,g           | [webdir/standalone] Verify challenge before attempting authorization                                                                         | true                                 |
| bind_address            | **d**,g           | [standalone] Serve the challenge using a HTTP server on given IP                                                                             |                                      |
| port                    | **d**,g           | [standalone] Serve the challenge using a HTTP server on this port                                                                            | 80                                   |
| dns_ttl                 | **d**,g           | [dns.*] Write TXT records with this TTL (also determines the update wait time at twice this value                                            | 60                                   |
| dns_updatedomain        | **d**,g           | [dns.*] Write the TXT records to this domain (you have to create the necessary CNAME on the real challenge domain manually)                  |                                      |
| dns_verify_interval     | **d**,g           | [dns.*] Do verification checks when starting the challenge every {dns_verify_interval} seconds                                               | 10                                   |
| dns_verify_failtime     | **d**,g           | [dns.*] Fail challenge TXT record verification after {dns_verify_failtime} seconds                                                           | {dns_waittime} + 1                   |
| dns_verify_waittime     | **d**,g           | [dns.*] Assume DNS challenges are valid after {dns_verify_waittime}                                                                          | 2 * {dns_ttl}                        |
| dns_verify_all_ns       | **d**,g           | [dns.*] Verify DNS challenges by querying all known zone NS servers (resolved by zone master from SOA or dns_verify_server)                  | false                                |
| dns_verify_server       | **d**,g           | [dns.*] Verify DNS challenges by querying this DNS server unless 'dns_verify_all_ns' is enabled, then use to determine zone NS               |                                      |
| nsupdate_server         | **d**,g           | [dns.nsupdate] DNS Server to delegate the update to                                                                                          | {determine from zone SOA}            |
| nsupdate_verify         | **d**,g           | [dns.nsupdate] Verify TXT record on the update server upon creation                                                                          | true                                 |
| nsupdate_keyfile        | **d**,g           | [dns.nsupdate] Bind-formatted TSIG key file to use for updates (may be used instead of nsupdate_key*)                                        |                                      |
| nsupdate_keyname        | **d**,g           | [dns.nsupdate] TSIG key name to use for updates                                                                                              |                                      |
| nsupdate_keyvalue       | **d**,g           | [dns.nsupdate] TSIG key value to use for updates                                                                                             |                                      |
| nsupdate_keyalgorithm   | **d**,g           | [dns.nsupdate] TSIG key algorithm to use for updates                                                                                         | HMAC-MD5.SIG-ALG.REG.INT             |
| defaults:               | **g**             | Default deployment action settings used by all domains                                                                                       |                                      |
| path                    | **d**             | (deployment) deploy certificate data to the given file                                                                                       |                                      |
| format                  | **d**,g(defaults) | (deployment) deploy one or more of the following data to the file at path: key,crt,ca                                                        |                                      |
| user                    | **d**,g(defaults) | (deployment) change the user of the file deployed at path to this value (optional, defaults to acertmgr current effective user)              |                                      |
| group                   | **d**,g(defaults) | (deployment) change the group of the file deployed at path to this value (optional,defaults to acertmgr current effective group)             |                                      |
| perm                    | **d**,g(defaults) | (deployment) change the permissions of the file deployed at path to this value (optional, CAUTION: uses system defaults for new files)       |                                      |
| action                  | **d**,g(defaults) | (deployment) run the following action after deployment is finished. This command will be run in a shell and supports it's syntax. (optional) |                                      |

Security
--------

Please keep the following in mind when using this software:

  * DO read the source code, since it (usually) will be run as root
  * Make sure that your configuration files are NOT writable by other users - arbitrary commands can be executed after updating certificates
  * Try to run this program non-privileged if possible. This requires you to:
     * Create a dedicated user for acertmgr (e.g. acertmgr)
     * Run a acertmgr as that user (add acertmgr to that users cron!)
     * Access rights to read/write all files configured with the created user
     * Run any programs/scripts defined on cert update as the created user (might need work-arounds with sudo or wrapper scripts)
