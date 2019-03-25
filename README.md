ACERTMGR
========

This is an automated certificate manager using ACME/letsencrypt with minimal dependencies.

Running ACERTMGR
----------------

The main file acertmgr.py is intended to be run regularly (e.g. as daily cron job / systemd timer) as root or user with enough privileges.

Requirements
------------

  * Python (2.7+ and 3.5+ should work)
  * cryptography

Optional packages
-----------------

  * PyYAML (when using config files in YAML format)
  * dnspython (required for the dns.nsupdate mode)
  * idna (for automatically translating to the IDNA representation of unicode domain names)

Initial Setup
-------------

You should decide which challenge mode you want to use with acertmgr:
  * webdir: In this mode, responses to challenges are put into a directory, to be served by an existing webserver
  * standalone: In this mode, challenges are completed by acertmgr directly.
    This starts a webserver to solve the challenges, which can be used standalone or together with an existing webserver that forwards request to a specified local port
  * webdir/standalone: Make sure that the `webdir` directory exists in both cases (Note: the standalone webserver does not yet serve the files in situation)
  * dns.*: This mode puts the challenge into a TXT record for the domain (usually _acme-challenge.<domain>) where it will be parsed from by the authority
  * dns.* (Alias mode): Can be used similar to the above but allows redirection of _acme-challenge.<domain> to any other (updatable domain) defined in dns_updatedomain via CNAME (e.g. _acme-challenge.example.net IN CNAME bla.foo.bar with config dns_updatedomain="bla.foo.bar" in config)
  * dns.nsupdate: Updates the TXT record using RFC2136 (with dnspython)

You can optionally provide the private key files to be used with the ACME protocol (if you do not they will be automatically created):
  * The account private key is (by default) expected at `/etc/acertmgr/account.key` (used to register an account with the authorities server)
  * The domain private keys are (by default) expected at `/etc/acertmgr/{certificate-hash}.key`
  * If you are missing these keys, they will be created for you or you can create them using e.g. `openssl genrsa 4096 > /etc/acertmgr/account.key`
  * Do not forget to set proper permissions of the keys using `chmod 0400 /etc/acertmgr/*.key`

Finally, you need to setup the configuration files, as shown in the next section.
While testing, you can use the acme-staging authority instead, in order to avoid issuing too many certificates.

Authorities (e.g. our default Let's Encrypt) will require you to accept their Terms of Service. This can be done either in the optional global config file and/or via a commandline parameter (see acertmgr.py --help).

Configuration
-------------

Unless specified with a commandline parameter (see acertmgr.py --help) the optional global configuration is read from '/etc/acertmgr/acertmgr.conf'.
Domains for which certificates should be obtained/renewed should be configured in `/etc/acertmgr/*.conf` (the global configuration is always excluded if it is in the same directory).
By default the directory containing the working data (work_dir) is located at `/etc/acertmgr/`.

All configuration files can use yaml (requires PyYAML) or json syntax. *Examples can be found in the docs/ directory* (Note: The JSON examples may be incomplete due to inability to express comments in JSON)

4 configuration contexts are known: *domainconfig (d) > globalconfig (g) > commandline (c) > built-in defaults*
The following the directives are currently known (subject to change, recommended context for usage written bold):

| Directive               | Context           | Description                                                                                                                                  | Built-in Default                     |
| ---                     | ---               | ---                                                                                                                                          | ---                                  |
| < domains >:            | **d**             | (domainconfig header) Domains to use in the cert request, will be MD5 hashed as cert_id                                                      |                                      |
| api                     | d,**g**           | Determines the API version used                                                                                                              | v2                                   |
| authority               | d,**g**           | URL to the certificate authorities API                                                                                                       | https://acme-v02.api.letsencrypt.org |
| authority_tos_agreement | d,**g**,**c**     | Indicates agreement to the ToS of the certificate authority                                                                                  |                                      |
| authority_contact_email | d,**g**           | (v2 API only) Contact e-mail to be registered with your account key                                                                          |                                      |
| account_key             | d,**g**           | Path to the account key                                                                                                                      | {work_dir}/account.key               |
| ttl_days                | d,**g**           | Renew certificate if it has less than this value validity left                                                                               | 30                                   |
| cert_dir                | d,**g**           | Directory containing all certificate related data (crt,key,csr)                                                                              | {work_dir}                           |
| csr_static              | **d**,g           | Whether to re-use a static CSR or generate a new dynamic CSR                                                                                 | false                                |
| csr_file                | **d**,g           | Path to store (and load) the certificate CSR file                                                                                            | {cert_dir}/{cert_id}.csr             |
| ca_file                 | **d**,g           | Path to store (and load) the certificate authority file                                                                                      | {cert_dir}/{cert_id}.ca              |
| cert_file               | **d**             | Path to store (and load) the certificate file                                                                                                | {cert_dir}/{cert_id}.crt             |
| key_file                | **d**,g           | Path to store (and load) the private key file                                                                                                | {cert_dir}/{cert_id}.key             |
| key_length              | d,**g**           | Key-length for newly generated private keys                                                                                                  | 4096                                 |
| mode                    | **d**,g           | Mode of challenge handling used                                                                                                              | standalone                           |
| webdir                  | **d**,g           | [webdir] Put acme challenges into this path                                                                                                  |                                      |
| port                    | **d**,g           | [standalone] Serve the challenge using a HTTP server on this port                                                                            | 80                                   |
| dns_ttl                 | **d**,g           | [dns.*] Write TXT records with this TTL (also determines the update wait time at twice this value                                            | 60                                   |
| dns_updatedomain        | **d**,g           | [dns.*] Write the TXT records to this domain (you have to create the necessary CNAME on the real challenge domain manually)                  |                                      |
| nsupdate_server         | **d**,g           | [dns.nsupdate] DNS Server to delegate the update to                                                                                          | <determine from zone SOA>            |
| nsupdate_keyfile        | **d**,g           | [dns.nsupdate] Bind-formatted TSIG key file to use for updates (may be used instead of nsupdate_key*)                                        |                                      |
| nsupdate_keyname        | **d**,g           | [dns.nsupdate] TSIG key name to use for updates                                                                                              |                                      |
| nsupdate_keyvalue       | **d**,g           | [dns.nsupdate] TSIG key value to use for updates                                                                                             |                                      |
| nsupdate_keyalgorithm   | **d**,g           | [dns.nsupdate] TSIG key algorithm to use for updates                                                                                         |                                      |
| defaults:               | **g**             | Deployment action defaults                                                                                                                   |                                      |
| path                    | **d**             | (deployment) deploy certificate data to the given file                                                                                       |                                      |
| user                    | **d**,g(defaults) | (deployment) change the user of the file deployed at path to this value                                                                      |                                      |
| group                   | **d**,g(defaults) | (deployment) change the group of the file deployed at path to this value                                                                     |                                      |
| perm                    | **d**,g(defaults) | (deployment) change the permissions of the file deployed at path to this value                                                               |                                      |
| format                  | **d**,g(defaults) | (deployment) deploy one or more of the following data to the file at path: key,crt,ca                                                        |                                      |
| action                  | **d**,g(defaults) | (deployment) run the following action after deployment is finished. This command will be run in a shell and therefore supports shell syntax. |                                      |


Security
--------

Please keep the following in mind when using this software:

  * DO read the source code, since it (usually) will be run as root
  * Make sure that your configuration files are NOT writable by other users - arbitrary commands can be executed after updating certificates
