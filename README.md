ACERTMGR
========

This is an automated certificate manager using ACME/letsencrypt.

Running ACERTMGR
----------------

The main file acertmgr.py is intended to be run regularly (e.g. as daily cron job) as root.

Requirements
------------

  * Python (2.7+ and 3.3+ should work)
  * cryptography

Optional packages
-----------------

  * PyYAML (when using config files in YAML format)
  * dnspython (required for the dns.nsupdate mode)

Initial Setup
-------------

You should decide which challenge mode you want to use with acertmgr:
  * webdir: In this mode, challenges are put into a directory, and served by an existing webserver
  * standalone: In this mode, challenges are completed by acertmgr directly.
    This starts a webserver to solve the challenges, which can be used standalone or together with an existing webserver that forwards request to a specified local port
  * webdir/standalone: Make sure that the `webdir` directory exists in both cases (Note: the standalone webserver does not yet serve the files in situation)
  * dns.*: This mode puts the challenge into a TXT record for the domain (usually _acme-challenge.<domain>) where it will be parsed from by the authority
  * dns.* (Alias mode): Can be used similar to the above but allows redirection of _acme-challenge.<domain> to any other (updatable domain) defined in dns_updatedomain via CNAME (e.g. _acme-challenge.example.net IN CNAME bla.foo.bar with config dns_updatedomain="bla.foo.bar" in config)
  * dns.nsupdate: Updates the TXT record using RFC2136 (with dnspython)

You can optionally provide the key files for the ACME protocol, if you do not they will be automatically created:
  * The account key is expected at `/etc/acertmgr/account.key`
  * The domain key is expected at `/etc/acertmgr/server.key` (Note: only one domain key is required for all domains used in the same instance of acertmgr)
  * If you are missing these keys, they will be created for you or you can create them using `openssl genrsa 4096 > /etc/acertmgr/account.key` and `openssl genrsa 4096 > /etc/acertmgr/server.key` respectively
  * Do not forget to set proper permissions of the keys using `chmod 0400 /etc/acertmgr/*.key`

Finally, you need to setup the configuration files, as shown in the next section.
While testing, you can use the acme-staging authority instead, in order to avoid issuing too many certificates.

Authorities (e.g. our default Let's Encrypt) will require you to accept their Terms of Service. This can be done either in the optional global config file and/or via a commandline parameter (see acertmgr.py --help).

Configuration
-------------

Unless specified with a commandline parameter (see acertmgr.py --help) the optional global configuration is read from '/etc/acertmgr/acertmgr.conf'.
Domains for which certificates should be obtained/renewed should be configured in `/etc/acertmgr/*.conf` (the global configuration is always excluded if it is in the same directory).

All configuration files can use yaml (requires PyYAML) or json syntax.

  * Example optional global configuration file (YAML syntax):

```yaml
---
# Optional: Authority API endpoint to use
# Legacy ACME v1 API with options:
#api: v1
#authority: "https://acme-v01.api.letsencrypt.org"
#authority: "https://acme-staging.api.letsencrypt.org"
#authority_tos_agreement: "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf"
# Current (default) ACME v2 API with options:
#api: v2
#authority: "https://acme-v02.api.letsencrypt.org"
#authority: "https://acme-staging-v02.api.letsencrypt.org"
authority_tos_agreement: "true" # Indicates you agree to the ToS stated by the API provider
#authority_contact_email: "foo@b.ar" # For single addresses
#authority_contact_email:            # For multiple addresses
#  - "foo@b.ar"
#  - "c4f3@b.ar"

# Optional: account_key location. This defaults to "/etc/acertmgr/account.key"
#account_key: "/etc/acertmgr/account.key"

# Optional: global server_key location. Otherwise separate key per server
#server_key: "/etc/acertmgr/server.key"

# Optional: global challenge handling mode with parameters
#mode: webdir
#webdir: /var/www/acme-challenge/
#mode: standalone
#port: 13135
```

  * Example domain configuration file (YAML syntax):

```yaml
---

mail.example.com:
- path: /etc/postfix/ssl/mail.key
  user: root
  group: root
  perm: '400'
  format: key
  action: '/etc/init.d/postfix reload'
- path: /etc/postfix/ssl/mail.crt
  user: root
  group: root
  perm: '400'
  format: crt,ca
  action: '/etc/init.d/postfix reload'

jabber.example.com:
- path: /etc/ejabberd/server.pem
  user: jabber
  group: jabber
  perm: '400'
  format: key,crt,ca
  action: '/etc/init.d/ejabberd restart'

# this will create a certificate with subject alternative names
www.example.com example.com:
- path: /var/www/ssl/cert.pem
  user: apache
  group: apache
  perm: '400'
  action: '/etc/init.d/apache2 reload'
  format: crt,ca
- path: /var/www/ssl/key.pem
  user: apache
  group: apache
  perm: '400'
  action: '/etc/init.d/apache2 reload'
  format: key

# this will create a certificate with subject alternative names
# using a different challenge handler for one domain
# wildcards are possible with api v2 and dns challenge modes only!
mail.example.com smtp.example.com webmail.example.net *.intra.example.com:
- mode: dns.nsupdate
  nsupdate_server: ns1.example.com
  nsupdate_keyname: mail
  nsupdate_keyvalue: Test1234512359==
- domain: webmail.example.net
  mode: dns.nsupdate
  nsupdate_server: ns1.example.net
  nsupdate_keyname: webmail.
  nsupdate_keyfile: /etc/nsupdate.key
  dns_updatedomain: webmail.example.net
- path: /etc/postfix/ssl/mail.key
  user: root
  group: root
  perm: '400'
  format: key
  action: '/etc/init.d/postfix reload'
- path: /etc/postfix/ssl/mail.crt
  user: root
  group: root
  perm: '400'
  format: crt,ca
  action: '/etc/init.d/postfix reload'

```

  * Example optional global configuration file (JSON syntax):

```json
---
{
"mode": "standalone",
"port": "80",

"account_key": "/etc/acertmgr/acc.key",
"server_key": "/etc/acertmgr/serv.key",

"webdir": "/var/www/acme-challenge/",
"authority": "https://acme-v01.api.letsencrypt.org",
}
```

  * Example domain configuration file (JSON syntax):

```json
---
{
"mail.example.com": [
{ "path": "/etc/postfix/ssl/mail.key",
  "user": "root",
  "group": "root",
  "perm": "400",
  "format": "key",
  "action": "/etc/init.d/postfix reload" },
{ "path": "/etc/postfix/ssl/mail.crt",
  "user": "root",
  "group": "root",
  "perm": "400",
  "format": "crt,ca",
  "action": "/etc/init.d/postfix reload" }
],
"jabber.example.com": [
{ "path": "/etc/ejabberd/server.pem",
  "user": "jabber",
  "group": "jabber",
  "perm": "400",
  "format": "key,crt,ca",
  "action": "/etc/init.d/ejabberd restart" }
],
"www.example.com example.com": [
{ "path": "/var/www/ssl/cert.pem",
  "user": "apache",
  "group": "apache",
  "perm": "400",
  "action": "/etc/init.d/apache2 reload",
  "format": "crt,ca" },
{ "path": "/var/www/ssl/key.pem",
  "user": "apache",
  "group": "apache",
  "perm": "400",
  "action": "/etc/init.d/apache2 reload",
  "format": "key" }
]
}
```

Security
--------

Please keep the following in mind when using this software:

  * DO read the source code, since it has to be run as root
  * Make sure that your configuration files are NOT writable by other users - arbitrary commands can be executed after updating certificates
