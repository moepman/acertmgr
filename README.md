ACERTMGR
========

This is an automated certificate manager using ACME/letsencrypt.

Running ACERTMGR
----------------

The main file acertmgr.py is intended to be run regularly (e.g. as daily cron job) as root.

Requirements
------------

  * Python (2.7+ and 3.3+ should work)
  * python-dateutil
  * PyYAML
  * pyOpenSSL

Initial Setup
-------------

First, you need to provide two key files for the ACME protocol:
  * The account key is expected at `/etc/acme/account.key`
  * The domain key is expected at `/etc/acme/server.key` (note: only one domain key is required for all domains used in the same instance of acertmgr)
If you are missing these keys, you can create them using `openssl genrsa 4096 > /etc/acme/account.key` and `openssl genrsa 4096 > /etc/acme/server.key` respectively.
  * Do not forget to set proper permissions of the keys using `chmod 0400 /etc/acme/*.key`

Secondly, you should download the letsencrypt CA certificate:
  * wget -O /etc/acme/lets-encrypt-x3-cross-signed.pem https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem
  * The path to this file must be entered in the configuration, see below.

Thirdly, you should decide which challenge mode you want to use with acertmgr
  * webdir: In this mode, challenges are put into a directory, and served by an existing webserver. Make sure the target directory exists!
  * standalone: In this mode, challenges are completed by acertmgr directly.
    This starts a webserver to solve the challenges, which can be used standalone or together with an existing webserver that forwards request to a specified local port.

Finally, you need to setup the configuration files, as shown in the next section.
While testing, you can use the acme-staging authority instead, so you avoid issuing too many certificates.

Configuration
-------------

The main configuration is read from `/etc/acme/acme.conf`, domains for which certificates should be obtained/renewed should be configured in `/etc/acme/domains.d/{fqdn}.conf`.

All configuration files use yaml syntax.

  * Example global configuration file:
```yaml
---

mode: webdir
#mode: standalone
#port: 13135
webdir: /var/www/acme-challenge/
authority: "https://acme-v01.api.letsencrypt.org"
#authority: "https://acme-staging.api.letsencrypt.org"

defaults:
  cafile: /etc/acme/lets-encrypt-x3-cross-signed.pem

```

  * Example domain configuration file:

```yaml
---

mail.example.com:
- path: /etc/postfix/ssl/mail.key
  user: postfix
  group: postfix
  perm: '400'
  format: key
  action: '/etc/init.d/postfix reload'
- path: /etc/postfix/ssl/mail.crt
  user: postfix
  group: postfix
  perm: '400'
  format: crt
  action: '/etc/init.d/postfix reload'
- path: /etc/dovecot/ssl/mail.crt
  user: dovecot
  group: dovecot
  perm: '400'
  action: '/etc/init.d/dovecot reload'

jabber.example.com:
- path: /etc/ejabberd/server.pem
  user: jabber
  group: jabber
  perm: '400'
  format: key,crt,ca
  action: '/etc/init.d/ejabberd restart'

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
```

Security
--------

Please keep the following in mind when using this software:

  * DO read the source code, since it is intended to be run as root
  * Make sure that your configuration files are NOT writable by other users - arbitrary commands can be executed after updating certificates
