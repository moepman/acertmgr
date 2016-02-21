ACERTMGR
========

This is an automated certificate manager using ACME/letsencrypt.

Running ACERTMGR
----------------

The main file acertmgr.py is intended to be run regularly (e.g. as daily cron job) as root.

Requirements
------------

  * Python (2.7+ and 3.4+ should work)
  * python-dateutil
  * PyYAML
  * acme\_tiny (`acme_tiny.py` in $PYTHONHOME or $PYTHONPATH or placed next to `acertmgr.py`)

Initial Setup
-------------

First, you need to provide two key files for acme-tiny:
  * The account key is expected at `/etc/acme/account.key`
  * The domain key is expected at `/etc/acme/server.key` (note: only one domain key is required for all domains used in the same instance of acertmgr)
If you are missing these keys, you can create them using `openssl genrsa 4096 > /etc/acme/account.key` and `openssl genrsa 4096 > /etc/acme/server.key` respectively.
Otherwise refer to the acme-timy documentation for how to reuse your existing keys.

Second, you should decide which challenge mode you want to use with acertmgr
  * webdir: In this mode, challenges are put into a directory, and served by an existing webserver. Make sure the target directory exists!
  * standalone: In this mode, challenges are completed by acertmgr directly.
    This starts a webserver to solve the challenges, which can be used standalone or together with an existing webserver that forwards request to a specified local port.

Finally, you need to setup the configuration files, as shown in the next section.

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
cafile: /etc/acme/letencrypt_ca.crt

defaults:
  format: crt
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
```

Security
--------

Please keep the following in mind when using this software:

  * DO read the source code, since it is intended to be run as root
  * Make sure that your configuration files are NOT writable by other users - arbitrary commands can be executed after updating certificates
