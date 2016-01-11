ACERTMGR
========

This is an automated certificate manager using ACME/letsencrypt.

Running ACERTMGR
----------------

The main file acertmgr.py is intended to be run regularly (e.g. as daily cron job) as root.

Requirements
------------

  * Python (2.7+ and 3.4+ should work)
  * PyYAML
  * acme\_tiny (`acme_tiny.py` placed in `/opt/acme/acme_tiny.py`)

Configuration
-------------

The main configuration is read from `/etc/acme/acme.conf`, domains for which certificates should be obtained/renewed should be configured in `/etc/acme/domains.d/{fqdn}.conf`.

All configuration files use yaml syntax.

  * Example global configuration file:
```yaml
---

mode: webdir
#mode: standalone
webdir: /var/www/acme-challenge/

defaults:
  format: split
```

  * Example domain configuration file:

```yaml
---

mail.example.com:
- user: postfix
  group: postfix
  perm: '400'
  notify: '/etc/init.d/postfix reload'
- user: dovecot
  group: dovecot
  perm: '400'
  notify: '/etc/init.d/dovecot reload'
```

Security
--------

Please keep the following in mind when using this software:

  * DO read the source code, since it is intended to be run as root
  * Make sure that your configuration files are NOT writable by other users - arbitrary commands can be executed after updating certificates
