ACERTMGR
========

This is an automated certificate manager using ACME/letsencrypt.

Running ACERTMGR
----------------

The main file acertmgr.py is intended to be run regularly (e.g. as daily cron job) as root.

Configuration
-------------

The main configuration is read from `/etc/acme/acme.conf`, domains for which certificates should be obtained/renewed should be configured in `/etc/acme/domains.d/{fqdn}.conf`.

All configuration files use yaml syntax.

  * Example global configuration file:
```yaml
---

mode: webdir
webdir: /var/www/challenges/
```

  * Example domain configuration file:

```yaml
---

mail.example.com:
- user: postfix
  group: postfix
  perm: '400'
- user: dovecot
  group: dovecot
  perm: '400'
```
