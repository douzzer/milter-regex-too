# milter-regex-too -- enhanced milter-regex with integrated GeoIP rules and labeling

This is `milter-regex-too`, forked from Daniel Hartmeier's `milter-regex` at version 1.9.
See [the master page for milter-regex](https://www.benzedrine.ch/milter-regex.html) for more on
the original `milter-regex`, currently at version 2.7 (December 12th, 2019).

The most significant enhancement in `milter-regex-too` is GeoIP rules based
on [`libmaxminddb` from MaxMind](https://github.com/maxmind/libmaxminddb/).

## Usage

```
usage: ./milter-regex-too [-d] [-t] [-c config] [-u user] [-p pipe] [-r pidfile] [-j jaildir] [-g <path to GeoIP2 db file>]
```
|Flag   | Meaning
-----------------
|`-d`     | debug mode -- verbose diagnostics and run in foreground
|`-t`     | test config and exit
|`-c config` | use `config` rather than the default `/etc/milter-regex.conf`
|`-u user` | set daemon pseudouser
|`-p pipe` | use `pipe` for the sendmail/milter interface, rather than the default `/var/spool/milter-regex/sock`
|`-r pidfile` | store the PID to `pidfile` at startup
|`-j jaildir` | run chrooted to `jaildir`
|`-g path` | enable GeoIP logic, and use `path` as the MaxMind database

This fork does not (yet) include the following features added in
mainline versions 2.0-2.7:

>2.6: April 26th, 2019
>Make pid file writable only by root, from Ralph Seichter.
>2.4: March 2nd, 2019
>Add -f option to set syslog facility. Patch from Takao Abe.
>2.2: September 25, 2018
>Add -U, -G, and -P options to set pipe user, group, and permissions. Suggested and tested by Ralph Seichter.
>2.0: November 25, 2013
>Add -l option to specify maximum log level.


### Major config file additions relative to mainline `milter-regex`:

* Default to extended regexps, and access basic regexps with a new `b`
  flag

* new action: `whitelist` (same as accept, but omits automatic GeoIP lookups)

* new tests: `connectgeo` `headergeo` `phasedone`

### `connectgeo`

Test the connecting IP address for any GeoIP attribute of interest:

`connectgeo <GeoIP path> <regexp>` where `<GeoIP path>` can be
any leaf in the MaxMind location database,
e.g. `"/country/iso_code"`, and the regexp should match possible
values of that leaf, e.g. `/^(US|CA)$/`.

### `headergeo`

Test for any GeoIP attribute of interest, anywhere in the value of any
header of interest:

`headergeo <regexp matching header name> <regexp to capture IP
address(es) from header value> <GeoIP path> <regexp to test GeoIP
leaf value>`

E.g. to test for any non-US IP addresses in any of the `Received` headers:
```
/^received$/ei /[[(](IPv6:)?([0-9.]+|[0-9a-f:]+)[])]/eig "/country/iso_code" /^US$/ne
```

Note that a new `g` flag can be added to the capturing regexp to cause
matching to iterate over all matching spans in the value, rather than
only the first.

### `phasedone`

Explicitly tests if a particular phase of message evaluation is complete:

`phasedone <regexp>` where the regexp should match one or more of
`connect` `connectgeo` `helo` `envfrom` `envrcpt` `header`
`headergeo` `macro` `body`.
