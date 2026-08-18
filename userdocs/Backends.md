# Destinations (Backends)

`REPO=` (and `DEST=` for `RESTORE`) accepts three kinds of destination.
AmiSnap picks which one based on the string's own prefix -- no separate
switch needed.

## Mounted volume (Tier 1)

Anything that isn't a `http://`, `https://`, or `s3://` URL is treated
as a plain AmigaDOS path: a volume (`Backup:`), an assign, or a
subdirectory (`Backup:MyRepo`), or a DOS device provided by a network
filesystem handler (`smbfs`, `AmiNFS`, or similar mounted as a normal
device). This is Tier 1 -- the primary target, and the fastest: a
trusted LAN NAS mounted this way runs at wire speed, with no networking
library or TLS overhead at all.

```
AmiSnap ACTION=SNAPSHOT SOURCE=Work: REPO=Backup:MyRepo
```

## WebDAV (`http://` / `https://`)

```
REPO=http://[user[:pass]@]host[:port][/path]
REPO=https://[user[:pass]@]host[:port][/path]
```

Needs `bsdsocket.library` (any TCP/IP stack). `https://` additionally
needs `AmiSSL` v5, soft-loaded only when actually required -- AmiSnap
runs fine without it installed as long as no destination in a given run
uses `https://`.

- **TLS version**: defaults to TLS 1.2. Add the `TLS13` switch to allow
  TLS 1.3 for the run.
- **Certificate verification**: on by default -- trust is a core design
  principle of this project, not an afterthought. Add
  `TLSINSECURE` to disable it entirely, for a self-signed certificate on
  a home-lab NAS/WebDAV server -- a deliberate, explicit opt-out, never
  a default.
- **Cipher selection**: `CIPHERS=<list>` forces a specific cipher/list.
  This is a CPU-budget lever for accelerated hardware, not a security
  setting -- see [Performance](Performance.md) for the measured
  reasoning.

## S3-compatible object storage (`s3://`)

```
REPO=s3://[access_key:secret_key@]host[:port]/bucket[/prefix][?region=<region>]
```

Also needs `bsdsocket.library`. If the URL has no embedded credentials,
AmiSnap reads `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` (and
`AWS_REGION`/`AWS_DEFAULT_REGION` for the region, if `?region=` wasn't
given either) from the environment instead -- if neither source has
credentials, the run fails with a clear message rather than attempting
an unsigned request. With no region given at all, `us-east-1` is used.

Large files are uploaded via real S3 multipart upload once buffered data
crosses S3's own 5 MiB minimum part size, so restoring or writing a
large object never depends on holding the whole thing in memory at once.

TLS for `s3://` (an `s3s://` scheme, or similar) is not implemented yet
-- `s3://` is plaintext HTTP only for now, independent of `https://`'s
own TLS support above.

> **Note:** because AmigaDOS `ReadArgs()` delimits an unquoted keyword
> value on the first unescaped `=` it meets, a `REPO=` value containing
> a second `=` (e.g. an explicit `?region=eu-west-1`) cannot currently
> be passed safely on the command line, quoted or not -- the built-in
> `us-east-1` default, or the `AWS_REGION` environment variable, are the
> reliable ways to select a region today.

## Encryption is independent of the destination

Any of the three destinations above may hold an encrypted repository
(`CIPHER=1`) -- see [Encryption](Encryption.md). Encryption is a
property of the repository itself (set once at `INIT`), not of which
kind of destination you chose.
