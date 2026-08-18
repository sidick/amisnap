# Encryption

Encryption is off by default and entirely opt-in, per repository. A
plain repository (the default) needs no setup at all: just `SNAPSHOT`
straight to `REPO=`. Turning encryption on is a one-time step,
`ACTION=INIT`, run once before the repository's first snapshot.

## Setting up an encrypted repository

```
1.C:> AmiSnap ACTION=INIT REPO=Backup:MyRepo PASSPHRASE
AmiSnap passphrase: ********
Confirm passphrase: ********
```

`INIT` refuses to run against a repository that's already initialized
(it's a one-time setup step, not idempotent) and needs `PASSPHRASE`
explicitly -- `INIT` without it is a usage error, since there is nothing
else for `INIT` to do.

Behind the prompt, AmiSnap:

1. Generates a random repository key (the key that actually encrypts
   your data) and a random salt.
2. Calibrates PBKDF2's iteration count with a short timing probe against
   the real machine it's running on, targeting roughly 1.5 seconds of
   wall clock -- so the cost of deriving a key from your passphrase
   tracks the CPU actually doing the work, rather than a fixed count
   that's either too fast on slow hardware or needlessly slow on fast
   hardware.
3. Wraps the repository key under a key derived from your passphrase,
   and writes the cipher choice, KDF parameters, and wrapped key into
   `amisnap.repo` at the repository's root.

The repository key itself never needs to change again -- see "Changing
the passphrase" below.

## Using an encrypted repository

Once `amisnap.repo` declares encryption, every command that opens the
repository (`SNAPSHOT`, `RESTORE`, `LIST`, `VERIFY`, `PRUNE`) prompts
for the passphrase automatically -- no extra keyword needed beyond the
usual `REPO=`:

```
1.C:> AmiSnap ACTION=SNAPSHOT SOURCE=Work: REPO=Backup:MyRepo
AmiSnap passphrase: ********
Snapshot 0000000000000605: ...
```

A wrong passphrase fails closed with a clear error (`RETURN_FAIL`) --
never silently produces garbage plaintext. This is checked via a MAC on
the wrapped key itself, before any real object is touched.

## What's encrypted

Every content object and every manifest is encrypted; object *names* on
the destination are always the plaintext content hash regardless of
`CIPHER`, since content-addressing and deduplication depend on it, and a
hash reveals nothing about the file's actual bytes. `PRUNE`'s sweep pass
(matching surviving hashes against what's on disk) never needs the key
for this reason.

## Changing the passphrase

```
1.C:> AmiSnap ACTION=REKEY REPO=Backup:MyRepo
AmiSnap passphrase: ********          (the CURRENT passphrase)
New passphrase: ********
Confirm new passphrase: ********
```

`REKEY` unwraps the repository key under the current passphrase first
(failing closed on a wrong one, same as any other command), then
rewraps it under the new one and recalibrates PBKDF2 for the machine
doing the rekey. The repository key itself is carried over unchanged --
every object and manifest already written stays readable, since what
changed is only how the key is protected, not the key.

## What's not implemented yet

- A key-file option (as opposed to a passphrase) was considered in the
  original design but turned out unnecessary: the wrapped key already
  living inside `amisnap.repo` is functionally the same thing.
- TLS for `s3://` destinations specifically is separate from repository
  encryption and not implemented yet -- see
  [Destinations](Backends.md).
