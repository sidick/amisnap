#!/usr/bin/env python3
"""amisnap_reader.py -- host-side reference reader for the AmiSnap
repository format.

This is the reader docs/format.md's own opening line describes: "the C
implementation (src/core/) and the host-side reference reader (this
file) both cite it, and CI asserts they agree." Every tag value, field
layout, and encoding rule below is transcribed from that document (and
cross-checked against src/core/tlv.c, meta.c, manifest.c, repo.c's own
encode/decode implementations -- not guessed or assumed) -- if the two
ever disagree, format.md wins and this file is wrong.

Deliberately stdlib-only: format.md's own promise is "no index, no
AmiSnap binaries, no Amiga required" for disaster recovery -- a Python
3 interpreter and this one file is meant to be enough on a bare PC.
BLAKE2s-256 is in hashlib since Python 3.6 (PEP 552), so even the
integrity-critical hash needs no third-party dependency.

Known, honest gap versus the spec's own reader guidance: format.md
says a reader should "parse amisnap.repo (refuse unknown version/
cipher)" as step one. A CIPHER=0 repository still has no amisnap.repo
at all in some cases (any repository never INIT'd -- repo.c's writer
creates snapshots/objects on first use with no header required; only
INIT PASSPHRASE writes one, per implementation-plan.md Phase 4 item
3), so this reader treats a missing amisnap.repo as CIPHER=0 rather
than refusing, and says so. CIPHER=1 (encrypted) repositories are
supported: this reader prompts for the passphrase (getpass, no echo)
and derives the repository key the same way src/core/repo_crypto.c
does -- see the "Encryption" section below, a stdlib-only pure-Python
reimplementation of ChaCha20/PBKDF2-HMAC-SHA256/keyed-BLAKE2s-256 kept
deliberately independent of src/core/'s own C (this is the whole point
of a *reference* reader: it must not just call back into the
implementation it's meant to be checking).

Subcommands:
  list <repo>                       list snapshot ids, oldest first
  verify <repo> [--snapid ID] [--full]
                                     structural (default) or full
                                     (re-hash every object) verify
  restore <repo> <dest> [--snapid ID] [--subtree PATH] [--uaem]
                                     reconstruct file content under
                                     dest; reports what metadata exists
                                     per entry (this host can apply
                                     essentially none of it faithfully
                                     -- AmigaDOS protection bits/
                                     comments have no POSIX equivalent
                                     -- so it is reported, not silently
                                     dropped, matching format.md's own
                                     "apply metadata as far as the
                                     target system allows, reporting
                                     what it couldn't apply"). --uaem
                                     additionally writes a <name>.uaem
                                     sidecar next to each restored
                                     entry (protection/datestamp/
                                     comment, the FS-UAE/Amiberry/
                                     Copperline host-directory-metadata
                                     convention implementation-plan.md
                                     already documents) -- not a
                                     substitute for applying metadata,
                                     but real Amiga metadata that
                                     survives the round trip either
                                     for a later emulator mount or for
                                     `AmiSnap ACTION=APPLYUAEM` to
                                     apply for real on a real Amiga
                                     (src/cli/main.c)
"""
import argparse
import datetime
import getpass
import hashlib
import hmac
import os
import struct
import sys
import zlib

MAGIC = b"ASNP"
FORMAT_VERSION = 1

FTYPE_REPO = 1
FTYPE_MANIFEST = 2

TAG_CRITICAL = 0x8000

REC_REPO = 0x8001
REC_SNAP = 0x8002
REC_VOLUME = 0x8003
REC_ENTRY = 0x8004
REC_END = 0x8005

# REC_REPO fields
TAG_REPO_ID = 0x8010
TAG_CIPHER = 0x8011
TAG_CHUNK_SIZE = 0x0012
TAG_KDF = 0x8013
TAG_WRAPPED_KEY = 0x8014
TAG_FORMAT_APP = 0x0015
TAG_OBJCOMP = 0x8016

# REC_SNAP fields
TAG_CREATED = 0x8020
TAG_HOSTNAME = 0x0021
TAG_TOOLVER = 0x0022
TAG_SNAP_COMMENT = 0x0023

# REC_VOLUME fields
TAG_VOL_ROOT = 0x8030
TAG_VOL_NAME = 0x0031
TAG_VOL_DOSTYPE = 0x0032
TAG_VOL_CREATED = 0x0033
TAG_VOL_CAPS = 0x0034

# REC_ENTRY fields
TAG_E_PATH = 0x8040
TAG_E_TYPE = 0x8041
TAG_E_PROT = 0x8042
TAG_E_DATE = 0x8043
TAG_E_COMMENT = 0x0044
TAG_E_OWNER = 0x0045
TAG_E_SIZE = 0x8046
TAG_E_CONTENT = 0x8047
TAG_E_LINK = 0x8048
TAG_E_XHASH = 0x0049

# REC_END fields
TAG_END_COUNT = 0x8050
TAG_END_HASH = 0x8051

ETYPE_FILE = 1
ETYPE_DIR = 2
ETYPE_SOFTLINK = 3
ETYPE_HARDLINK = 4

# Encryption (docs/format.md "Encryption (CIPHER 1)")
CIPHER_NONE = 0
CIPHER_CHACHA20_BLAKE2S = 1

# Object compression (docs/format.md "Content objects")
OBJCOMP_RAW = 0
OBJCOMP_FRAMED = 1
COMP_STORED = 0
COMP_LZ4 = 1
COMP_ZLIB = 2
FRAME_HDR_SIZE = 9  # alg:u8 + usize:u64 BE
KDF_PBKDF2_HMAC_SHA256 = 1
REPO_KEY_SIZE = 32
NONCE_SIZE = 12
MAC_SIZE = 16
WRAPPED_KEY_SIZE = NONCE_SIZE + REPO_KEY_SIZE + MAC_SIZE


class FormatError(Exception):
    """A repository/manifest byte sequence that doesn't match format.md."""


# --------------------------------------------------------------------------
# TLV primitives (format.md "TLV encoding"): every structured file is a
# sequence of records; every record is a sequence of fields. Both levels
# use the same primitive (tag:u16, length:u32, value:length bytes) --
# confirmed against tlv.c's amisnap_buf_field()/amisnap_cursor_field(),
# not just the prose description.
# --------------------------------------------------------------------------

def iter_tlv(buf, start=0):
    """Yield (tag, value, tlv_start_offset) for each tag/length/value
    entry in buf[start:], at whichever level (record or field) the
    caller is parsing. tlv_start_offset is the absolute offset of this
    entry's own tag byte, needed by REC_END's END_HASH check (BLAKE2s-
    256 "over every manifest byte from magic up to (not including)
    this REC_END record")."""
    off = start
    n = len(buf)
    while off < n:
        if off + 6 > n:
            raise FormatError("truncated tag/length header at offset %d" % off)
        tlv_start = off
        tag = struct.unpack_from(">H", buf, off)[0]
        length = struct.unpack_from(">I", buf, off + 2)[0]
        off += 6
        if off + length > n:
            raise FormatError("truncated value (tag 0x%04x, offset %d)" % (tag, off))
        value = buf[off:off + length]
        off += length
        yield tag, value, tlv_start


def parse_fields(buf):
    """A record's own value, parsed one level down into its fields.
    Returns an ordered list of (tag, value) -- callers needing E_CONTENT
    (repeatable) must not collapse this into a dict."""
    return [(tag, value) for tag, value, _ in iter_tlv(buf)]


def require_no_unknown_critical(fields, known_tags, context):
    """format.md: "a reader encountering an unknown critical tag MUST
    NOT claim a complete read of that record." known_tags is the set
    this specific record type understands; a critical (0x8000 bit set)
    tag outside that set means this record has a field we don't
    understand well enough to trust the record as fully read."""
    for tag, _ in fields:
        if tag not in known_tags and (tag & TAG_CRITICAL):
            raise FormatError(
                "unknown critical tag 0x%04x in %s -- refusing to claim a complete read"
                % (tag, context))


def decode_string(value):
    """format.md "Conventions": a string field's own value is itself a
    u16 byte count followed by that many bytes -- distinct from, and
    nested inside, the outer tag/length/value framing every field
    already has (confirmed against tlv.c's amisnap_buf_field_string(),
    which really does double-encode the length: the outer TLV length
    covers 2 + strlen, and the first 2 bytes of the value are a second,
    inner u16 length)."""
    if len(value) < 2:
        raise FormatError("truncated string field")
    strlen = struct.unpack_from(">H", value, 0)[0]
    if 2 + strlen != len(value):
        raise FormatError("string field length mismatch (declared %d, field holds %d)"
                           % (strlen, len(value) - 2))
    return value[2:2 + strlen]


def decode_u8(value):
    if len(value) != 1:
        raise FormatError("bad u8 field length %d" % len(value))
    return value[0]


def decode_u16(value):
    if len(value) != 2:
        raise FormatError("bad u16 field length %d" % len(value))
    return struct.unpack_from(">H", value, 0)[0]


def decode_u32(value):
    if len(value) != 4:
        raise FormatError("bad u32 field length %d" % len(value))
    return struct.unpack_from(">I", value, 0)[0]


def decode_datestamp(value):
    if len(value) != 12:
        raise FormatError("bad DateStamp field length %d" % len(value))
    days, mins, ticks = struct.unpack_from(">III", value, 0)
    return {"days": days, "mins": mins, "ticks": ticks}


# --------------------------------------------------------------------------
# Common file header (format.md "Common file header")
# --------------------------------------------------------------------------

def parse_header(buf, expect_ftype):
    if len(buf) < 8:
        raise FormatError("file shorter than the common header (8 bytes)")
    if buf[0:4] != MAGIC:
        raise FormatError("bad magic %r, expected %r" % (buf[0:4], MAGIC))
    ftype = buf[4]
    version = buf[5]
    flags = struct.unpack_from(">H", buf, 6)[0]
    if ftype != expect_ftype:
        raise FormatError("ftype %d, expected %d" % (ftype, expect_ftype))
    if version != FORMAT_VERSION:
        raise FormatError("unsupported format version %d (this reader implements %d)"
                           % (version, FORMAT_VERSION))
    return flags, 8


# --------------------------------------------------------------------------
# Encryption (docs/format.md "Encryption (CIPHER 1)") -- a stdlib-only
# pure-Python reimplementation of ChaCha20 (RFC 8439), independent of
# src/core/chacha20.c (PBKDF2 and keyed BLAKE2s are already in
# hashlib, no reimplementation needed for those). Deliberately NOT
# calling into the C implementation or a third-party crypto package --
# see this file's own module docstring on why a *reference* reader
# staying independent is the entire point.
# --------------------------------------------------------------------------

def _chacha20_block(key, counter, nonce):
    """One 64-byte keystream block (RFC 8439 Sec 2.3), 32-bit-wrapping
    arithmetic throughout via `& 0xffffffff` (Python ints don't wrap on
    their own)."""
    def rotl32(x, n):
        x &= 0xffffffff
        return ((x << n) | (x >> (32 - n))) & 0xffffffff

    state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    ] + list(struct.unpack("<8I", key)) + [
        counter,
    ] + list(struct.unpack("<3I", nonce))

    working = list(state)

    def quarter_round(a, b, c, d):
        working[a] = (working[a] + working[b]) & 0xffffffff
        working[d] ^= working[a]
        working[d] = rotl32(working[d], 16)
        working[c] = (working[c] + working[d]) & 0xffffffff
        working[b] ^= working[c]
        working[b] = rotl32(working[b], 12)
        working[a] = (working[a] + working[b]) & 0xffffffff
        working[d] ^= working[a]
        working[d] = rotl32(working[d], 8)
        working[c] = (working[c] + working[d]) & 0xffffffff
        working[b] ^= working[c]
        working[b] = rotl32(working[b], 7)

    for _ in range(10):  # 20 rounds = 10 column+diagonal pairs
        quarter_round(0, 4, 8, 12)
        quarter_round(1, 5, 9, 13)
        quarter_round(2, 6, 10, 14)
        quarter_round(3, 7, 11, 15)
        quarter_round(0, 5, 10, 15)
        quarter_round(1, 6, 11, 12)
        quarter_round(2, 7, 8, 13)
        quarter_round(3, 4, 9, 14)

    out_words = [(working[i] + state[i]) & 0xffffffff for i in range(16)]
    return struct.pack("<16I", *out_words)


def chacha20_xor(key, nonce, counter, data):
    """XORs `data` with the ChaCha20 keystream (key/nonce/initial
    counter -- see chacha20.h's own C signature, which this mirrors
    exactly). Symmetric: the same call encrypts and decrypts."""
    out = bytearray(len(data))
    off = 0
    blk_counter = counter
    while off < len(data):
        block = _chacha20_block(key, blk_counter, nonce)
        n = min(64, len(data) - off)
        for i in range(n):
            out[off + i] = data[off + i] ^ block[i]
        blk_counter = (blk_counter + 1) & 0xffffffff
        off += n
    return bytes(out)


def _subkey(parent, label):
    """docs/format.md "Subkey derivation": domain-separated keyed
    BLAKE2s-256, subkey(parent, label) = keyed-BLAKE2s-256(key=parent,
    message=label)."""
    return hashlib.blake2s(label.encode("ascii"), key=parent, digest_size=32).digest()


def derive_subkeys(repo_key):
    return {
        "enc": _subkey(repo_key, "AmiSnap-object-enc-v1"),
        "mac": _subkey(repo_key, "AmiSnap-object-mac-v1"),
        "nonce": _subkey(repo_key, "AmiSnap-object-nonce-v1"),
    }


def object_nonce(subkey_nonce, content_hash):
    return hashlib.blake2s(content_hash, key=subkey_nonce, digest_size=32).digest()[:NONCE_SIZE]


def manifest_nonce(subkey_nonce, snapid_bytes):
    return hashlib.blake2s(snapid_bytes, key=subkey_nonce, digest_size=32).digest()[:NONCE_SIZE]


def _mac16(key, nonce, ciphertext):
    return hashlib.blake2s(nonce + ciphertext, key=key, digest_size=32).digest()[:MAC_SIZE]


def encrypt_frame(sk, nonce, plaintext):
    """docs/format.md's object/manifest frame: nonce || ChaCha20(K_enc,
    nonce, plaintext) || first-16-bytes-of-keyed-BLAKE2s-256(K_mac,
    nonce||ciphertext)."""
    ciphertext = chacha20_xor(sk["enc"], nonce, 0, plaintext)
    return nonce + ciphertext + _mac16(sk["mac"], nonce, ciphertext)


def decrypt_frame(sk, frame):
    if len(frame) < NONCE_SIZE + MAC_SIZE:
        raise FormatError("encrypted frame shorter than nonce+mac (%d bytes)" % len(frame))
    nonce = frame[:NONCE_SIZE]
    ciphertext = frame[NONCE_SIZE:-MAC_SIZE]
    mac = frame[-MAC_SIZE:]
    want_mac = _mac16(sk["mac"], nonce, ciphertext)
    if not hmac.compare_digest(want_mac, mac):
        raise FormatError("MAC mismatch decrypting frame -- wrong passphrase, wrong "
                           "repository key, or corrupt/tampered data")
    return chacha20_xor(sk["enc"], nonce, 0, ciphertext)


def wrap_key(k_wrap, wrap_nonce, repo_key):
    sk = {"enc": _subkey(k_wrap, "AmiSnap-wrap-enc-v1"), "mac": _subkey(k_wrap, "AmiSnap-wrap-mac-v1")}
    return encrypt_frame(sk, wrap_nonce, repo_key)


def unwrap_key(k_wrap, wrapped):
    sk = {"enc": _subkey(k_wrap, "AmiSnap-wrap-enc-v1"), "mac": _subkey(k_wrap, "AmiSnap-wrap-mac-v1")}
    return decrypt_frame(sk, wrapped)


# --------------------------------------------------------------------------
# Repository header (amisnap.repo) -- see this file's own module
# docstring for why a missing amisnap.repo is tolerated, not refused.
# --------------------------------------------------------------------------

def parse_repo_header(buf):
    flags, body_start = parse_header(buf, FTYPE_REPO)
    if flags != 0:
        raise FormatError("amisnap.repo: reserved header flags must be 0")

    records = list(iter_tlv(buf, body_start))
    if len(records) != 1 or records[0][0] != REC_REPO:
        raise FormatError("amisnap.repo: expected exactly one REC_REPO record")

    fields = parse_fields(records[0][1])
    known = {TAG_REPO_ID, TAG_CIPHER, TAG_CHUNK_SIZE, TAG_KDF, TAG_WRAPPED_KEY,
             TAG_FORMAT_APP, TAG_OBJCOMP}
    require_no_unknown_critical(fields, known, "REC_REPO")

    # objcomp defaults to 0: headers written before OBJCOMP existed are
    # raw by construction (format.md "Repository header").
    out = {"cipher": 0, "objcomp": 0}
    for tag, value in fields:
        if tag == TAG_REPO_ID:
            out["repo_id"] = value
        elif tag == TAG_CIPHER:
            out["cipher"] = decode_u8(value)
        elif tag == TAG_OBJCOMP:
            out["objcomp"] = decode_u8(value)
        elif tag == TAG_CHUNK_SIZE:
            out["chunk_size"] = decode_u32(value)
        elif tag == TAG_FORMAT_APP:
            out["format_app"] = decode_string(value).decode("latin-1")
        elif tag == TAG_KDF:
            # docs/format.md: kdfid:u8, iters:u32, salt:string -- packed
            # scalars followed by the string primitive, not itself a
            # nested TLV record (same convention E_DATE/E_OWNER use).
            if len(value) < 1 + 4 + 2:
                raise FormatError("KDF field too short")
            out["kdf_id"] = value[0]
            out["kdf_iters"] = struct.unpack_from(">I", value, 1)[0]
            salt_len = struct.unpack_from(">H", value, 5)[0]
            if 7 + salt_len != len(value):
                raise FormatError("KDF salt length mismatch (declared %d, field holds %d)"
                                   % (salt_len, len(value) - 7))
            out["salt"] = value[7:7 + salt_len]
        elif tag == TAG_WRAPPED_KEY:
            if len(value) != WRAPPED_KEY_SIZE:
                raise FormatError("WRAPPED_KEY is %d bytes, expected %d"
                                   % (len(value), WRAPPED_KEY_SIZE))
            out["wrapped_key"] = value

    if out["cipher"] not in (CIPHER_NONE, CIPHER_CHACHA20_BLAKE2S):
        raise FormatError(
            "amisnap.repo declares CIPHER=%d -- this reader only implements "
            "CIPHER=0 (none) and CIPHER=1 (ChaCha20 + keyed-BLAKE2s-256)"
            % out["cipher"])
    if out["cipher"] == CIPHER_CHACHA20_BLAKE2S and ("kdf_iters" not in out or "wrapped_key" not in out):
        raise FormatError("amisnap.repo declares CIPHER=1 but is missing KDF/WRAPPED_KEY")
    if out["objcomp"] not in (OBJCOMP_RAW, OBJCOMP_FRAMED):
        raise FormatError(
            "amisnap.repo declares OBJCOMP=%d -- this reader only implements "
            "OBJCOMP=0 (raw objects) and OBJCOMP=1 (framed objects)"
            % out["objcomp"])
    return out


# --------------------------------------------------------------------------
# Manifest (snapshots/<snapid>.mf)
# --------------------------------------------------------------------------

def decode_snap(value):
    fields = parse_fields(value)
    known = {TAG_CREATED, TAG_HOSTNAME, TAG_TOOLVER, TAG_SNAP_COMMENT}
    require_no_unknown_critical(fields, known, "REC_SNAP")
    out = {}
    for tag, v in fields:
        if tag == TAG_CREATED:
            out["created"] = decode_datestamp(v)
        elif tag == TAG_HOSTNAME:
            out["hostname"] = decode_string(v)
        elif tag == TAG_TOOLVER:
            out["toolver"] = decode_string(v)
        elif tag == TAG_SNAP_COMMENT:
            out["comment"] = decode_string(v)
    if "created" not in out:
        raise FormatError("REC_SNAP missing required CREATED field")
    return out


def decode_volume(value):
    fields = parse_fields(value)
    known = {TAG_VOL_ROOT, TAG_VOL_NAME, TAG_VOL_DOSTYPE, TAG_VOL_CREATED, TAG_VOL_CAPS}
    require_no_unknown_critical(fields, known, "REC_VOLUME")
    out = {}
    for tag, v in fields:
        if tag == TAG_VOL_ROOT:
            out["vol_root"] = decode_string(v)
        elif tag == TAG_VOL_NAME:
            out["name"] = decode_string(v)
        elif tag == TAG_VOL_DOSTYPE:
            out["dostype"] = decode_u32(v)
        elif tag == TAG_VOL_CREATED:
            out["created"] = decode_datestamp(v)
        elif tag == TAG_VOL_CAPS:
            if len(v) != 4:
                raise FormatError("bad VOL_CAPS field length %d" % len(v))
            maxnamelen, capflags = struct.unpack_from(">HH", v, 0)
            out["maxnamelen"] = maxnamelen
            out["owner_supported"] = bool(capflags & 1)
            out["filenote_supported"] = bool(capflags & 2)
    if "vol_root" not in out:
        raise FormatError("REC_VOLUME missing required VOL_ROOT field")
    return out


def decode_entry(value):
    fields = parse_fields(value)
    known = {TAG_E_PATH, TAG_E_TYPE, TAG_E_PROT, TAG_E_DATE, TAG_E_COMMENT, TAG_E_OWNER,
             TAG_E_SIZE, TAG_E_CONTENT, TAG_E_LINK, TAG_E_XHASH}
    require_no_unknown_critical(fields, known, "REC_ENTRY")
    out = {"content": []}
    for tag, v in fields:
        if tag == TAG_E_PATH:
            out["path"] = decode_string(v)
        elif tag == TAG_E_TYPE:
            out["type"] = decode_u8(v)
        elif tag == TAG_E_PROT:
            out["prot"] = decode_u32(v)
        elif tag == TAG_E_DATE:
            out["date"] = decode_datestamp(v)
        elif tag == TAG_E_COMMENT:
            out["comment"] = decode_string(v)
        elif tag == TAG_E_OWNER:
            if len(v) != 4:
                raise FormatError("bad E_OWNER field length %d" % len(v))
            uid, gid = struct.unpack_from(">HH", v, 0)
            out["owner"] = (uid, gid)
        elif tag == TAG_E_SIZE:
            out["size"] = struct.unpack_from(">Q", v, 0)[0] if len(v) == 8 else \
                (_ for _ in ()).throw(FormatError("bad E_SIZE field length %d" % len(v)))
        elif tag == TAG_E_CONTENT:
            if len(v) != 40:
                raise FormatError("bad E_CONTENT field length %d (want 40)" % len(v))
            out["content"].append({"hash": v[0:32], "size": struct.unpack_from(">Q", v, 32)[0]})
        elif tag == TAG_E_LINK:
            out["link"] = decode_string(v)
        elif tag == TAG_E_XHASH:
            out["xhash"] = decode_u32(v)  # advisory only -- never checked for integrity
    for required in ("path", "type", "prot", "date"):
        if required not in out:
            raise FormatError("REC_ENTRY missing required field %r" % required)
    return out


def decode_end(value):
    fields = parse_fields(value)
    out = {}
    for tag, v in fields:
        if tag == TAG_END_COUNT:
            out["count"] = decode_u32(v)
        elif tag == TAG_END_HASH:
            if len(v) != 32:
                raise FormatError("bad END_HASH field length %d" % len(v))
            out["hash"] = v
        elif tag & TAG_CRITICAL:
            raise FormatError("unknown critical tag 0x%04x in REC_END" % tag)
    if "count" not in out or "hash" not in out:
        raise FormatError("REC_END missing required field(s)")
    return out


class Manifest:
    """A fully-parsed, END_HASH-verified manifest: one snap record, an
    ordered list of (volume, [entries under it]) groups matching
    format.md's own required record order (REC_SNAP, then REC_VOLUME
    followed immediately by that volume's REC_ENTRY records, repeated,
    then REC_END last)."""

    def __init__(self, snap, volumes):
        self.snap = snap
        self.volumes = volumes  # list of (volume_dict, [entry_dict, ...])

    def all_entries(self):
        for _vol, entries in self.volumes:
            for e in entries:
                yield e


def parse_manifest(buf):
    """Parses an already-plaintext manifest file. Encrypted manifests
    (flags bit 0 set) go through open_manifest() first, which decrypts
    and hands back an equivalent flags=0 buffer -- this function itself
    never sees CIPHER involved, same split C's manifest.c/repo.c keep."""
    flags, body_start = parse_header(buf, FTYPE_MANIFEST)
    if flags != 0:
        raise FormatError("manifest: flags must be 0 here -- callers decrypt via "
                           "open_manifest() before calling parse_manifest()")

    snap = None
    volumes = []  # [(vol_dict, [entries]), ...]
    current_entries = None
    entry_count = 0
    end = None

    for tag, value, tlv_start in iter_tlv(buf, body_start):
        if end is not None:
            raise FormatError("data follows REC_END -- manifest is malformed")

        if tag == REC_SNAP:
            if snap is not None:
                raise FormatError("more than one REC_SNAP")
            snap = decode_snap(value)
        elif tag == REC_VOLUME:
            if snap is None:
                raise FormatError("REC_VOLUME before REC_SNAP")
            vol = decode_volume(value)
            current_entries = []
            volumes.append((vol, current_entries))
        elif tag == REC_ENTRY:
            if snap is None:
                raise FormatError("REC_ENTRY before REC_SNAP")
            if current_entries is None:
                raise FormatError("REC_ENTRY before any REC_VOLUME")
            current_entries.append(decode_entry(value))
            entry_count += 1
        elif tag == REC_END:
            end = decode_end(value)
            if end["count"] != entry_count:
                raise FormatError(
                    "END_COUNT %d does not match %d REC_ENTRY records actually present"
                    % (end["count"], entry_count))
            # format.md REC_END/END_HASH: "BLAKE2s-256 over every
            # manifest byte from magic up to (not including) this
            # REC_END record" -- tlv_start is exactly that boundary.
            computed = hashlib.blake2s(buf[:tlv_start], digest_size=32).digest()
            if computed != end["hash"]:
                raise FormatError(
                    "END_HASH mismatch: manifest bytes don't match their own "
                    "recorded hash (got %s, wanted %s)"
                    % (computed.hex(), end["hash"].hex()))
        elif tag & TAG_CRITICAL:
            raise FormatError("unknown critical top-level tag 0x%04x" % tag)

    if snap is None:
        raise FormatError("manifest has no REC_SNAP")
    if end is None:
        # format.md: "A manifest without a valid REC_END is not a
        # snapshot... readers MUST treat it as absent/corrupt, never as
        # 'best effort'."
        raise FormatError("manifest has no REC_END -- not a valid snapshot")

    return Manifest(snap, volumes)


# --------------------------------------------------------------------------
# Repository-level operations
# --------------------------------------------------------------------------

def object_key(hash32):
    hexhash = hash32.hex()
    return "objects/%s/%s" % (hexhash[0:2], hexhash)


def list_snapshot_ids(repo_dir):
    snaps_dir = os.path.join(repo_dir, "snapshots")
    if not os.path.isdir(snaps_dir):
        return []
    ids = []
    for name in os.listdir(snaps_dir):
        # format.md: "<snapid>" is 16 lower-case hex characters -- a
        # listed name not shaped like that (a stray tmp/ leftover, a
        # foreign file) is silently skipped, same leniency
        # amisnap_repo_list_snapshots() documents on the C side.
        if len(name) == 19 and name.endswith(".mf"):
            stem = name[:-3]
            if len(stem) == 16 and all(c in "0123456789abcdef" for c in stem):
                ids.append(stem)
    ids.sort()  # format.md: lexicographic order is chronological order
    return ids


def open_manifest(repo_dir, snapid, subkeys):
    """Fetches snapshots/<snapid>.mf and decrypts it if its common
    header's flags bit 0 is set (docs/format.md "Encryption ...
    Manifests"), mirroring src/core/repo.c's own
    amisnap_repo_open_manifest() exactly -- including its consistency
    check that the frame's own embedded nonce matches the deterministic
    derivation from `snapid` (a protocol-violation check the MAC alone
    wouldn't catch, since the MAC covers whatever nonce is actually
    present). Returns raw bytes with a plaintext (flags=0) header,
    ready for parse_manifest() -- callers never need to know CIPHER was
    involved."""
    path = os.path.join(repo_dir, "snapshots", "%s.mf" % snapid)
    with open(path, "rb") as f:
        raw = f.read()

    flags, body_start = parse_header(raw, FTYPE_MANIFEST)
    if flags & ~1:
        raise FormatError("manifest: reserved header flags must be 0 (got %d)" % flags)
    if not (flags & 1):
        return raw

    if subkeys is None:
        raise FormatError(
            "%s.mf is encrypted (flags bit 0 set) but no repository key is available "
            "-- this repository needs a passphrase" % snapid)

    frame = raw[body_start:]
    if len(frame) < NONCE_SIZE + MAC_SIZE:
        raise FormatError("encrypted manifest frame too short")

    expect_nonce = manifest_nonce(subkeys["nonce"], snapid.encode("ascii"))
    if frame[:NONCE_SIZE] != expect_nonce:
        raise FormatError(
            "%s.mf's nonce doesn't match the deterministic derivation from its own "
            "snapid -- this manifest wasn't produced the way this repository's own "
            "writer produces them" % snapid)

    plaintext_body = decrypt_frame(subkeys, frame)
    header = MAGIC + bytes([FTYPE_MANIFEST, FORMAT_VERSION]) + struct.pack(">H", 0)
    return header + plaintext_body


def load_manifest(repo_dir, snapid, subkeys=None):
    return parse_manifest(open_manifest(repo_dir, snapid, subkeys))


def resolve_snapid(repo_dir, snapid):
    if snapid:
        return snapid
    ids = list_snapshot_ids(repo_dir)
    if not ids:
        raise FormatError("no snapshots in %r" % repo_dir)
    return ids[-1]


def read_repo_header(repo_dir):
    path = os.path.join(repo_dir, "amisnap.repo")
    if not os.path.exists(path):
        # See this module's own docstring: a repository that was never
        # INIT'd (only ever needed for CIPHER 1) has no amisnap.repo at
        # all. Not a corrupt repository -- a real, normal state for a
        # plain one.
        print("note: no amisnap.repo (never INIT'd -- a plain repository doesn't need "
              "one) -- assuming CIPHER=0", file=sys.stderr)
        return {"cipher": 0, "objcomp": 0}
    with open(path, "rb") as f:
        return parse_repo_header(f.read())


def open_repo_key(header):
    """Given a parsed amisnap.repo header (read_repo_header()), returns
    the derived object/manifest subkeys (derive_subkeys()) for a
    CIPHER=1 repository, or None for CIPHER=0. Prompts interactively
    for the passphrase (getpass, no echo) and fails closed --
    FormatError, never a silent fallback to unencrypted access -- on a
    wrong passphrase (MAC mismatch unwrapping WRAPPED_KEY) exactly like
    src/core/repo_crypto.c's amisnap_repo_unwrap_key()."""
    if header["cipher"] == CIPHER_NONE:
        return None

    passphrase = getpass.getpass("AmiSnap passphrase: ")
    k_wrap = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), header["salt"],
                                  header["kdf_iters"], REPO_KEY_SIZE)
    try:
        repo_key = unwrap_key(k_wrap, header["wrapped_key"])
    except FormatError:
        raise FormatError("wrong passphrase (or a corrupt amisnap.repo)")
    return derive_subkeys(repo_key)



# --------------------------------------------------------------------------
# OBJCOMP=1 object frames (docs/format.md "Content objects") -- kept
# stdlib-only like everything else here: zlib is in the standard
# library, and the LZ4 *block* format is simple enough to decode in a
# few dozen lines of Python, implemented below from the documented
# format (https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md)
# and cross-checked in CI against objects the vendored upstream LZ4
# writes. Decode-only on purpose: a disaster-recovery reader never
# needs to compress.
# --------------------------------------------------------------------------

def lz4_block_decompress(src, usize):
    dst = bytearray()
    i, n = 0, len(src)
    while i < n:
        token = src[i]
        i += 1
        lit = token >> 4
        if lit == 15:
            while True:
                if i >= n:
                    raise FormatError("LZ4 block: truncated literal length")
                b = src[i]
                i += 1
                lit += b
                if b != 255:
                    break
        if i + lit > n:
            raise FormatError("LZ4 block: literals overrun the input")
        dst += src[i:i + lit]
        i += lit
        if i == n:
            break  # last sequence is literals-only
        if i + 2 > n:
            raise FormatError("LZ4 block: truncated match offset")
        offset = src[i] | (src[i + 1] << 8)
        i += 2
        if offset == 0 or offset > len(dst):
            raise FormatError("LZ4 block: match offset %d out of range" % offset)
        mlen = (token & 0xF) + 4
        if (token & 0xF) == 15:
            while True:
                if i >= n:
                    raise FormatError("LZ4 block: truncated match length")
                b = src[i]
                i += 1
                mlen += b
                if b != 255:
                    break
        # Matches may overlap their own output; copy byte-by-byte.
        pos = len(dst) - offset
        for _ in range(mlen):
            dst.append(dst[pos])
            pos += 1
        if len(dst) > usize:
            raise FormatError("LZ4 block: output exceeds declared usize")
    if len(dst) != usize:
        raise FormatError("LZ4 block: decoded %d bytes, frame declared %d"
                          % (len(dst), usize))
    return bytes(dst)


def decode_object_frame(data, expected_usize, key):
    """Decodes an OBJCOMP=1 frame (alg:u8 + usize:u64 BE + payload) to
    the uncompressed content bytes. expected_usize comes from the
    manifest's E_CONTENT ref -- format.md requires the frame to agree,
    and checking first also stops a corrupt frame from demanding an
    arbitrary allocation."""
    if len(data) < FRAME_HDR_SIZE:
        raise FormatError("%s: framed object shorter than the frame header" % key)
    alg = data[0]
    usize = struct.unpack_from(">Q", data, 1)[0]
    if usize != expected_usize:
        raise FormatError("%s: frame usize %d, E_CONTENT declared %d"
                          % (key, usize, expected_usize))
    payload = data[FRAME_HDR_SIZE:]
    if alg == COMP_STORED:
        if len(payload) != usize:
            raise FormatError("%s: stored payload is %d bytes, frame declared %d"
                              % (key, len(payload), usize))
        return payload
    if alg == COMP_LZ4:
        return lz4_block_decompress(payload, usize)
    if alg == COMP_ZLIB:
        try:
            out = zlib.decompress(payload)
        except zlib.error as e:
            raise FormatError("%s: zlib payload does not decompress (%s)" % (key, e))
        if len(out) != usize:
            raise FormatError("%s: zlib payload decoded to %d bytes, frame declared %d"
                              % (key, len(out), usize))
        return out
    raise FormatError("%s: frame names compression alg %d -- this reader only "
                      "implements 0 (stored), 1 (LZ4 block), 2 (zlib)" % (key, alg))


def read_object(repo_dir, hash32, expected_size, subkeys=None, objcomp=OBJCOMP_RAW):
    key = object_key(hash32)
    path = os.path.join(repo_dir, key)
    with open(path, "rb") as f:
        data = f.read()

    if subkeys is None:
        if objcomp == OBJCOMP_FRAMED:
            data = decode_object_frame(data, expected_size, key)
        elif len(data) != expected_size:
            raise FormatError("%s: size %d, E_CONTENT declared %d" % (key, len(data), expected_size))
        got_hash = hashlib.blake2s(data, digest_size=32).digest()
        if got_hash != hash32:
            raise FormatError("%s: content does not hash to its own name (got %s)"
                               % (key, got_hash.hex()))
        return data

    if objcomp == OBJCOMP_FRAMED:
        # A compressed payload's stored size isn't predictable, only
        # bounded: at least the frame header, at most stored-plus-header
        # (the writer's store-raw fallback guarantees the ceiling), plus
        # the encryption envelope either way (compress-then-encrypt).
        lo = NONCE_SIZE + FRAME_HDR_SIZE + MAC_SIZE
        hi = NONCE_SIZE + FRAME_HDR_SIZE + expected_size + MAC_SIZE
        if not lo <= len(data) <= hi:
            raise FormatError("%s: stored size %d outside the possible framed range %d-%d"
                               % (key, len(data), lo, hi))
    else:
        expect_len = NONCE_SIZE + expected_size + MAC_SIZE
        if len(data) != expect_len:
            raise FormatError("%s: stored size %d, expected %d (E_CONTENT declared %d plaintext "
                               "bytes + the encryption frame overhead)"
                               % (key, len(data), expect_len, expected_size))
    expect_nonce = object_nonce(subkeys["nonce"], hash32)
    if data[:NONCE_SIZE] != expect_nonce:
        raise FormatError("%s: nonce doesn't match the deterministic derivation from its "
                           "own content hash -- this object wasn't produced the way this "
                           "repository's own writer produces them" % key)
    plaintext = decrypt_frame(subkeys, data)
    if objcomp == OBJCOMP_FRAMED:
        plaintext = decode_object_frame(plaintext, expected_size, key)
    got_hash = hashlib.blake2s(plaintext, digest_size=32).digest()
    if got_hash != hash32:
        raise FormatError("%s: decrypted content does not hash to its own name (got %s)"
                           % (key, got_hash.hex()))
    return plaintext


# --------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------

def cmd_list(args):
    header = read_repo_header(args.repo)
    subkeys = open_repo_key(header)
    ids = list_snapshot_ids(args.repo)
    if not ids:
        print("No snapshots in %r" % args.repo)
        return 0
    for snapid in ids:
        mf = load_manifest(args.repo, snapid, subkeys)
        n = sum(1 for _ in mf.all_entries())
        print("%s  %d entries" % (snapid, n))
    return 0


def cmd_verify(args):
    header = read_repo_header(args.repo)
    subkeys = open_repo_key(header)
    snapid = resolve_snapid(args.repo, args.snapid)
    mf = load_manifest(args.repo, snapid, subkeys)

    checked = missing = corrupt = 0
    for entry in mf.all_entries():
        for ref in entry["content"]:
            checked += 1
            key = object_key(ref["hash"])
            path = os.path.join(args.repo, key)
            if not os.path.exists(path):
                missing += 1
                print("MISSING: %s (referenced by %r)" % (key, entry["path"]))
                continue
            if args.full:
                try:
                    read_object(args.repo, ref["hash"], ref["size"], subkeys,
                                header["objcomp"])
                except FormatError as e:
                    corrupt += 1
                    print("CORRUPT: %s: %s" % (key, e))

    mode = "FULL" if args.full else "structural"
    print("Verify %s (%s): %d objects checked, %d missing, %d corrupt"
          % (snapid, mode, checked, missing, corrupt))
    return 1 if (missing or corrupt) else 0


def describe_metadata(entry):
    """format.md's own reader guidance: "apply metadata as far as the
    target system allows, reporting what it couldn't apply." A plain
    POSIX host can apply essentially none of AmigaDOS's protection
    mask, FileNote, or numeric owner IDs faithfully (no fib_Protection
    concept, no comment-per-file, no shared uid/gid namespace with the
    source Amiga) -- so every field is reported, honestly, as present-
    but-not-applied rather than silently dropped or guessed at."""
    bits = []
    bits.append("prot=0x%08x (not applied -- no POSIX equivalent)" % entry["prot"])
    d = entry["date"]
    bits.append("date=%d.%d.%d (not applied)" % (d["days"], d["mins"], d["ticks"]))
    if "comment" in entry:
        bits.append("comment=%r (not applied -- no POSIX FileNote)"
                     % entry["comment"].decode("latin-1"))
    if "owner" in entry:
        bits.append("owner=%d.%d (not applied -- Amiga uid/gid, no relation to this host's)"
                     % entry["owner"])
    return "; ".join(bits)


# --------------------------------------------------------------------------
# .uaem sidecars (implementation-plan.md's item 8: the FS-UAE-
# originated, Amiberry/Copperline-shared host-directory-metadata
# convention -- documented there from Amiberry's own wiki and confirmed
# against real Copperline output during that work, not re-derived from
# scratch here). One line: an 8-character HSPARWED-style protection
# flag string ('-' for unset), a space, "YYYY-MM-DD HH:MM:SS.CC", then
# an optional free-form comment to end of line.
# --------------------------------------------------------------------------

# (bitmask, display char, active_high) in left-to-right display order.
# HSPA (dos/dos.h FIBB_HOLD.. FIBB_ARCHIVE, bits 7-4) show their letter
# when SET; rwed (FIBB_READ..FIBB_DELETE, bits 3-0) are the classic
# active-low permission bits and show their letter when CLEAR (i.e.
# "allowed") -- confirmed against three real captured Copperline .uaem
# lines during item 8's own work (e.g. prot=0x11 -- ARCHIVE|DELETE --
# produced "---arwe-", the trailing dash being the SET delete bit), not
# assumed from the bit names alone.
_UAEM_PROT_ORDER = [
    (0x80, "h", True),
    (0x40, "s", True),
    (0x20, "p", True),
    (0x10, "a", True),
    (0x08, "r", False),
    (0x04, "w", False),
    (0x02, "e", False),
    (0x01, "d", False),
]


def prot_to_uaem_flags(prot):
    out = []
    for mask, letter, active_high in _UAEM_PROT_ORDER:
        bit_set = bool(prot & mask)
        show = bit_set if active_high else not bit_set
        out.append(letter if show else "-")
    return "".join(out)


def datestamp_to_uaem_timestamp(date):
    """AmigaOS DateStamp -> "YYYY-MM-DD HH:MM:SS.CC". `days` is days
    since 1978-01-01 (Python's datetime handles the proleptic Gregorian
    arithmetic correctly for any offset this format can produce, no
    hand-rolled calendar math needed on the Python side -- unlike the
    C/Amiga side, which has no datetime library at all).`mins` is
    minutes past midnight; `ticks` is ticks (1/50s) past the CURRENT
    MINUTE (confirmed the hard way earlier this project, not assumed:
    ticks is 0-2999, not 0-49 -- see implementation-plan.md's Phase 2
    performance-gate item). SS comes from ticks // 50, CC (centiseconds)
    from (ticks % 50) * 2 -- verified against a real captured sample
    (mins=123, ticks=7 -> "02:03:00.14": 123 = 2*60+3, 7*2=14)."""
    d = datetime.date(1978, 1, 1) + datetime.timedelta(days=date["days"])
    hh, mm = divmod(date["mins"], 60)
    ss, rem_ticks = divmod(date["ticks"], 50)
    cc = rem_ticks * 2
    return "%04d-%02d-%02d %02d:%02d:%02d.%02d" % (d.year, d.month, d.day, hh, mm, ss, cc)


def write_uaem_sidecar(dest_path, entry):
    """Writes <dest_path>.uaem as a sibling of dest_path -- matching
    real Copperline output exactly (e.g. a restored "Sub" directory's
    metadata lives in "Sub.uaem" next to it, not inside it). Skipped
    for the volume root entry by the caller (E_PATH ""): there is no
    sibling location for the destination root's own sidecar, and real
    Copperline never wrote one for a mount root either."""
    flags = prot_to_uaem_flags(entry["prot"])
    timestamp = datestamp_to_uaem_timestamp(entry["date"])
    line = "%s %s" % (flags, timestamp)
    if "comment" in entry:
        line += " " + entry["comment"].decode("latin-1")
    with open(dest_path + ".uaem", "w", encoding="latin-1", newline="\n") as f:
        f.write(line + "\n")


def safe_dest_path(dest, rel):
    """Joins a manifest entry's relative path onto the restore
    destination, refusing any path that would escape it. A manifest can
    come from an untrusted source (a compromised NAS/WebDAV/S3 server;
    note a plaintext manifest's END_HASH is self-recomputable, so a
    forged one can look valid), so a hostile entry path like
    "../../home/user/.profile" or an absolute "/etc/passwd" must not
    let the reader overwrite files outside `dest`. Rejects absolute
    paths and any ".." component up front, then verifies via realpath
    that the result really stays under `dest` (defence in depth against
    symlinks in `dest` itself and platform path quirks). Returns the
    validated absolute path, or raises ValueError."""
    text = rel.decode("latin-1")
    # Amiga manifests use '/' as the separator; also treat the host
    # separator so this is correct whichever platform runs the reader.
    parts = text.replace("\\", "/").split("/")
    for comp in parts:
        if comp in ("", ".", ".."):
            if comp == "..":
                raise ValueError("manifest path escapes destination: %r" % text)
            # empty/'.' components are harmless -- skip them
            continue
    if text.startswith("/") or os.path.isabs(text):
        raise ValueError("manifest path is absolute: %r" % text)
    dest_root = os.path.realpath(dest)
    joined = os.path.realpath(os.path.join(dest_root, text))
    if joined != dest_root and not joined.startswith(dest_root + os.sep):
        raise ValueError("manifest path escapes destination: %r" % text)
    return joined


def cmd_restore(args):
    header = read_repo_header(args.repo)
    subkeys = open_repo_key(header)
    snapid = resolve_snapid(args.repo, args.snapid)
    mf = load_manifest(args.repo, snapid, subkeys)

    subtree = args.subtree.encode("latin-1") if args.subtree else None

    def in_subtree(path):
        if subtree is None:
            return True
        if path == subtree:
            return True
        return path.startswith(subtree + b"/")

    dirs = files = skipped = 0
    for entry in mf.all_entries():
        path = entry["path"]
        if not in_subtree(path):
            skipped += 1
            continue

        dest_path = safe_dest_path(args.dest, path) if path else os.path.realpath(args.dest)

        if entry["type"] == ETYPE_DIR:
            os.makedirs(dest_path, exist_ok=True)
            dirs += 1
        elif entry["type"] in (ETYPE_SOFTLINK, ETYPE_HARDLINK):
            # Matches src/core/restore.c's own honest gap (restore.h:
            # "no backend.h link concept yet") -- counted, not silently
            # dropped, not attempted as a plain file either.
            print("SKIPPED (link, not yet supported): %r -> %r"
                  % (path.decode("latin-1"), entry.get("link", b"").decode("latin-1")))
            skipped += 1
            continue
        else:
            os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
            with open(dest_path, "wb") as out:
                for ref in entry["content"]:
                    out.write(read_object(args.repo, ref["hash"], ref["size"], subkeys,
                                          header["objcomp"]))
            files += 1

        if args.uaem and path:  # no sidecar for the root entry -- see write_uaem_sidecar
            write_uaem_sidecar(dest_path, entry)

        print("%s: %s" % (path.decode("latin-1") or "(root)", describe_metadata(entry)))

    print("Restored %s: %d dirs, %d files, %d skipped" % (snapid, dirs, files, skipped))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="list snapshot ids")
    p_list.add_argument("repo")
    p_list.set_defaults(func=cmd_list)

    p_verify = sub.add_parser("verify", help="verify a snapshot")
    p_verify.add_argument("repo")
    p_verify.add_argument("--snapid", default=None)
    p_verify.add_argument("--full", action="store_true")
    p_verify.set_defaults(func=cmd_verify)

    p_restore = sub.add_parser("restore", help="restore a snapshot's content")
    p_restore.add_argument("repo")
    p_restore.add_argument("dest")
    p_restore.add_argument("--snapid", default=None)
    p_restore.add_argument("--subtree", default=None)
    p_restore.add_argument("--uaem", action="store_true",
                            help="also write a .uaem metadata sidecar next to each restored entry")
    p_restore.set_defaults(func=cmd_restore)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except FormatError as e:
        print("FormatError: %s" % e, file=sys.stderr)
        return 2
    except OSError as e:
        print("I/O error: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
