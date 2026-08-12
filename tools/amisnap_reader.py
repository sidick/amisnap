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
cipher)" as step one. src/core/repo.c does not write amisnap.repo at
all yet (repo.h's own header comment: repository-level state "is
explicitly out of scope here... lands with encryption wiring, phase
4") -- so this reader treats a missing amisnap.repo as CIPHER=0 (the
only value the C side can produce right now) rather than refusing,
and says so. This is a real, current limitation of the repository
this reader is reading, not a bug in the reader.

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
import hashlib
import os
import struct
import sys

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
    known = {TAG_REPO_ID, TAG_CIPHER, TAG_CHUNK_SIZE, TAG_KDF, TAG_WRAPPED_KEY, TAG_FORMAT_APP}
    require_no_unknown_critical(fields, known, "REC_REPO")

    out = {"cipher": 0}
    for tag, value in fields:
        if tag == TAG_REPO_ID:
            out["repo_id"] = value
        elif tag == TAG_CIPHER:
            out["cipher"] = decode_u8(value)
        elif tag == TAG_CHUNK_SIZE:
            out["chunk_size"] = decode_u32(value)
        elif tag == TAG_FORMAT_APP:
            out["format_app"] = decode_string(value).decode("latin-1")
        # KDF/WRAPPED_KEY: only meaningful once CIPHER != 0 (phase 4,
        # unimplemented on the writer side); parsed but unused here.

    if out["cipher"] != 0:
        raise FormatError(
            "amisnap.repo declares CIPHER=%d -- this reader only implements "
            "CIPHER=0 (encryption lands in phase 4)" % out["cipher"])
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
    flags, body_start = parse_header(buf, FTYPE_MANIFEST)
    if flags != 0:
        raise FormatError("manifest: reserved header flags must be 0 (encryption unimplemented)")

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


def load_manifest(repo_dir, snapid):
    path = os.path.join(repo_dir, "snapshots", "%s.mf" % snapid)
    with open(path, "rb") as f:
        return parse_manifest(f.read())


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
        # See this module's own docstring: the current C writer never
        # creates amisnap.repo. Not a corrupt repository -- a real,
        # current gap in what it writes.
        print("note: no amisnap.repo (the C writer doesn't create one yet, "
              "implementation-plan.md phase 4) -- assuming CIPHER=0", file=sys.stderr)
        return {"cipher": 0}
    with open(path, "rb") as f:
        return parse_repo_header(f.read())


def read_object(repo_dir, hash32, expected_size):
    key = object_key(hash32)
    path = os.path.join(repo_dir, key)
    with open(path, "rb") as f:
        data = f.read()
    if len(data) != expected_size:
        raise FormatError("%s: size %d, E_CONTENT declared %d" % (key, len(data), expected_size))
    got_hash = hashlib.blake2s(data, digest_size=32).digest()
    if got_hash != hash32:
        raise FormatError("%s: content does not hash to its own name (got %s)"
                           % (key, got_hash.hex()))
    return data


# --------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------

def cmd_list(args):
    read_repo_header(args.repo)
    ids = list_snapshot_ids(args.repo)
    if not ids:
        print("No snapshots in %r" % args.repo)
        return 0
    for snapid in ids:
        mf = load_manifest(args.repo, snapid)
        n = sum(1 for _ in mf.all_entries())
        print("%s  %d entries" % (snapid, n))
    return 0


def cmd_verify(args):
    read_repo_header(args.repo)
    snapid = resolve_snapid(args.repo, args.snapid)
    mf = load_manifest(args.repo, snapid)

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
                    read_object(args.repo, ref["hash"], ref["size"])
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


def cmd_restore(args):
    read_repo_header(args.repo)
    snapid = resolve_snapid(args.repo, args.snapid)
    mf = load_manifest(args.repo, snapid)

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

        dest_path = os.path.join(args.dest, path.decode("latin-1")) if path else args.dest

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
                    out.write(read_object(args.repo, ref["hash"], ref["size"]))
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
