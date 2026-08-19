# AmiSnap build -- versioned network/cloud backup for classic AmigaOS.
# See docs/proposal.md for the full design and phase sequencing.
#
#   make test        build and run the host-side unit/vector tests (default)
#   make m68k        cross-build the Amiga binary (needs amiga-gcc on PATH)
#   make m68k-docker cross-build inside the CI container (no local toolchain)
#   make dist        package build/dist/AmiSnap.lha for Aminet
#   make clean
#
# Also implements sidick/amiga-workflows' five-verb CI contract (build,
# test-host, test-target, lint, dist) -- see the "Verb contract" section
# below.
#
# The core engine (snapshot model, index, repository format, hashing) is
# portable C, so `test` builds with any host compiler. Amiga-specific code
# (ExAll metadata capture, DOS I/O backend, ReadArgs front-end) lives in
# src/amiga/ and only enters the m68k build.
#
# Target floor: 68020, AmigaOS 2.04 (V37) -- the audience for network
# backup skews accelerated/emulated (docs/proposal.md "Toolchain and
# testing"). Newer APIs (e.g. V39's SetOwner()) are used opportunistically
# and MUST be runtime version-gated, never called bare -- see
# docs/implementation-plan.md "OS floor is V37, not V39".

BUILD := build

include version.mk

# --- Host toolchain (tests) ---
CC      ?= cc
CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -Werror
CORE_INC := -Isrc/core

# Vendored miniz (src/core/miniz.[ch], zlib/deflate for OBJCOMP framed
# objects): strip everything but the compression core -- no zip archive
# APIs, no stdio, no time -- and force byte-by-byte loads: the 68020
# tolerates unaligned access but the flag also covers any stricter
# future target, and miniz's default detection can't know about m68k.
# Must be identical on host and m68k builds (miniz.c and its header
# have to agree).
MINIZ_DEFS := -DMINIZ_NO_ARCHIVE_APIS -DMINIZ_NO_STDIO -DMINIZ_NO_TIME \
              -DMINIZ_USE_UNALIGNED_LOADS_AND_STORES=0
CFLAGS += $(MINIZ_DEFS)

# --- m68k cross toolchain (Amiga build) ---
M68K_CC     ?= m68k-amigaos-gcc
# -m68020/-msoft-float: the target floor above, no FPU assumed. -noixemul
# links against libnix (no ixemul.library runtime dependency) -- see the
# libnix skill for startup/library-open conventions.
M68K_CFLAGS ?= -std=c99 -O2 -Wall -Wextra -Werror -m68020 -msoft-float -noixemul \
               $(CORE_INC) -Isrc/amiga \
               -DVERSION=$(VERSION) -DREVISION=$(REVISION)
M68K_CFLAGS += $(MINIZ_DEFS)

CORE_SRCS  := $(wildcard src/core/*.c)
AMIGA_SRCS := $(wildcard src/amiga/*.c)
CLI_SRCS   := src/cli/main.c
TEST_SRCS  := $(wildcard tests/*.c)

# Whole-program link rules below have no per-object .d files, so headers
# are listed as prerequisites wholesale -- coarse but correct, a header
# touch rebuilds everything in seconds at this size (same reasoning as
# sibling AmiAuth's Makefile).
CORE_HDRS  := $(wildcard src/core/*.h)
AMIGA_HDRS := $(wildcard src/amiga/*.h)
TEST_HDRS  := $(wildcard tests/*.h)
ALL_HDRS   := $(CORE_HDRS) $(AMIGA_HDRS) $(TEST_HDRS)

# --- Containerised cross-build: same image as CI ---
DOCKER          ?= docker
AMIGA_GCC_IMAGE ?= ghcr.io/sidick/amiga-dev:1
# Run as the calling user so bind-mounted build/ output isn't root-owned
# on Linux hosts (breaks later non-Docker steps like `make dist`; found
# for real in sibling AmiAuth's release rehearsal).
DOCKER_USER     := --user "$(shell id -u):$(shell id -g)"

.PHONY: all test m68k m68k-docker clean build test-host stackswap-vamos-test cross-check \
	copperline-fixtures test-target lint dist version guide

all: test

# --- Verb contract (sidick/amiga-workflows' build-test.yml) ---------------
# ci.yml calls these five names; each build-test.yml job is independent
# (no artifact-passing between them), so test-target/dist pull in their
# own build steps rather than assuming a prior job ran.
build: m68k

test-host: test stackswap-vamos-test cross-check webdav-check s3-check

# --- stackswap-vamos-test: Phase 1 item 7's vamos regression test ---------
# Confirms amisnap_stackswap_run() genuinely swaps to a new stack -- see
# tests/vamos/stackswap_test.c's own header for the safe (never
# deliberately-overflow-triggering) test design, and
# docs/implementation-plan.md's "Stack management" section for why.
# Runs directly (no docker wrapping): like sibling AmiAuth's own vamos
# asm-crypto-tests, this assumes it's running inside the amiga-dev image,
# which has m68k-amigaos-gcc and vamos on PATH together -- the CI
# test-host job's actual environment, not a bare host.
STACKSWAP_TEST_SRC := tests/vamos/stackswap_test.c
STACKSWAP_TEST_BIN := $(BUILD)/stackswap-test

$(STACKSWAP_TEST_BIN): $(STACKSWAP_TEST_SRC) src/amiga/stackswap.c src/amiga/stackswap.h | $(BUILD)/.dir
	$(M68K_CC) $(M68K_CFLAGS) $(STACKSWAP_TEST_SRC) src/amiga/stackswap.c -o $@

stackswap-vamos-test: $(STACKSWAP_TEST_BIN)
	vamos -C 020 $(STACKSWAP_TEST_BIN)

# --- cross-check: Phase 2's CI cross-implementation check -----------------
# docs/format.md's own opening line: "the C implementation and the host-
# side reference reader both cite it, and CI asserts they agree." Builds
# a small sample repository with the real portable C write path (host
# compiler, not m68k -- backend_dir.c/repo.c have no Amiga dependency),
# then tests/cross/run.sh drives tools/amisnap_reader.py (stdlib-only
# Python) against it independently and asserts they agree.
CROSS_GEN_SRC := tests/cross/gen_sample_repo.c
CROSS_GEN_BIN := $(BUILD)/gen_sample_repo

$(CROSS_GEN_BIN): $(CROSS_GEN_SRC) src/core/backend_dir.c src/core/repo.c src/core/repo_crypto.c \
	src/core/repo_header.c src/core/pbkdf2.c src/core/hmac_sha256.c src/core/sha256.c \
	src/core/manifest.c src/core/meta.c src/core/tlv.c src/core/blake2s.c src/core/chacha20.c \
	src/core/xxhash32.c $(CORE_HDRS) | $(BUILD)/.dir
	$(CC) $(CFLAGS) $(CORE_INC) $(CROSS_GEN_SRC) src/core/backend_dir.c src/core/repo.c \
		src/core/repo_crypto.c src/core/repo_header.c src/core/pbkdf2.c src/core/hmac_sha256.c \
		src/core/sha256.c src/core/manifest.c src/core/meta.c src/core/tlv.c src/core/blake2s.c \
		src/core/chacha20.c src/core/xxhash32.c -o $@

cross-check: $(CROSS_GEN_BIN)
	sh tests/cross/run.sh

# --- webdav-check: Phase 3 item 5's own host-CI check ----------------------
# "Host CI runs the protocol code against a local WebDAV container"
# (implementation-plan.md Phase 3 blurb) -- tests/webdav/run.sh builds
# the portable webdav.c/http.c against a real POSIX transport
# (tests/webdav/posix_transport.c, host-only -- never part of CORE_SRCS,
# see that file's own header for why) and drives it against
# mini_webdav_server.py, a minimal stdlib-only, INDEPENDENT WebDAV
# server implementation -- deliberately not the in-memory mock
# tests/test_webdav.c already covers, since a self-consistent mock can
# never catch a real interop bug the way a separate implementation can.
webdav-check:
	sh tests/webdav/run.sh

# --- s3-check: Phase 5's own host-CI check ---------------------------------
# "Host CI: a real MinIO instance (container or process...)" (implementation-
# plan.md Phase 5 blurb) -- ended up meaning a from-scratch, independent S3
# server implementation instead, same reasoning webdav-check's own comment
# gives (and stronger here: mini_s3_server.py also independently re-verifies
# every SigV4 signature s3.c produces, not just the wire format). Builds the
# portable s3.c/sigv4.c/http.c against tests/webdav/posix_transport.c
# (reused as-is -- generic POSIX sockets, no WebDAV-specific logic) and
# drives it against mini_s3_server.py.
s3-check:
	sh tests/s3/run.sh

# --- copperline-fixtures: test-only stage/readback helpers (Phase 1 item 8) -
# Never shipped -- same convention as AmiPilot's own fixtures/. Kept out of
# `m68k`/`build` for the same reason: not a real deliverable.
COPPERLINE_FIXTURE_DIR := $(BUILD)/copperline-fixtures

$(COPPERLINE_FIXTURE_DIR)/stage: tests/copperline/fixture/stage.c | $(BUILD)/.dir
	@mkdir -p $(COPPERLINE_FIXTURE_DIR)
	$(M68K_CC) $(M68K_CFLAGS) $< -o $@

$(COPPERLINE_FIXTURE_DIR)/readback: tests/copperline/fixture/readback.c | $(BUILD)/.dir
	@mkdir -p $(COPPERLINE_FIXTURE_DIR)
	$(M68K_CC) $(M68K_CFLAGS) $< -o $@

$(COPPERLINE_FIXTURE_DIR)/bulkstage: tests/copperline/fixture/bulkstage.c | $(BUILD)/.dir
	@mkdir -p $(COPPERLINE_FIXTURE_DIR)
	$(M68K_CC) $(M68K_CFLAGS) $< -o $@

$(COPPERLINE_FIXTURE_DIR)/timeit: tests/copperline/fixture/timeit.c | $(BUILD)/.dir
	@mkdir -p $(COPPERLINE_FIXTURE_DIR)
	$(M68K_CC) $(M68K_CFLAGS) $< -o $@

$(COPPERLINE_FIXTURE_DIR)/modify: tests/copperline/fixture/modify.c | $(BUILD)/.dir
	@mkdir -p $(COPPERLINE_FIXTURE_DIR)
	$(M68K_CC) $(M68K_CFLAGS) $< -o $@

$(COPPERLINE_FIXTURE_DIR)/checkuaem: tests/copperline/fixture/checkuaem.c | $(BUILD)/.dir
	@mkdir -p $(COPPERLINE_FIXTURE_DIR)
	$(M68K_CC) $(M68K_CFLAGS) $< -o $@

$(COPPERLINE_FIXTURE_DIR)/bigfile: tests/copperline/fixture/bigfile.c | $(BUILD)/.dir
	@mkdir -p $(COPPERLINE_FIXTURE_DIR)
	$(M68K_CC) $(M68K_CFLAGS) $< -o $@

copperline-fixtures: $(COPPERLINE_FIXTURE_DIR)/stage $(COPPERLINE_FIXTURE_DIR)/readback \
	$(COPPERLINE_FIXTURE_DIR)/bulkstage $(COPPERLINE_FIXTURE_DIR)/timeit $(COPPERLINE_FIXTURE_DIR)/modify \
	$(COPPERLINE_FIXTURE_DIR)/checkuaem $(COPPERLINE_FIXTURE_DIR)/bigfile

# Copperline on-target harness (docs/proposal.md "Toolchain and testing",
# implementation-plan.md Phase 1 item 8): boots a minimal A1200/68020 from
# tests/copperline/boot/, runs stage -> AmiSnap SNAPSHOT/LIST/VERIFY/RESTORE
# -> readback, then asserts against the host-mounted result files. run.sh
# skips cleanly (exit 0 with a SKIP message, not a false pass) when the
# Kickstart ROM asset (nondistribution/roms/, gitignored) is absent, since
# CI has no such licensed asset.
#
# run-ffs.sh is the real-FFS-floppy complement (implementation-plan.md's
# item 8 "noted for later" follow-up): same pipeline, but against genuine
# AmigaDOS floppy filesystems (OFS/FFS/FFS+International, via amitools'
# xdftool) instead of Copperline's own HOSTFS pass-through. Skips cleanly
# if xdftool isn't on PATH, same convention as the ROM check.
#
# run-perf.sh is Phase 1's own performance gate: "10k-file unchanged run
# under a minute on emulated 68030 without archive-bit help" -- a real
# 68030/50 emulated run (--model A4000, needed: bare --cpu 68030 with no
# --model hangs before boot on this ROM's default chipset profile,
# confirmed empirically), timed by the guest's own DateStamp() rather
# than host wall-clock (accurate under Copperline's deterministic core
# regardless of host speed/warp-speed pacing). Slower than the other two
# on-target scripts (a several-minute --benchmark-until window) but
# still skips cleanly on the same missing-ROM/missing-tool convention.
#
# run-uaem.sh proves the .uaem round trip end to end across all three
# pieces built for it: the C repository writer (build/gen_sample_repo,
# same fixture make cross-check uses), the Python reference reader's
# own `restore --uaem`, and AmiSnap's ACTION=APPLYUAEM
# (src/amiga/applyuaem.c) applying the sidecars for real on a real FFS
# floppy (deliberately not HOSTFS -- see that script's own header for
# why HOSTFS's native .uaem awareness would make ApplyUAEM's own effect
# unobservable). Depends on the same $(CROSS_GEN_BIN) make cross-check
# builds, not on running that whole check again here.
#
# run-bigfile.sh proves fixed-size chunking end to end: a real file well
# over AMISNAP_DEFAULT_CHUNK_SIZE (repo.h) backs up, verifies, and
# restores byte-for-byte at a constrained fast-RAM config, exercising
# both the write side (amisnap_repo_writer_file_chunked) and the read
# side (restore.c's streaming use of backend.h's put_begin/put_append/
# put_finish) -- see implementation-plan.md's chunking item for why the
# read side needed its own fix, found only by this same on-target test.
#
# run-webdav.sh proves the WebDAV backend (Phase 3 item 3) end to end on
# real hardware emulation: boots Copperline with --hostsocket-net host
# (a Zorro board that installs bsdsocket.library into the guest with
# zero guest-side setup) and runs a real SNAPSHOT/LIST/VERIFY/RESTORE
# cycle against a real WebDAV server (tests/webdav/mini_webdav_server.py,
# the same independent, non-mock server Phase 3 item 5's host-CI check
# uses) reachable over a real TCP loopback connection out of the guest.
# Needs python3, same as webdav-check.
test-target: m68k copperline-fixtures $(CROSS_GEN_BIN)
	sh tests/copperline/run.sh
	sh tests/copperline/run-ffs.sh
	sh tests/copperline/run-perf.sh
	sh tests/copperline/run-uaem.sh
	sh tests/copperline/run-bigfile.sh
	sh tests/copperline/run-webdav.sh

# semgrep installs into a venv rather than the system/user Python, so
# `make lint` doesn't need pip on PATH (bare `pip` doesn't exist on
# every host -- see e.g. macOS with only `pip3`) and doesn't touch
# whatever else is installed globally. Reused across runs via the
# venv's own semgrep binary as the target file.
VENV := $(BUILD)/venv

$(VENV)/bin/semgrep: | $(BUILD)/.dir
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --quiet --upgrade pip
	$(VENV)/bin/pip install --quiet semgrep

lint: $(VENV)/bin/semgrep
	$(VENV)/bin/semgrep --config auto --error \
	  --include='*.c' --include='*.h' \
	  src/ tests/

version:
	@echo "$(VERSION).$(REVISION)"

# --- Host: unit / vector tests ---
test: $(BUILD)/run-tests
	$(BUILD)/run-tests

$(BUILD)/run-tests: $(CORE_SRCS) $(TEST_SRCS) $(CORE_HDRS) $(TEST_HDRS) | $(BUILD)/.dir
	$(CC) $(CFLAGS) $(CORE_INC) -Itests $(CORE_SRCS) $(TEST_SRCS) -o $@

# --- m68k: Amiga CLI binary (amiga-gcc on PATH) ---
#
# src/amiga/tls.c (Phase 3 item 4) needs AmiSSL's own headers to
# compile against -- amisslmaster.library itself stays a soft,
# runtime-only dependency (proposal.md's "the tool has no hard AmiSSL
# dependency"), but the C code that calls its API still needs real
# declarations to compile, the same way any library's headers are a
# build-time need distinct from the library itself being installed at
# runtime. scripts/fetch-amissl-sdk.sh is the same pinned/hashed,
# locally-cached fetch tests/copperline/'s own AmiSSL work already
# uses -- idempotent, so this costs nothing beyond the first real
# build on a given machine/CI cache. libamisslstubs.a resolves the
# link-time symbols for AmiSSL's own out-of-line call stubs (unlike
# bsdsocket.library's plain inline-asm LVO stubs, AmiSSL's varargs-tag
# API needs real stub functions) -- this is still link-time-only
# resolution against a jump table populated at runtime by
# OpenAmiSSLTags(), not a hard runtime dependency either.
# Cache dir pinned inside the repo checkout (git-ignored, survives
# `make clean` since that only wipes $(BUILD)), NOT the fetch script's
# own $HOME-based default -- a docker cross-build run with
# --user "$(id -u):$(id -g)" (this project's own standard invocation,
# used to avoid root-owned output) has no sane $HOME for that numeric
# UID, which silently broke this the first time it was wired in: the
# fetch script produced an empty path, `-I` got no argument, and the
# real error only surfaced three lines later as a confusing "header not
# found". Pinning the cache dir sidesteps that class of problem
# entirely rather than special-casing docker.
AMISSL_CACHE_DIR ?= $(CURDIR)/.amissl-cache

m68k: | $(BUILD)/.dir
	@sdk_dev=$$(AMISSL_CACHE_DIR="$(AMISSL_CACHE_DIR)" sh scripts/fetch-amissl-sdk.sh | sed -n '1p'); \
	if [ -z "$$sdk_dev" ]; then \
		echo "m68k: scripts/fetch-amissl-sdk.sh did not produce an SDK path -- see its own output above" >&2; \
		exit 1; \
	fi; \
	echo "$(M68K_CC) $(M68K_CFLAGS) -I$$sdk_dev/include $(CORE_SRCS) $(AMIGA_SRCS) $(CLI_SRCS) -L$$sdk_dev/lib/AmigaOS3 -lamisslstubs -o $(BUILD)/AmiSnap"; \
	$(M68K_CC) $(M68K_CFLAGS) -I"$$sdk_dev/include" $(CORE_SRCS) $(AMIGA_SRCS) $(CLI_SRCS) \
		-L"$$sdk_dev/lib/AmigaOS3" -lamisslstubs \
		-o $(BUILD)/AmiSnap

m68k-docker:
	$(DOCKER) run --rm --platform linux/amd64 $(DOCKER_USER) -v "$(CURDIR)":/work -w /work \
		$(AMIGA_GCC_IMAGE) sh -lc 'PATH=/opt/amiga/bin:$$PATH make m68k'

# --- lha: build the real LHa for UNIX (archive-capable), pinned ------------
# Homebrew's and Ubuntu's `lha` is Lhasa -- extract-only, useless for
# packaging -- and the last lha *release* tag (2021) no longer compiles
# with modern compilers, so build a pinned master commit from source into
# build/tools/. Same pinned commit as siblings amiauth/amipilot/sana2loop.
# Override with a known-good archiver: make dist LHA=/path/to/real/lha
LHA_REPO   := https://github.com/jca02266/lha.git
LHA_COMMIT := 86094cb56aba34de45668f39f74fcfb61e9d7fb6
LHA        ?= $(BUILD)/tools/lha

$(BUILD)/tools/lha:
	@mkdir -p $(BUILD)/tools
	rm -rf $(BUILD)/tools/lha-src
	git clone -q $(LHA_REPO) $(BUILD)/tools/lha-src
	cd $(BUILD)/tools/lha-src && \
		git -c advice.detachedHead=false checkout -q $(LHA_COMMIT) && \
		autoreconf -fi >/dev/null 2>&1 && ./configure >/dev/null && \
		$(MAKE) >/dev/null
	cp $(BUILD)/tools/lha-src/src/lha $(BUILD)/tools/lha
	rm -rf $(BUILD)/tools/lha-src

# --- guide: AmigaGuide user documentation, generated from userdocs/ ----------
# userdocs/ is the single source of truth for user docs (published as the
# versioned MkDocs site via mike/GitHub Pages) -- this converts the same
# Markdown into one hyperlinked AmigaGuide document for on-Amiga reading,
# same tool and convention as sibling AmiAuth's own `make guide`.
guide: | $(BUILD)/.dir
	python3 tools/docs2guide.py userdocs $(BUILD)/AmiSnap.guide

# --- dist: assemble the Aminet upload pair (archive + .readme) -------------
# Builds the m68k binary itself (build-test.yml's dist job runs `make
# dist` standalone). The $VER grep confirms the binary just built embeds
# the CURRENT version.mk VERSION.REVISION -- catching a stale build/
# before it ships (same self-check as the siblings' dist targets).
dist: m68k guide $(LHA)
	rm -rf $(BUILD)/dist
	mkdir -p $(BUILD)/dist/AmiSnap
	cp $(BUILD)/AmiSnap $(BUILD)/AmiSnap.guide LICENSE AmiSnap.readme $(BUILD)/dist/AmiSnap/
	cp AmiSnap.readme $(BUILD)/dist/
	@v="$(VERSION).$(REVISION)"; \
	grep -aqF "\$$VER: AmiSnap $$v (" $(BUILD)/dist/AmiSnap/AmiSnap || \
		{ echo "dist: $(BUILD)/dist/AmiSnap/AmiSnap lacks \"\$$VER: AmiSnap $$v (...)\" - stale build/?"; exit 1; }
	cd $(BUILD)/dist && $(abspath $(LHA)) aq AmiSnap.lha AmiSnap
	@ls -l $(BUILD)/dist/AmiSnap.lha $(BUILD)/dist/AmiSnap.readme

# A marker file, not $(BUILD) itself: BUILD's value is literally "build",
# so a target named $(BUILD) would collide with the verb-contract `build:`
# target above (Make merges prerequisites across rules sharing a target
# name) -- see sibling AmiAuth's Makefile for the same bug caught for real.
$(BUILD)/.dir:
	@mkdir -p $(BUILD)/.dir

clean:
	rm -rf $(BUILD)
