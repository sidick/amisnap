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

# --- m68k cross toolchain (Amiga build) ---
M68K_CC     ?= m68k-amigaos-gcc
# -m68020/-msoft-float: the target floor above, no FPU assumed. -noixemul
# links against libnix (no ixemul.library runtime dependency) -- see the
# libnix skill for startup/library-open conventions.
M68K_CFLAGS ?= -std=c99 -O2 -Wall -Wextra -Werror -m68020 -msoft-float -noixemul \
               $(CORE_INC) -Isrc/amiga \
               -DVERSION=$(VERSION) -DREVISION=$(REVISION)

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
	copperline-fixtures test-target lint dist version

all: test

# --- Verb contract (sidick/amiga-workflows' build-test.yml) ---------------
# ci.yml calls these five names; each build-test.yml job is independent
# (no artifact-passing between them), so test-target/dist pull in their
# own build steps rather than assuming a prior job ran.
build: m68k

test-host: test stackswap-vamos-test cross-check

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

$(CROSS_GEN_BIN): $(CROSS_GEN_SRC) src/core/backend_dir.c src/core/repo.c src/core/manifest.c \
	src/core/meta.c src/core/tlv.c src/core/blake2s.c src/core/xxhash32.c $(CORE_HDRS) | $(BUILD)/.dir
	$(CC) $(CFLAGS) $(CORE_INC) $(CROSS_GEN_SRC) src/core/backend_dir.c src/core/repo.c \
		src/core/manifest.c src/core/meta.c src/core/tlv.c src/core/blake2s.c src/core/xxhash32.c -o $@

cross-check: $(CROSS_GEN_BIN)
	sh tests/cross/run.sh

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
test-target: m68k copperline-fixtures $(CROSS_GEN_BIN)
	sh tests/copperline/run.sh
	sh tests/copperline/run-ffs.sh
	sh tests/copperline/run-perf.sh
	sh tests/copperline/run-uaem.sh
	sh tests/copperline/run-bigfile.sh

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
m68k: | $(BUILD)/.dir
	$(M68K_CC) $(M68K_CFLAGS) $(CORE_SRCS) $(AMIGA_SRCS) $(CLI_SRCS) \
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

# --- dist: assemble the Aminet upload pair (archive + .readme) -------------
# Builds the m68k binary itself (build-test.yml's dist job runs `make
# dist` standalone). The $VER grep confirms the binary just built embeds
# the CURRENT version.mk VERSION.REVISION -- catching a stale build/
# before it ships (same self-check as the siblings' dist targets).
dist: m68k $(LHA)
	rm -rf $(BUILD)/dist
	mkdir -p $(BUILD)/dist/AmiSnap
	cp $(BUILD)/AmiSnap LICENSE AmiSnap.readme $(BUILD)/dist/AmiSnap/
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
