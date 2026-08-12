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
# Target floor: 68020, AmigaOS 3.0 (V39) -- the audience for network
# backup skews accelerated/emulated (docs/proposal.md "Toolchain and
# testing"), and V39 gives SetOwner() for restore.

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

.PHONY: all test m68k m68k-docker clean build test-host test-target lint dist version

all: test

# --- Verb contract (sidick/amiga-workflows' build-test.yml) ---------------
# ci.yml calls these five names; each build-test.yml job is independent
# (no artifact-passing between them), so test-target/dist pull in their
# own build steps rather than assuming a prior job ran.
build: m68k

test-host: test

# Nothing runs on-target yet -- Phase 1's engine is host-tested first,
# and the Copperline metadata round-trip harness (docs/proposal.md
# "Toolchain and testing") lands with the Amiga-side capture code. run.sh
# skips cleanly (exit 0 with a SKIP message, not a false pass).
test-target: m68k
	sh tests/copperline/run.sh

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
