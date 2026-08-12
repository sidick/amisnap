#!/bin/sh
# On-target test harness placeholder. Nothing runs on-target yet: Phase 1's
# engine is host-tested, and the real Copperline harness (metadata
# round-trip asserted via .uaem sidecars on the host side -- see
# docs/proposal.md "Toolchain and testing") lands with the Amiga-side
# metadata capture code. Skips honestly rather than claiming coverage.
echo "SKIP: no on-target tests yet (Phase 1 engine is host-tested; see docs/proposal.md)"
exit 0
