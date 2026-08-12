#!/bin/sh
# Verifies a release tag (e.g. v1.0) matches version.mk and AmiSnap.readme
# before release.yml hands off to sidick/amiga-workflows' aminet-release.yml
# -- same shape as sibling amipilot's scripts/verify-version.sh.
#
# Usage: scripts/verify-version.sh vX.Y
set -eu

tag_ref="${1:?usage: verify-version.sh <tag, e.g. v1.0>}"
tag="${tag_ref#v}"

ver=$(sed -n 's/^VERSION[[:space:]]*:=[[:space:]]*//p' version.mk)
rev=$(sed -n 's/^REVISION[[:space:]]*:=[[:space:]]*//p' version.mk)
src="$ver.$rev"
readme=$(sed -n 's/^Version:[[:space:]]*\(.*\)$/\1/p' AmiSnap.readme)

echo "tag=$tag version.mk=$src AmiSnap.readme=$readme"
[ "$tag" = "$src" ]    || { echo "::error file=version.mk::Tag v$tag does not match version.mk \"$src\""; exit 1; }
[ "$tag" = "$readme" ] || { echo "::error file=AmiSnap.readme::Tag v$tag does not match Version: \"$readme\""; exit 1; }
