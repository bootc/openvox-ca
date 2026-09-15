#!/usr/bin/env bash
# Report lines that one side of a merge added and the resolution then dropped.
# Run mid-merge, before committing: integration.sh calls it once the conflicted
# files are resolved and staged.
#
# rerere replays a resolution whenever the CONFLICT TEXT matches, not whenever
# the resolution is still right, and its cache is shared by every worktree here.
# A replayed file shows no markers, so "rerere resolved it" proves only that a
# previous resolution existed for the same text.
#
# The sides are read from commits (HEAD, MERGE_HEAD and their merge base), not
# from index stages: `git add` collapses the stages, so a stage-based check sees
# nothing at exactly the point it is called. The conflicted files come from
# `merge-tree`, which ignores rerere, so a replayed file is still listed.
#
# Advisory, not blocking: dropping a line is often the right resolution, and
# re-wrapped prose false-positives because the content survives while the line
# breaks move.
#
# Usage: ./integration-verify-merge.sh [file...]   (default: every file the merge
#                                                   conflicted on)
set -eu -o pipefail

cd "$(dirname "$0")/../openvox-ca-integration" 2>/dev/null || cd "$(dirname "$0")"

if ! git rev-parse -q --verify MERGE_HEAD >/dev/null; then
  echo "No merge in progress." >&2
  echo "To inspect a merge already committed, re-run it: git merge --no-commit <branch>" >&2
  exit 1
fi

BASE=$(git merge-base HEAD MERGE_HEAD)

if [ "$#" -gt 0 ]; then
  FILES="$*"
else
  # Line 1 is the tree; the conflicted paths follow, up to the first blank line.
  FILES=$(git merge-tree --write-tree --name-only HEAD MERGE_HEAD 2>/dev/null \
    | sed -n '2,$p' | sed '/^$/,$d' | sort -u || true)
fi

[ -n "$FILES" ] || { echo "No conflicted files in this merge."; exit 0; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

status=0
for f in $FILES; do
  [ -f "$f" ] || continue
  git show "$BASE:$f" >"$TMP/base" 2>/dev/null || : >"$TMP/base"
  git show "HEAD:$f" >"$TMP/ours" 2>/dev/null || : >"$TMP/ours"
  git show "MERGE_HEAD:$f" >"$TMP/theirs" 2>/dev/null || : >"$TMP/theirs"

  # A line each side added relative to the base. Blank lines are noise; anything
  # else that vanished is worth a human deciding on.
  ours_added=$(comm -13 <(sort -u "$TMP/base") <(sort -u "$TMP/ours") | grep -vE '^\s*$' || true)
  theirs_added=$(comm -13 <(sort -u "$TMP/base") <(sort -u "$TMP/theirs") | grep -vE '^\s*$' || true)

  lost_ours=$(comm -23 <(printf '%s\n' "$ours_added" | sort -u) <(sort -u "$f") | grep -vE '^\s*$' || true)
  lost_theirs=$(comm -23 <(printf '%s\n' "$theirs_added" | sort -u) <(sort -u "$f") | grep -vE '^\s*$' || true)

  if [ -n "$lost_ours$lost_theirs" ]; then
    status=1
    echo "── $f"
    [ -n "$lost_ours" ]   && printf '%s\n' "$lost_ours"   | sed 's/^/   dropped from OURS:   /'
    [ -n "$lost_theirs" ] && printf '%s\n' "$lost_theirs" | sed 's/^/   dropped from THEIRS: /'
    echo
  fi
done

if [ "$status" -ne 0 ]; then
  cat >&2 <<'MSG'
Lines above were added by one side and are not in the resolution.

Not automatically wrong — a resolution legitimately drops a line when the other
side rewrote the same sentence. Decide each one rather than finding it in a
merged tree later.

To redo a file by hand:  git checkout --conflict=merge -- <file>
MSG
else
  echo "Checked: $(echo "$FILES" | wc -w | tr -d ' ') file(s); no one-sided additions were dropped."
fi
exit 0

# vim: ai ts=2 sw=2 et sts=2 ft=sh
