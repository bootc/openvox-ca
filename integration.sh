#!/usr/bin/env bash
set -eu -o pipefail

# Rebuild the throwaway `integration` branch: merge every open PR branch into a
# worktree, apply any fixes no single branch can carry, and force-push it.
#
# Companions:
#   integration-trial.sh         which branches conflict, read-only, no worktree
#   integration-verify-merge.sh  what a resolution dropped; runs below, mid-merge
#
# PUSHING THIS BRANCH SHIPS. A live deployment tracks
# ghcr.io/bootc/openvox-ca:integration-alpine. A push publishes the image,
# Renovate opens a digest bump and automerges it within about a minute, and Flux
# reconciles within 5 minutes; the chart pin is not automerged. So a build is a
# release of every listed branch to one production CA. Chris has accepted that
# arrangement — do not raise it again — but report the published digest after a
# push, not just that it happened.
#
# Rebuilds force-push this branch. The deployment's Flux source pins
# branch+commit, and the old commit objects remain, so the pin still resolves.
#
# ---------------------------------------------------------------------------
# WHAT GOES IN BRANCHES
#
# Every open non-draft PR except Renovate's, which merge on their own. Entries
# are refs, not shas, so only membership needs editing. Check both directions —
# an open PR missing, and an entry whose PR has merged (its ref is deleted, so
# the merge fails):
#
#   eval "$(sed -n '/^BRANCHES=(/,/^)/p' integration.sh)"
#   comm -3 <(gh pr list --state open --json isDraft,headRefName \
#               --jq '.[] | select(.isDraft|not) | .headRefName' | sort) \
#           <(printf '%s\n' "${BRANCHES[@]}" | sed 's|^origin/||' | sort)
#
# Expected leftovers: Renovate branches on one side, local/integration-setup on
# the other.
#
# Comments in BRANCHES hold only what does not decay: a merge order a PR body
# states, a stack, a resolution that needs more than its hunk. What conflicts
# today belongs to integration-trial.sh, which answers it on demand.
#
# Order by COLLISION, not file overlap, and keep colliding pairs adjacent so a
# conflict surfaces once. To measure collisions, merge each branch onto main
# first and then merge-tree those results pairwise. A single pairwise
# `merge-tree --merge-base=origin/main` reports a branch far behind main as
# colliding with everything.
#
# A stacked child must be merged after its parent. A child that conflicts with
# its own parent has not caught up with it — the parent moved on or was
# rewritten. That conflict is the child's own rebase to do, and the build should
# wait for it rather than resolve it here, where the resolution could differ
# from the one the child's driver makes.
#
# ---------------------------------------------------------------------------
# WHEN A BRANCH FAILS: HOLD THE BUILD, DO NOT DROP THE BRANCH
#
# A build that quietly omits a branch looks like a full integration. Stop,
# report which branch and why, and leave BRANCHES alone: removing an entry is
# Chris's call.
#
# ---------------------------------------------------------------------------
# CARRIED FIXES — integration-fixes.patch, applied after the merge loop
#
# None: PATCH_PATHS is empty and there must be no patch file. A carried fix is
# a change correct on no single branch, only once two are merged together.
# Before re-adding or retiring one, check whether the owning branch has absorbed
# it.
#
# ---------------------------------------------------------------------------
# HAZARD
#
# Never run `git history` here without --update-refs=head. Its default rewrites
# every local branch descending from the commit, and several worktrees share
# this object store.
#
# ---------------------------------------------------------------------------
# A GREEN BUILD IS NOT CLEARANCE TO TAG
#
# No `v*` tag until issue #250 closes (#282 is its PR). release.yml,
# container-images.yml and helm-chart.yml each trigger on `v*` independently,
# so a premature tag publishes images — `latest` included — and the chart even
# if release.yml fails. This script pushes a branch, never a tag.
#
# ---------------------------------------------------------------------------
# RESOLVING CONFLICTS
#
# rerere is not verification: it replays on matching conflict TEXT from a cache
# shared by every worktree. integration-verify-merge.sh runs before each merge
# commit and reports one-sided lines the resolution dropped (advisory; re-wrapped
# prose false-positives). To check a replay properly, redo the file with
# `git merge-file` from the three sides and compare: the resolution must match
# git's own merge outside the conflict hunks.
#
# Resolve by the PARAGRAPH or table ROW, not the file. Several branches each
# amend the same passages in locking.md, configuration.md, metrics.md and
# mixin/README.md. Where each side changed different rows, take each row from
# the side that changed it. Where both changed one, union and re-check the
# claims against the merged CODE.
#
# A branch that predates another carries the OLD claim unchanged in a region the
# newer one never touches, so nothing conflicts. Grep the merged tree for claims
# the other side has made false.
#
# A clean merge outside the hunk can still break the build. One side renames a
# symbol and the other adds callers of the old name: those calls merge cleanly
# and do not compile. Build after resolving any Go conflict.
#
# A conflict block need not start or end on a complete construct. If a side's
# last line is not one, reconstruct each side whole and union at the level the
# file is made of: whole test groups, struct fields or sections. gofmt and
# `go build` catch a broken Go union; nothing catches a YAML one, so for
# mixin/tests.yaml assert the group count and that no two groups share a name.
BRANCHES=(
  local/integration-setup

  # Collides with nothing else in this list.
  origin/issue-358-revoke-404             # PR #372 — issue #358

  # #312, #399 and #371 all collide with the managed-certificate stack below,
  # so they sit against it.
  #
  # #312 and #399 collide with it on the docs/development/locking.md lock-name
  # table. Resolve that ROW BY ROW: take whichever side carries the newer claim
  # for each row rather than picking a side.
  #
  # #399 is stacked on #312, so it follows it. It also collides with #371
  # (internal/storage/storage.go, docs/configuration.md,
  # docs/storage-backends.md) and with #336, #344, #282 and #266 on
  # packaging/systemd/openvox-ca.service.
  origin/feature/188-rebuild-inventory-hmac   # PR #312 — issue #188
  origin/feature/397-openvox-server-cadir     # PR #399 — issue #397
  origin/fix/351-sqlite-database-permissions  # PR #371 — issue #351

  # A STACK: #322 -> #336 -> #344, each based on the one before. Merge in that
  # order. A child conflicting with its parent is a rebase owed, not a
  # collision to resolve here (see the header).
  #
  # #336 x #371 needs more than its hunk. #336 renames storage's sqliteFilePath
  # to SQLiteFilePath; #371 adds new callers of the old name, which git merges
  # cleanly OUTSIDE the conflict, so rerere's replay leaves a tree that does
  # not compile. Rename every remaining sqliteFilePath, test files included.
  origin/feature/242-managed-certificates          # PR #322 — issue #242
  origin/feature/243-component-certificate-stores  # PR #336 — issue #243
  origin/feature/326-ca-serving-certificate        # PR #344 — issue #326

  # A STACK: #266 is based on #282. #282 collides with #336 and #344 above
  # (README.md, packaging/systemd/openvox-ca.service).
  #
  # #282 replaces the unit's StateDirectory with ReadWritePaths on cadir, while
  # #336 and #344 document StateDirectory in docs/configuration.md and
  # docs/systemd.md. Nothing conflicts, so the merged docs describe a unit that
  # no longer exists. Their fix, not a resolution: do not edit them here.
  origin/feature/package-payload          # PR #282 — issue #250
  origin/feature/release-packaging        # PR #266
)


# Branches excluded for a reason. Commenting one out of BRANCHES stops its
# merge but not its code, which still arrives through any branch built on it.
# Empty is fine; both checks below are silent on an empty set.
HELD_OUT=(
)


# Ancestry misses a cherry-pick, so pair each held-out branch with a
# "ref|symbol" marker its defect cannot travel without. A hit means look.
HELD_OUT_MARKERS=(
)

git fetch origin

# Pre-flight: a held-out branch must not have reached anything we merge.
for HELD in "${HELD_OUT[@]}"; do
  git rev-parse --verify --quiet "$HELD" >/dev/null || continue
  for BRANCH in "${BRANCHES[@]}"; do
    if git merge-base --is-ancestor "$HELD" "$BRANCH" 2>/dev/null; then
      echo "$HELD is held out, but is an ancestor of $BRANCH — it would be merged anyway." >&2
      echo "Read its note in BRANCHES before going further: excluding it from the array" >&2
      echo "no longer excludes its code, so the hold has to be re-decided rather than kept." >&2
      exit 1
    fi
  done
done

# Same question by the other route: has a marker symbol been picked across?
for ENTRY in "${HELD_OUT_MARKERS[@]}"; do
  HELD=${ENTRY%%|*}
  MARKER=${ENTRY#*|}
  git rev-parse --verify --quiet "$HELD" >/dev/null || continue
  for BRANCH in "${BRANCHES[@]}"; do
    if git grep -q "$MARKER" "$BRANCH" -- internal 2>/dev/null; then
      echo "$BRANCH contains '$MARKER', a marker for held-out $HELD." >&2
      echo "Ancestry says it was not merged, so it was cherry-picked or reimplemented." >&2
      echo "Check whether the held-out defect came with it before building." >&2
      exit 1
    fi
  done
done

git worktree add ../openvox-ca-integration -B integration origin/main

cd ../openvox-ca-integration
test "$(git rev-parse --abbrev-ref HEAD)" = "integration"

for BRANCH in "${BRANCHES[@]}"; do
  if ! git merge --no-edit "$BRANCH"; then
    if [ -n "$(git diff --name-only --diff-filter=U)" ]; then
      echo "Unresolved conflicts merging $BRANCH — dropping to a shell." >&2
      echo "Resolve, 'git add' the files, then either 'git commit' yourself or just exit when staged." >&2
      export debian_chroot="CONFLICTED"
      bash -i || true
      unset debian_chroot
      if [ -n "$(git diff --name-only --diff-filter=U)" ]; then
        echo "Still unresolved conflicts merging $BRANCH — aborting" >&2
        exit 1
      fi
    fi
    # Ask git rather than test .git/MERGE_HEAD: in a linked worktree .git is a
    # file, not a directory. rerere records only at commit time.
    if git rev-parse -q --verify MERGE_HEAD >/dev/null; then
      ../openvox-ca/integration-verify-merge.sh || true
      git commit --no-edit
    fi
  fi
done

# Carried fixes ride in as a patch, applied last once every file it edits is
# merged; it must be committed on local/integration-setup to reach the worktree.
#
#   PATCH_PATHS non-empty  a patch is required and may touch only these paths.
#   PATCH_PATHS empty      no fixes carried; a patch present anyway aborts.
PATCH_PATHS=""

if [ -n "$PATCH_PATHS" ] && [ ! -f integration-fixes.patch ]; then
  echo "PATCH_PATHS declares carried fixes but integration-fixes.patch is not in" >&2
  echo "this worktree, so NONE were applied. The build would look clean here and" >&2
  echo "fail under pre-push instead, in files whose own branches are blameless." >&2
  echo "Most likely it is untracked in the main checkout — commit it:" >&2
  echo "  git -C ../openvox-ca add integration-fixes.patch && git -C ../openvox-ca commit" >&2
  exit 1
elif [ -f integration-fixes.patch ]; then
  UNEXPECTED=$(git apply --numstat integration-fixes.patch | cut -f3 | while read -r p; do
    case " $PATCH_PATHS " in *" $p "*) ;; *) echo "$p" ;; esac
  done)
  if [ -n "$UNEXPECTED" ]; then
    echo "integration-fixes.patch touches paths PATCH_PATHS does not declare:" >&2
    printf '%s\n' "$UNEXPECTED" | sed 's/^/  /' >&2
    echo "Each carried fix is described at the top of this file; nothing else belongs" >&2
    echo "in the patch. If a fix has been added, declare it in PATCH_PATHS. If the" >&2
    echo "patch is stale, regenerate it with an explicit pathspec, or delete it." >&2
    exit 1
  fi
  echo "Applying integration-fixes.patch..." >&2
  # --3way survives churn around the hunks. It applies as a no-op when the
  # patch is already in the tree, so commit only if something changed.
  if git apply --3way integration-fixes.patch; then
    if git diff --quiet && git diff --cached --quiet; then
      echo "integration-fixes.patch was already applied; nothing to commit." >&2
    else
      git commit -qam "Carry the cross-branch test fixes this build needs"
    fi
  else
    echo "integration-fixes.patch no longer applies — a branch has moved under it." >&2
    echo "Check whether its owning branch has absorbed the fix; if so, drop the entry" >&2
    echo "from PATCH_PATHS and delete the patch. Otherwise re-derive it with:" >&2
    echo "  (cd ../openvox-ca-integration && git diff -- $PATCH_PATHS) > integration-fixes.patch" >&2
    exit 1
  fi
else
  echo "No carried fixes: PATCH_PATHS is empty and no patch is present." >&2
fi

# container-images.yml must keep both this branch's contribution (the
# `integration` trigger and `type=edge,branch=main`; without the trigger a push
# builds no image and nothing fails) and main's (cosign signing). Taking a
# branch's copy of the file wholesale loses either silently, so assert both.
# `--` because "- integration" starts with a dash.
for NEEDLE in '- integration' 'type=edge,branch=main' 'cosign sign --yes --recursive'; do
  if ! grep -qF -- "$NEEDLE" .github/workflows/container-images.yml; then
    echo "container-images.yml has lost \"$NEEDLE\"." >&2
    echo "A merge resolution has taken some branch's copy of that file wholesale." >&2
    echo "Restore it before pushing: this file carries both this branch's build" >&2
    echo "trigger and main's signing rewrite, and losing either is silent." >&2
    exit 1
  fi
done

git push bootc integration --force-with-lease
cd -
git worktree remove ../openvox-ca-integration/

# vim: ai ts=2 sw=2 et sts=2 ft=sh
