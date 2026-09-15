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
# Every open non-draft PR except Renovate's, which merge on their own, and
# except PRs from forks: a build ships to production unreviewed, so an outside
# contributor's code stays out until Chris says otherwise (ruled 2026-10-11, on
# #494). Entries are refs, not shas, so only membership needs editing. Check
# both directions — an open PR missing, and an entry whose PR has merged (its
# ref is deleted, so the merge fails):
#
#   eval "$(sed -n '/^BRANCHES=(/,/^)/p' integration.sh)"
#   comm -3 <(gh pr list --state open --json isDraft,headRefName \
#               --jq '.[] | select(.isDraft|not) | .headRefName' | sort) \
#           <(printf '%s\n' "${BRANCHES[@]}" | sed 's|^origin/||' | sort)
#
# Expected leftovers: Renovate branches and fork PRs' branch names on one side,
# local/integration-setup on the other.
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
# A carried fix is a change correct on no single branch, only once two are
# merged together. Before re-adding or retiring one, check whether the owning
# branch has absorbed it. Carried now:
#
#   #349 rename x every other branch — old names a merge cannot convert. A
#     rename PR's sweep runs once, on its own branch; a merge does not re-run
#     it. So a line ANOTHER branch adds in an old name, outside any conflict,
#     survives the merge: PUPPET_CA_ -> OPENVOX_CA_ and /etc/puppet-ca ->
#     /etc/openvox-ca. Conflict hunks are converted at the stop; this patch
#     takes the rest. Some are not cosmetic:
#       #514 x #510  config.go `const configEnvVar = "PUPPET_CA_CONFIG"`: the
#                    server would read the old name.
#       #521 x #510  generate_test.go's config pin; its must-fail twin goes red.
#       #519 x #510  _helpers.tpl's storageBackend reads the env var by name;
#                    unconverted, the replica refusal stops seeing it.
#       #520 x #510  autosign_validation_test.go's config pins go inert.
#     The rest are prose and comments (#515, #520, and a line #510's re-wrap
#     put in cmd/openvox-ca-ctl/main_test.go). After the patch the tree must
#     hold no PUPPET_CA_, /etc/puppet-ca or puppetca_, and exactly #514's 9
#     deliberate /var/lib/puppet-ca pins.
#   #514 x #519  magefile.go — #519 quotes mountPath in deployment.yaml, so
#     #514's two pinned-mountPath chart:test cases expect "mountPath:
#     \"/var/lib/puppet-ca\"". Each PR is green alone; the merge fails 2
#     chart assertions without this.
#
#   Retire a line when its PRs have both merged: the second to land carries
#   it. Regenerate the patch from a trial build with an explicit pathspec.
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
# release.yml, container-images.yml and helm-chart.yml each trigger on `v*`
# independently, so a tag publishes images — `latest` included — and the chart
# even if release.yml fails. Tagging is a release decision, not a build step:
# this script pushes a branch, never a tag. (#250, the packaging issue the old
# hold here waited on, closed on 2026-10-13.)
#
# ---------------------------------------------------------------------------
# RESOLVING CONFLICTS
#
# rerere is not verification: it replays on matching conflict TEXT from a cache
# shared by every worktree. integration-verify-merge.sh runs before each merge
# commit and reports one-sided lines the resolution dropped (informational; re-wrapped
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

  # Collide with nothing else in this list.
  origin/docs/310-named-fixes             # PR #511 — issue #310
  origin/fix/483-renewrace-ordering       # PR #513 — issue #483
  origin/fix/432-plaintext-key-warning    # PR #515 — issue #432
  origin/fix/447-storage-hygiene          # PR #517 — issue #447
  origin/fix/452-systemd-hardening        # PR #518 — issue #452
  origin/fix/495-refuse-ca-subject-key-writes  # PR #521 — issue #495
  origin/fix/445-migrate-verify-source    # PR #522 — issue #445
  origin/fix/493-group-accessible-locks   # PR #524 — issue #493

  # The #349 rename, three independent PRs that collide with one another:
  # metrics (#507), env vars (#510), paths (#514). Merge them in that order,
  # the order they land on main, each straight before the PRs it collides with.
  #
  # Each resolution between two of them is MECHANICAL: re-run the other PR's
  # substitution over the merged file (AGENTS.md's contract bullets and
  # CONTRIBUTING.md's "own published names" sentence take both). Storage
  # identifiers never rename: puppet_ca_blobs, puppet_ca_inventory, the
  # /puppet-ca etcd and puppet-ca Redis prefixes, and the /puppet-ca/v1 route.
  #
  # A merge does not re-run a sweep. Lines another branch ADDED in an old name
  # outside any conflict survive the merge unconverted; those are the carried
  # fix described in the header, not something to resolve here.
  origin/rename/349-metrics-openvoxca     # PR #507 — issue #349
  # #512 x #507, docs/kubernetes-export.md, one line: #512's absolute mixin
  # link plus #507's OpenVoxCAKubernetesExportFailing ("an", not "a").
  origin/docs/249-absolute-links          # PR #512 — issue #249
  origin/rename/349-env-openvoxca         # PR #510 — issue #349
  # #520 x #510: take #520's new setting with #510's OPENVOX_CA_ spelling.
  origin/fix/438-autosign-recheck         # PR #520 — issue #438
  origin/rename/349-paths-openvoxca       # PR #514 — issue #349
  # #503 x #514, magefile_test.go: both append a Describe at end of file; keep
  # both.
  origin/ci/gate-container-builds         # PR #503
  # #519 meets three of the above. magefile.go Dev.Check: keep #503's
  # verifyAggregateJobs and #519's verifyChartBackendAliases (a guard left
  # uncalled fails verifyDevCheckWiring). magefile.go openbao-auth chart:test
  # cases: #510's OPENVOX_CA_ names with #519's quoted serviceAccountName.
  # docs/helm-chart.md: #514's paths in #519's replica paragraph.
  origin/fix/450-chart-hardening          # PR #519 — issue #450
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
PATCH_PATHS="charts/openvox-ca/templates/_helpers.tpl cmd/openvox-ca/autosign_validation_test.go cmd/openvox-ca/config.go cmd/openvox-ca/generate_test.go cmd/openvox-ca-ctl/main_test.go docs/configuration.md docs/systemd.md magefile.go"

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
