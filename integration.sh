#!/bin/bash
set -eu -o pipefail

BRANCHES=(
  # Always keep
  local/integration-setup

  # List of PR branches to integrate (Renovate PRs are deliberately excluded).
  # These are origin/ refs so each build integrates what is actually on the PR
  # rather than a stale local copy; the fetch below refreshes them.
  origin/fix/etcd-jitter-nosemgrep  # PR #149
  origin/fix/signer-psk-pipe        # PR #150
  origin/feature/compose-reorg      # PR #145

  # Stack: #154 was cut from #151, but the two have since diverged
  origin/feature/cert-index         # PR #151
  origin/feature/etcd-inventory     # PR #154

  # Stack: #143 and #157 were both cut from #142. #157 still has it as an
  # ancestor; #143 has diverged from it.
  origin/feature/version-stamping   # PR #142
  origin/docs/ctl-tls-flags         # PR #143
  origin/feature/helm-chart         # PR #157

  # Intermediate-CA work. Listed in dependency order, deepest last: merging a
  # branch before something it is built on drags that thing in early, at
  # whatever revision the branch happens to carry, and every later merge of the
  # real branch then fights those stale copies.
  #
  # Two kinds of dependency, and only the first is visible to git:
  #
  #   ancestor    the branch was cut from the other and still has it in its
  #               history, so merging the other afterwards is a no-op
  #   carries     the branch cherry-picked the other's commits, so the two must
  #               stay in step — if the other is rebased or amended, the
  #               carrier needs rebasing too or its stale copies conflict
  #
  # #166 carries #163 and #164 because it needs both the oracle and the renewal
  # gates, while being stacked on crl-chain-distribution for the maintenance
  # loop; no single branch holds all three. crl-chain-distribution carries #162
  # for the same reason.
  feature/sub-ca-bootstrap                # MR 1, PR #160   — standalone
  fix/crl-chain-preservation              # MR 2, PR #162   — standalone
  test/authorisation-baseline             # MR 6, PR #163   — standalone
  fix/renewal-issuer-gates                # MR 7, PR #164   — ancestor: #163
  feature/tls-self-provision              # MR 3, PR #165   — standalone
  feature/tls-self-provision-integration  # MR 4, PR #167   — ancestor: #157; carries #165
  feature/crl-chain-distribution          # MR 5, PR #168   — ancestor: #165; carries #162
  feature/client-trust-domains            # MR 8, PR #166   — ancestor: #168; carries #163, #164
)

git fetch origin
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
    # rerere resolved everything (or you resolved it in the shell above) —
    # commit only if the merge wasn't already finished for us
    if [ -f .git/MERGE_HEAD ]; then
      git commit --no-edit
    fi
  fi
done

git push bootc integration --force-with-lease
cd -
git worktree remove ../openvox-ca-integration/

# vim: ai ts=2 sw=2 et sts=2 ft=sh
