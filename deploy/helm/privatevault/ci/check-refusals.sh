#!/usr/bin/env bash
# Unsafe configurations must fail at render time, with a message that says why.
# RENDER is a command that takes one extra values file, e.g.
#   RENDER="helm template pv deploy/helm/privatevault -f"
set -euo pipefail
: "${RENDER:?set RENDER to a render command that takes a values file}"
dir=$(mktemp -d)
base='secrets: {name: s}
config: {name: c, presenterBundleKey: p}
signing: {trustedPublicKeys: "00"}'

expect_refusal() {  # name, expected message, extra yaml
  printf '%s\n%s\n' "$base" "$3" > "$dir/$1.yaml"
  if out=$($RENDER "$dir/$1.yaml" 2>&1); then
    echo "FAIL $1: rendered, expected a refusal"; exit 1
  fi
  grep -q "$2" <<<"$out" || { echo "FAIL $1: wrong message:"; echo "$out"; exit 1; }
  echo "ok   $1"
}

expect_refusal sqlite-with-two-replicas "SQLite cannot be shared" \
  'postgres: {enabled: false}
persistence: {enabled: true}
replicaCount: 2'
expect_refusal sqlite-autoscaled "SQLite cannot be shared" \
  'postgres: {enabled: false}
persistence: {enabled: true}
replicaCount: 1
autoscaling: {enabled: true}'
expect_refusal sqlite-without-volume "lost on restart" \
  'postgres: {enabled: false}
replicaCount: 1'
expect_refusal no-secret "secrets.name is required" 'secrets: {name: ""}'
expect_refusal no-config "config.name is required" 'config: {name: ""}'
expect_refusal secure-without-trusted-keys "trustedPublicKeys" 'signing: {trustedPublicKeys: ""}'
expect_refusal secure-without-lineage "lineage=enforce" 'lineage: shadow'
expect_refusal secure-without-presenters "presenterBundleKey" 'config: {name: c, presenterBundleKey: ""}'
expect_refusal bad-digest "image.digest must be" 'image: {digest: "latest"}'
echo "all unsafe configurations refused"
