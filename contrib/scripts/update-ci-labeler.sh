#!/usr/bin/env bash

set -e
set -o pipefail

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/../.."
WORKFLOW_PATH=".github/workflows"
LABELER_PATH=".github/labeler.yml"

# renovate: datasource=docker
YQ_IMAGE="docker.io/mikefarah/yq@sha256:495c1e1db2d653cce61a06da52cfca0c7d68d6249cc6e61b2a134d92c609c016" # 4.27.3
YQ="docker run --rm -v ${SCRIPT_ROOT}:/workdir --user $(id -u):$(id -g) $YQ_IMAGE"

function generate_ci_labeler() {
    cat <<EOF
dont-merge/needs-ci-validation:
- changed-files:
  - any-glob-to-any-file:
      - '.github/**/*'
      - '**/Makefile*'
      - 'images/**/*sh'
  - all-globs-to-all-files:
EOF

    grep -rl 'pull_request:$' "$WORKFLOW_PATH" \
    | while read -r path; do
        echo "    - '!$path'";
    done | sort
}

function check_diff() {
    local diff diff_staged
    diff="$(git diff)"
    diff_staged="$(git diff --staged)"

    if [ -n "$diff" ] || [ -n "$diff_staged" ]; then
        echo "Updated labeler configuration:"
        echo "$diff"
        echo "$diff_staged"
        echo "Please run 'contrib/scripts/update-ci-labeler.sh' and submit your changes"
        exit 1
    fi
}

function main() {
    local ci_labeler_yaml

    cd "$SCRIPT_ROOT"
    ci_labeler_yaml=$(mktemp "cilium-gh-labeler-XXXXXX.yaml")
    trap "rm $ci_labeler_yaml" EXIT

    generate_ci_labeler > "$ci_labeler_yaml"
    $YQ ea '. as $item ireduce ({}; . * $item )' \
        "$LABELER_PATH" \
        "$ci_labeler_yaml" \
    > "$LABELER_PATH.new"
    mv "$LABELER_PATH.new" "$LABELER_PATH"

    check_diff
}

main "$@"
