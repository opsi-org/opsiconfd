#!/usr/bin/env sh

set -o errexit
set -o nounset

cmd="sleep infinity"

exec $cmd
