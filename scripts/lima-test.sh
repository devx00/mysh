#!/usr/bin/env bash
# Run the workspace tests on Linux inside a lima VM.
#
#   scripts/lima-test.sh [INSTANCE]
#
# Expects an instance (default `mysh-ci`) with the repo mounted read-only at
# /mnt/mysh and rustup installed for the VM user; `scripts/lima.yaml` is a
# template that provisions exactly that:
#
#   limactl start --name mysh-ci scripts/lima.yaml
#
# The tree is rsynced into the VM (excluding `target/`) so the build does not
# touch the host checkout.
set -euo pipefail

instance="${1:-mysh-ci}"
limactl shell "$instance" -- bash -lc '
  set -euo pipefail
  source ~/.cargo/env
  rsync -a --delete --exclude target /mnt/mysh/ ~/mysh/
  cd ~/mysh
  cargo test --workspace 2>&1 | tail -n 40
'
