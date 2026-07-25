#!/usr/bin/env sh
set -eu

cargo install --path . --locked --force
secret-guard --version
