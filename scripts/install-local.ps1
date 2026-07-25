$ErrorActionPreference = "Stop"

cargo install --path . --locked --force
secret-guard --version
