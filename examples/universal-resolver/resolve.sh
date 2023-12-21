#! /bin/sh
cargo build
set -o allexport; source ../../.env; set +o allexport
../../target/debug/universal-resolver "$@"
