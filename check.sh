#!/bin/bash
cargo fmt -- --check
cargo clippy -- -Dwarnings
cargo test