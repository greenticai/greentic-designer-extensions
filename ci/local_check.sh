#!/usr/bin/env bash
set -euo pipefail

echo "==> cargo fmt"
cargo fmt --all -- --check

echo "==> cargo clippy"
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

echo "==> cargo test (all features)"
cargo test --workspace --all-features --locked

# Also exercise the default feature shape. `dev-allow-unsigned` compiles the
# signature-bypass branch in, so an all-features-only suite never checks that a
# production build lacks it — and that branch is the one that matters most.
echo "==> cargo test (default features)"
cargo test --workspace --locked

echo "==> cargo build (release)"
cargo build --workspace --locked --release

echo "==> wit sync check (canonical vs vendored)"
diff wit/extension-host.wit crates/greentic-ext-runtime/wit/deps/extension-host/extension-host.wit
diff wit/extension-design.wit crates/greentic-ext-runtime/wit/deps/extension-design-0.4/extension-design.wit
diff wit/runtime-side.wit crates/greentic-ext-runtime/wit/runtime-side.wit

echo "All checks passed."
