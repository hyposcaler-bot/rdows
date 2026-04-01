# CLAUDE.md

## Build & Test
- `cargo test --workspace` — run all tests
- `cargo clippy --workspace` — lint
- `cargo doc --no-deps` — build docs
- Always run both after changes

## Rules
- Reference `rdows-rfc.txt` for protocol details. Follow the spec.
- No `unsafe` Rust
- No serde for wire format — manual encode/decode over `bytes::{Bytes, BytesMut}`
- Big-endian (network byte order): use `to_be_bytes()` / `from_be_bytes()`
- R_Key generation: `OsRng` only. Never `thread_rng()`.
- ibverbs naming: reg_mr, dereg_mr, post_send, post_recv, poll_cq, rdma_write, rdma_read
- Keep it simple. This is a PoC, not a production RDMA stack.