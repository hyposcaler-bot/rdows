# Implement DoS Limits (RFC Section 12.3)

## Context

RDoWS is an RDMA-over-WebSockets implementation. Per `docs/rdows-rfc.txt` Section 12.3, the server must enforce resource limits to prevent denial-of-service. Currently all limits are unbounded. Use the RFC's recommended defaults.

## Limits to enforce

All from RFC Section 12.3 recommended defaults:

1. **Max MRs per session: 4096** — `memory_store.register()` should reject with `ErrInternal` (or add a new error if you prefer) when the region count hits the limit.

2. **Max total registered memory per session: 32 GiB** — `memory_store.register()` should track cumulative registered bytes and reject when a new registration would exceed 32 * 1024 * 1024 * 1024. Return `ErrBounds`.

3. **Max outstanding RDMA Read requests per session: 128** — Track in-flight reads in `Session`. Increment when READ_REQ is received, decrement when READ_RESP is sent. Reject with `ErrRnr` (or `ErrInternal`) when limit is hit.

4. **Max CQ depth: 65536** — Already the default in `DEFAULT_CQ_CAPACITY`. Just verify it's enforced (it is via the CQ overflow work).

5. **Max concurrent sessions per client IP: 256** — This requires tracking at the server level, not per-session. Add a shared `Arc<Mutex<HashMap<IpAddr, u32>>>` (or similar) in `run_server` that tracks active session count per IP. Reject new connections when limit is hit. Decrement when session ends.

6. **MR_REG rate limiting: 1000/sec per session (RFC Section 12.2)** — Track last MR_REG timestamp and count in a sliding window. Reject with `ErrInternal` if exceeded. Simple approach: store `mr_reg_count_this_second: u32` and `mr_reg_window_start: Instant`. If current time > window_start + 1 second, reset. If count >= 1000, reject.

## Changes

### `crates/rdows-server/src/memory_store.rs`

Add fields:
- `region_count: usize`
- `total_registered_bytes: u64`
- `max_regions: usize` (default 4096)
- `max_total_bytes: u64` (default 32 GiB)

In `register()`:
- Check `region_count >= max_regions` → reject
- Check `total_registered_bytes + region_len > max_total_bytes` → reject
- On success, increment both
- On `deregister()`, decrement both

### `crates/rdows-server/src/session.rs`

Add fields:
- `outstanding_reads: u32`
- `max_outstanding_reads: u32` (default 128)
- `mr_reg_count: u32`
- `mr_reg_window_start: tokio::time::Instant`

### `crates/rdows-server/src/handler.rs`

In `handle_read_req()`: check `session.outstanding_reads >= max_outstanding_reads` before processing. Reject if exceeded. Decrement after sending READ_RESP.

In `handle_mr_reg()`: check rate limit before calling `memory_store.register()`. If current window has >= 1000 regs, reject.

### `crates/rdows-server/src/lib.rs`

Add per-IP session tracking:

```rust
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

type SessionTracker = Arc<Mutex<HashMap<IpAddr, u32>>>;
```

In `run_server`, create the tracker. Pass to `handle_connection`. Before accepting a session, check count for that IP. On session end, decrement. Max 256 per IP.

### `crates/rdows-server/src/main.rs`

No CLI flags needed — use RFC defaults. Just works.

## Tests in `crates/rdows-client/tests/integration.rs`

- `max_mrs_per_session`: Register MRs in a loop. Use a test config with `max_regions: 3` (not 4096, that's too slow). Verify 4th registration fails.
- `max_total_memory`: Use a test config with `max_total_bytes: 1024`. Register a 512-byte MR (succeeds), register another 512-byte MR (succeeds), register a third 256-byte MR (fails).
- `mr_dereg_frees_capacity`: Hit the MR limit, deregister one, register again succeeds.

For per-IP limits and rate limiting, skip integration tests — they're hard to test without multiple connections and timing. The enforcement is simple enough that code review is sufficient.

### Config

Thread these limits through `ServerConfig`:

```rust
pub struct ServerConfig {
    pub recv_queue_depth: u32,
    pub max_regions_per_session: usize,
    pub max_total_bytes_per_session: u64,
    pub max_outstanding_reads: u32,
    pub max_sessions_per_ip: u32,
    pub mr_reg_rate_limit: u32,  // per second
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            recv_queue_depth: 128,
            max_regions_per_session: 4096,
            max_total_bytes_per_session: 32 * 1024 * 1024 * 1024,
            max_outstanding_reads: 128,
            max_sessions_per_ip: 256,
            mr_reg_rate_limit: 1000,
        }
    }
}
```

Pass through to `MemoryStore::new()` and `Session::new()` as needed.

## What NOT to do

- Don't add CLI flags for limits — defaults only
- Don't add complex rate limiting (token bucket, etc) — simple windowed counter is fine
- Don't change wire formats
- Don't add new error codes to the protocol — reuse existing codes (ErrBounds, ErrInternal, ErrRnr)

## Validation

`cargo test --workspace && cargo clippy --workspace`. All existing tests must pass — existing tests use well-under-limit resource counts so defaults won't affect them.