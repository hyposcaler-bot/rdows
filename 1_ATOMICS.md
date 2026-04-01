# Implement Atomic CAS/FAA Operations (RFC Section 7.4)

## Context

RDoWS is an RDMA-over-WebSockets implementation. The wire protocol types for atomic operations already exist (`AtomicReqPayload`, `AtomicRespPayload`, `ATOMIC_TYPE_CAS`, `ATOMIC_TYPE_FAA` in `rdows-core/src/message.rs`) but the server currently rejects them with `ERR_UNKNOWN_OPCODE`. We need to implement them for real.

Read `docs/rdows-rfc.txt` Section 7.4 for the spec. The existing code is in `crates/`.

## What to implement

### 1. Server: `memory_store.rs` — add `atomic_op()`

Add a method to `MemoryStore` that:
- Takes rkey, remote_va, atomic_type (CAS or FAA), operand1, operand2
- Validates R_Key exists and has `REMOTE_ATOMIC` access flag
- Validates 8-byte alignment of remote_va (`remote_va % 8 != 0` → `ErrAlignment`)
- Validates bounds (remote_va + 8 must fit within the MR)
- Reads 8 bytes at remote_va as a big-endian u64 (the "original value")
- For CAS: if original == operand1, write operand2; otherwise no-op
- For FAA: write (original.wrapping_add(operand1))
- Returns `Ok(original_value)` or `Err(ErrorCode)`

This must be done as a single method call (indivisible with respect to other RDoWS operations on the same MR, per spec).

### 2. Server: `handler.rs` — replace the atomic rejection with a real handler

Remove the `AtomicReq` arm from the "not supported" match in `dispatch()`. Add `handle_atomic_req()` that:
- Calls `memory_store.atomic_op()`
- On success: sends `AtomicResp` with original_value and status=0
- On error: sends ERROR with the appropriate error code
- Validate atomic_type is 0x01 or 0x02, otherwise ERR_UNKNOWN_OPCODE

### 3. Client: `verbs.rs` — add `atomic_cas()` and `atomic_faa()`

Two new public methods on `RdowsConnection`:

```rust
pub async fn atomic_cas(
    &mut self,
    wrid: u64,
    rkey: RKey,
    remote_va: u64,
    compare: u64,
    swap: u64,
) -> Result<u64, RdowsError>
```

```rust
pub async fn atomic_faa(
    &mut self,
    wrid: u64,
    rkey: RKey,
    remote_va: u64,
    addend: u64,
) -> Result<u64, RdowsError>
```

Both should:
- Build and send an `AtomicReq` message
- Await `AtomicResp`
- Push a CQE to the local completion queue
- Return the original value on success

Extract a shared `post_atomic()` helper to avoid duplication.

### 4. Integration tests in `crates/rdows-client/tests/integration.rs`

Add these tests:

- `atomic_cas_success`: Register MR with REMOTE_ATOMIC | REMOTE_WRITE, write a known u64 at offset 0, CAS with correct compare value, verify swap happened, verify returned original value
- `atomic_cas_no_match`: Same setup but CAS with wrong compare value, verify original value returned and memory unchanged
- `atomic_faa`: Write a known value, FAA with addend, verify new value = old + addend, verify returned original
- `atomic_alignment_error`: Attempt atomic at offset 3, expect ErrAlignment
- `atomic_access_denied`: Register MR with REMOTE_WRITE only (no REMOTE_ATOMIC), attempt atomic, expect ErrAccessDenied
- `atomic_bounds_error`: Attempt atomic at offset that would read past end of MR, expect ErrBounds

### 5. Example: `crates/rdows-client/examples/atomic_counter.rs`

Demonstrate FAA as a remote atomic counter:
- Connect, register remote MR with REMOTE_ATOMIC | REMOTE_READ | REMOTE_WRITE
- Initialize counter to 0 via RDMA Write
- FAA +1 five times in a loop, printing the previous value each time
- RDMA Read the final value, verify it equals 5
- Use the same embedded server pattern as the other examples

## What NOT to do

- Don't change any existing message types or wire formats
- Don't add atomicity across multiple MRs or cross-session atomicity
- Don't implement any locking beyond what single-threaded per-session handling gives you (the spec says atomicity with non-RDoWS accessors is "implementation-defined")

## Validation

Run `cargo test --workspace && cargo clippy --workspace` after implementation. All existing tests must continue to pass.