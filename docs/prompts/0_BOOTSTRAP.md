# RDoWS MVP — Claude Code Plan

## What Is This

An implementation of RFC XXXX: "RDMA over WebSockets (RDoWS)" — a protocol that emulates RDMA semantics (memory region registration, one-sided operations, queue pairs, completion queues) over WebSocket binary frames. The RFC is written in the style of a real IETF Standards Track document, complete with IANA considerations and normative references.

This is an April Fools project. The joke is that the spec is thorough, the implementation works, and nobody needed this. Treat the RFC as authoritative — follow it faithfully. The humor comes from the concept, not from cutting corners.

The RFC lives at `rdows-rfc.txt` in the repo root. Reference it constantly.

## MVP Scope

### In Scope
- **Connection lifecycle**: WebSocket upgrade with `rdows.v1` subprotocol, CONNECT/CONNECT_ACK handshake, DISCONNECT
- **24-byte frame header**: Per spec Section 5.1, big-endian, all fields
- **All opcodes from Section 5.2**: Enum coverage of the full table, even if not all are handled
- **Memory Region management**: MR_REG / MR_REG_ACK / MR_DEREG / MR_DEREG_ACK, Protection Domains, access flags, L_Key/R_Key with CSPRNG per Section 6.2
- **SEND/RECV**: Two-sided with posted Receive WRs, SG list, RECV_COMP, ERR_RNR
- **RDMA Write**: One-sided, R_Key + VA validation, WRITE_COMP
- **RDMA Read**: One-sided pull, READ_REQ / READ_RESP
- **Completion Queue**: CQE generation, poll_cq
- **ACK**: Cumulative ack (opcode 0x60)
- **ERROR**: Full error code table from Section 11
- **TLS required**: wss:// only, reject ws://
- **Server binary + Client library**

### Out of Scope
- Atomic operations (CAS, FAA) — opcodes defined but handler returns ERR_UNKNOWN_OPCODE
- Fragmentation — enforce Max_Message_Size, reject oversized with ERR_PAYLOAD_SIZE
- Credit-based flow control — advertise ICC=65535, accept and ignore CREDIT_UPDATE
- Completion coalescing — always send WRITE_COMP immediately
- Per-message compression

### Stubbed Behavior
- **Flow control**: Advertise ICC=65535 in CONNECT. Accept but ignore CREDIT_UPDATE. Don't track credits.
- **Fragmentation**: Default Max_Message_Size=16MiB. Reject oversized payloads. Never set F flag.
- **Atomics**: Define the opcodes and message types. Return ERR_UNKNOWN_OPCODE if received.

---

## Project Structure

```
rdows/
├── Cargo.toml              # Workspace
├── rdows-rfc.txt           # The spec
├── CLAUDE.md
├── crates/
│   ├── rdows-core/         # Wire types, frame codec, shared logic
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── frame.rs        # 24-byte header encode/decode
│   │       ├── opcode.rs       # Full opcode enum from Section 5.2
│   │       ├── error.rs        # Error codes from Section 11
│   │       ├── memory.rs       # MR, PD, MKey, AccessFlags types
│   │       ├── queue.rs        # QP, CQ, CQE, WR, SG types
│   │       └── message.rs      # Per-opcode payload encode/decode
│   │
│   ├── rdows-server/
│   │   └── src/
│   │       ├── main.rs         # CLI: --bind, --cert, --key
│   │       ├── session.rs      # Session state machine
│   │       ├── memory_store.rs # MR registry, R_Key gen/validation
│   │       └── handler.rs      # Opcode dispatch
│   │
│   └── rdows-client/
│       └── src/
│           ├── lib.rs          # Public API
│           ├── connection.rs   # WS connect + subprotocol negotiation
│           ├── verbs.rs        # ibverbs-style: reg_mr, post_send, rdma_write, etc.
│           └── completion.rs   # Local CQ
│
├── examples/
│   ├── echo_send_recv.rs
│   ├── one_sided_write.rs
│   └── one_sided_read.rs
│
└── tests/
    └── integration.rs          # Single file is fine for a PoC
```

---

## Dependencies

```toml
# rdows-core
bytes = "1"
thiserror = "2"
rand = "0.8"                    # OsRng for R_Key CSPRNG

# rdows-server, rdows-client
tokio = { version = "1", features = ["full"] }
tokio-tungstenite = "0.24"
tokio-rustls = "0.26"
rustls = "0.23"
tracing = "0.1"
tracing-subscriber = "0.3"

# dev-dependencies (workspace)
rcgen = "0.13"                  # Ephemeral TLS certs for tests
```

---

## Implementation Phases

Each phase must compile and pass tests before proceeding. Run `cargo test --workspace && cargo clippy --workspace` after each phase.

### Phase 1: Core Wire Types

All protocol types, full opcode table, frame header codec with round-trip unit tests.

1. Workspace setup with three crates
2. `opcode.rs` — enum with `TryFrom<u8>`, all opcodes from Section 5.2 including reserved ranges
3. `error.rs` — ErrorCode enum, ERROR message payload struct
4. `frame.rs` — `RdowsHeader` (24 bytes big-endian), encode/decode, flag bit constants. Unit tests for boundary values.
5. `memory.rs` — AccessFlags bitmask, ProtectionDomain, MemoryRegion, MemoryKey types
6. `queue.rs` — WorkRequest, WorkRequestId, CQE, ScatterGatherEntry
7. `message.rs` — payload types for every opcode with encode/decode. Unit test each.

### Phase 2: Server Connection + Client Connect

Server accepts wss://, negotiates subprotocol, CONNECT/CONNECT_ACK, DISCONNECT.

1. Server `main.rs` — TLS listener, WebSocket upgrade, subprotocol check
2. `session.rs` — states: AwaitingConnect → Ready → Closed. Track session ID, sequence numbers, Max_Message_Size.
3. Client `connection.rs` — connect to wss://, send CONNECT, await CONNECT_ACK
4. Reject ws://, reject missing `rdows.v1` (close 1002)
5. Integration test: connect, handshake, disconnect

### Phase 3: Memory Regions

MR_REG → MR_REG_ACK → MR_DEREG → MR_DEREG_ACK. R_Key via CSPRNG, no reuse within session.

1. `memory_store.rs` — per-session registry, `Vec<u8>` backing buffers, R_Key generation with `OsRng`, `HashSet<u32>` for used R_Keys
2. Server handlers for MR_REG and MR_DEREG
3. Client `reg_mr()` and `dereg_mr()` in verbs
4. Test: register, get keys, deregister, verify R_Key invalidated

### Phase 4: SEND/RECV

Two-sided ops. Posted Receive required.

1. Server + client: Receive Queue (`VecDeque`), post_recv, post_send
2. SEND handler: dequeue posted recv, copy data, CQE, send RECV_COMP. ERR_RNR if none posted.
3. Client RECV_COMP handler, poll_cq
4. Both sides are symmetric — either can initiate
5. Test: send data both directions, verify CQEs. Test ERR_RNR.

### Phase 5: RDMA Write + Read

One-sided operations, the whole point of the joke.

1. `rdma_write()` — build WRITE msg, validate R_Key + REMOTE_WRITE + bounds on server, copy into MR, WRITE_COMP
2. `rdma_read()` — build READ_REQ, validate R_Key + REMOTE_READ + bounds, send READ_RESP
3. Access flag enforcement: ERR_ACCESS_DENIED, ERR_BOUNDS
4. Test: write data into remote MR, read it back, verify match. Test error cases.

### Phase 6: Error Handling + ACK + Polish

1. ACK handling, sequence number tracking
2. Unknown opcode → ERR_UNKNOWN_OPCODE
3. Version mismatch → ERR_PROTO_VERSION
4. Oversized payload → ERR_PAYLOAD_SIZE
5. R_Key invalidation on session teardown

### Phase 7: Examples + README

1. Three working examples against a running server
2. `gen-certs.sh` for self-signed test certs
3. `README.md` — deadpan tone. Present it straight. Link to the RFC. The README should read like a real project. The joke is that you get 3 paragraphs in before you realize what's happening.
4. Doc comments on public API

---

## Tone Notes

The README, doc comments, and commit messages should be **completely straight-faced**. No winking, no "haha this is silly." Present RDoWS as a serious engineering artifact. The absurdity speaks for itself — you're implementing RDMA over WebSockets, and you did it *correctly*.