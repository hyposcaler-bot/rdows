# RDoWS Key-Value Store with Memory Region Visualizer

## Context

RDoWS is an RDMA-over-WebSockets implementation in `crates/`. We're building a key-value store demo where GET and PUT are implemented as RDMA Read and RDMA Write into a remote memory region. The web UI shows a live visualization of the remote memory region — a grid of hash table slots, hex view of the raw bytes, and a log of RDMA operations.

The existing codebase is in `crates/rdows-core`, `crates/rdows-client`, and `crates/rdows-server`. Read the client API in `crates/rdows-client/src/verbs.rs` and `crates/rdows-client/src/lib.rs`.

## Architecture

A single Rust binary (`rdows-kv`) that:
1. Starts an embedded RDoWS server (same pattern as the examples, with ephemeral TLS certs)
2. Connects an RDoWS client to that server
3. Registers a remote MR as the KV backing store
4. Runs an axum HTTP server serving the web UI and JSON API
5. API endpoints translate REST calls into RDMA Write (PUT) and RDMA Read (GET) against the remote MR

```
Browser <--HTTP/WS--> axum <--RDoWS/WSS--> embedded rdows-server
                       |
                   RdowsConnection
                       |
                   Remote MR (hash table)
```

## Crate: `crates/rdows-kv`

### Cargo.toml

```toml
[package]
name = "rdows-kv"
version = "0.1.0"
edition = "2021"

[dependencies]
rdows-core = { path = "../rdows-core" }
rdows-client = { path = "../rdows-client" }
rdows-server = { path = "../rdows-server" }
axum = "0.7"
tokio = { version = "1", features = ["full"] }
tokio-rustls = "0.26"
rustls = "0.23"
rcgen = "0.13"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
tracing-subscriber = "0.3"
tower-http = { version = "0.5", features = ["cors"] }
```

Add `rdows-kv` to the workspace `Cargo.toml` members list.

### Hash Table Layout in the Memory Region

Use a simple open-addressing hash table laid out in a flat byte array:

- **Total MR size: 64 KiB** (65536 bytes)
- **Number of slots: 64**
- **Slot size: 1024 bytes** (64 * 1024 = 65536)
- **Slot layout:**
  - Byte 0: status (0x00 = empty, 0x01 = occupied)
  - Bytes 1-2: key length (u16 big-endian)
  - Bytes 3-4: value length (u16 big-endian)
  - Bytes 5-259: key data (max 255 bytes, zero-padded)
  - Bytes 260-1023: value data (max 764 bytes, zero-padded)

**Hash function:** FNV-1a on the key bytes, mod 64 to get the slot index. Linear probing for collisions.

**PUT operation:**
1. Hash key → slot index
2. Linear probe to find an empty slot or matching key
3. Build the 1024-byte slot payload locally
4. RDMA Write the slot payload to `slot_index * 1024` in the remote MR
5. Return success with the slot index used

**GET operation:**
1. Hash key → slot index
2. RDMA Read 1024 bytes from `slot_index * 1024`
3. Check if the key matches. If not, linear probe (RDMA Read next slot)
4. Return the value if found, 404 if empty slot encountered

**DELETE operation:**
1. Find the slot via GET logic
2. RDMA Write a zeroed 1024-byte slot to that offset (sets status to 0x00)

### Source Files

**`src/main.rs`:**
- Parse CLI args: `--http-port` (default 8080), `--rdows-port` (default 9443)
- Start embedded RDoWS server with ephemeral TLS certs (same pattern as examples)
- Connect RDoWS client, register a 64 KiB remote MR with REMOTE_WRITE | REMOTE_READ
- Wrap the `RdowsConnection` in `Arc<Mutex<>>` for shared access from axum handlers
- Start axum on `0.0.0.0:{http_port}`
- Print startup message: `RDoWS KV store running at http://localhost:8080`

**`src/kv.rs`:**
- `KvStore` struct holding the `Arc<Mutex<RdowsConnection>>`, rkey, local MR lkey
- Constants: `SLOT_COUNT = 64`, `SLOT_SIZE = 1024`, `MR_SIZE = 65536`, `MAX_KEY_LEN = 255`, `MAX_VALUE_LEN = 764`
- `fn hash_key(key: &[u8]) -> usize` — FNV-1a mod 64
- `fn encode_slot(key: &str, value: &str) -> [u8; 1024]`
- `fn decode_slot(data: &[u8; 1024]) -> Option<(String, String)>` — returns None if status == 0x00
- `async fn put(&self, key: &str, value: &str) -> Result<PutResult>` — RDMA Write, returns slot index and whether it was an insert or update
- `async fn get(&self, key: &str) -> Result<Option<String>>` — RDMA Read with linear probing
- `async fn delete(&self, key: &str) -> Result<bool>` — returns true if key existed
- `async fn dump_slots(&self) -> Result<Vec<SlotInfo>>` — RDMA Read all 64 slots, return status of each (for the visualizer)

**`src/api.rs`:**
- axum router with these routes:
  - `GET /` → serve the HTML UI (embedded via `include_str!`)
  - `PUT /api/kv/:key` with JSON body `{"value": "..."}` → calls `kv.put()`, returns JSON with slot index and operation details
  - `GET /api/kv/:key` → calls `kv.get()`, returns JSON with value or 404
  - `DELETE /api/kv/:key` → calls `kv.delete()`
  - `GET /api/slots` → calls `kv.dump_slots()`, returns JSON array of all 64 slots with their status, key, value (for the visualizer to poll)
  - `GET /api/stats` → return connection info (session ID, rkey, MR size)

API responses should include RDMA operation details so the UI can show them:

```json
{
  "operation": "RDMA_WRITE",
  "slot": 17,
  "offset": "0x4400",
  "bytes": 1024,
  "key": "hello",
  "value": "world",
  "probes": 1
}
```

### HTML UI: `src/ui.html`

A single HTML file with embedded CSS and JS (no build tools, no frameworks). Embedded via `include_str!("ui.html")` in the axum handler.

**Layout (top to bottom):**

1. **Header:** "RDoWS Key-Value Store" with subtitle "GET/PUT via RDMA Read/Write over WebSocket" and connection info (Session ID, R_Key, MR size)

2. **Input panel:** Key input, Value input, PUT/GET/DELETE buttons. Clean and simple.

3. **Result panel:** Shows the result of the last operation including RDMA operation details (opcode, slot index, remote VA, bytes transferred, number of probes for linear probing)

4. **Memory Region Visualizer:** The main attraction.
   - An 8x8 grid of cells representing the 64 hash table slots
   - Each cell shows: slot index, abbreviated key (first 8 chars), status indicator
   - Color coding: empty slots are dark/neutral, occupied slots are highlighted, the slot involved in the most recent operation flashes/pulses briefly
   - Clicking a slot shows its full details (key, value, hex offset, raw bytes preview)

5. **Operation Log:** A scrolling log at the bottom showing recent RDMA operations with timestamps. Each entry shows the operation type, key, slot, offset, like:
   ```
   [12:34:56] RDMA WRITE → slot 17 @ VA 0x4400 (1024 bytes) PUT "hello" = "world"
   [12:34:58] RDMA READ  ← slot 17 @ VA 0x4400 (1024 bytes) GET "hello" → "world"
   [12:34:59] RDMA READ  ← slot 03 @ VA 0x0C00 (1024 bytes) GET "missing" → NOT FOUND
   ```

**Behavior:**
- On page load, fetch `/api/slots` and `/api/stats` to populate the grid and header
- After each PUT/GET/DELETE, re-fetch `/api/slots` to update the grid
- The recently-touched slot should flash for ~1 second (CSS animation)
- Auto-poll `/api/slots` every 2 seconds to stay current
- Input validation: reject keys > 255 bytes, values > 764 bytes, show inline error

**Style:**
- Dark theme (this is infrastructure tooling, not a SaaS landing page)
- Monospace fonts for hex values and the operation log
- The memory grid should feel like a hex editor or memory debugger
- Minimal, functional, no animations beyond the slot flash
- Color palette: dark background (#1a1a2e or similar), green for occupied slots, blue/cyan for active operations, red for errors/deletes

### Hex View (Optional Enhancement)

Below the grid, show a hex dump of the most recently accessed slot:

```
Slot 17 @ 0x4400-0x47FF:
01 00 05 00 05 68 65 6C 6C 6F 00 00 00 00 00 00  .....hello......
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
... (first 4-6 lines of hex)
```

This comes from the raw bytes returned by the GET API.

## What NOT to do

- Don't use any frontend framework (React, Vue, etc) — plain HTML/CSS/JS
- Don't use WebSocket from the browser to the RDoWS server — the browser talks HTTP to axum, axum does the RDMA operations
- Don't over-engineer the hash table — open addressing with linear probing is fine, no resizing
- Don't add authentication to the HTTP API
- Don't persist data — the MR is ephemeral

## Startup Flow

```
$ cargo run -p rdows-kv
RDoWS KV server starting...
  RDoWS server: wss://localhost:9443/rdows (ephemeral TLS)
  Session: 0xABCD1234
  Remote MR: R_Key=0xCAFEBABE, 65536 bytes (64 slots × 1024 bytes)
  HTTP UI: http://localhost:8080

Open http://localhost:8080 in your browser.
```

## Validation

`cargo test --workspace && cargo clippy --workspace` — existing tests must pass. No new tests required for the KV store (it's a demo), but the code should be clean and clippy-happy.