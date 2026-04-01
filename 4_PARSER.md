# Implement SSLKEYLOGFILE Support and Wireshark RDoWS Dissector

## Context

RDoWS is an RDMA-over-WebSockets implementation. We want to be able to inspect RDoWS traffic in Wireshark with full decryption and protocol-aware dissection. This requires two things:

1. TLS key logging via SSLKEYLOGFILE so Wireshark can decrypt the TLS traffic
2. A Wireshark Lua dissector that parses the 24-byte RDoWS header and payloads inside WebSocket binary frames

Read `docs/rdows-rfc.txt` Section 5.1 (frame header), Section 5.2 (opcodes), Section 6.1 (MR_REG payload), Section 7 (operation payloads), and Section 11 (error codes) for the wire format details.

---

## Feature 1: SSLKEYLOGFILE Support

When the `SSLKEYLOGFILE` environment variable is set, both client and server should dump TLS session keys to that file in the NSS Key Log Format. Wireshark reads this format natively under Preferences → Protocols → TLS → (Pre)-Master-Secret log filename.

### Server changes (`crates/rdows-server/src/lib.rs` and `main.rs`)

In `build_server_tls_config()` (or in `main.rs` where the ServerConfig is built), check for `std::env::var("SSLKEYLOGFILE")`. If set:

```rust
use rustls::KeyLogFile;

let config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certs, key)?;

// This is the only addition:
config.key_log = Arc::new(KeyLogFile::new());
```

`rustls::KeyLogFile::new()` automatically reads the `SSLKEYLOGFILE` env var and writes to that path. That's it for the server.

Note: `key_log` needs to be set on the `ServerConfig` after building. `ServerConfig::builder()` returns a `ServerConfig` directly, so you can set `config.key_log` before wrapping in `Arc`. Check if `build_server_tls_config` wraps in Arc -- if so, set key_log before the Arc::new.

### Client changes (`crates/rdows-client/src/connection.rs` and `main.rs`)

Same pattern for the client's `rustls::ClientConfig`. In `build_tls_config()` in `main.rs`:

```rust
let mut config = rustls::ClientConfig::builder()
    .with_root_certificates(root_store)
    .with_no_client_auth();

config.key_log = Arc::new(rustls::KeyLogFile::new());
```

Also add it to the test helper `start_embedded_server()` in the examples so examples can be captured too. DON'T add it to integration tests -- the key log is only useful for manual Wireshark inspection.

### No CLI flags needed

`KeyLogFile::new()` is a no-op when SSLKEYLOGFILE isn't set. So always install it -- zero cost when not in use, no flag needed.

---

## Feature 2: Wireshark Lua Dissector

Create `wireshark/rdows.lua` in the repo root. This is a standalone Lua script loaded into Wireshark via Preferences → Protocols → Lua → Lua script or placed in the Wireshark plugins directory.

The dissector registers on the WebSocket dissector's binary payload and parses RDoWS framing.

### Structure

```lua
-- rdows.lua — Wireshark dissector for RDoWS (RDMA over WebSockets)

local rdows_proto = Proto("rdows", "RDMA over WebSockets")

-- Header fields (24 bytes)
local f_version      = ProtoField.uint8("rdows.version", "Version", base.HEX)
local f_opcode       = ProtoField.uint8("rdows.opcode", "Opcode", base.HEX)
local f_flags        = ProtoField.uint16("rdows.flags", "Flags", base.HEX)
local f_flag_f       = ProtoField.bool("rdows.flags.fragment", "Fragment", 16, nil, 0x8000)
local f_flag_l       = ProtoField.bool("rdows.flags.last", "Last Fragment", 16, nil, 0x4000)
local f_flag_s       = ProtoField.bool("rdows.flags.solicited", "Solicited", 16, nil, 0x2000)
local f_session_id   = ProtoField.uint32("rdows.session_id", "Session ID", base.HEX)
local f_sequence     = ProtoField.uint32("rdows.sequence", "Sequence Number", base.DEC)
local f_wrid         = ProtoField.uint64("rdows.wrid", "Work Request ID", base.DEC)
local f_payload_len  = ProtoField.uint32("rdows.payload_length", "Payload Length", base.DEC)

-- Payload fields — define fields for each opcode's payload

-- CONNECT / CONNECT_ACK
local f_pd_handle    = ProtoField.uint32("rdows.pd", "PD Handle", base.HEX)
local f_cap_flags    = ProtoField.uint32("rdows.capability_flags", "Capability Flags", base.HEX)
local f_max_msg_size = ProtoField.uint32("rdows.max_msg_size", "Max Message Size", base.DEC)
local f_icc          = ProtoField.uint32("rdows.icc", "Initial Credit Count", base.DEC)

-- MR_REG
local f_access_flags = ProtoField.uint32("rdows.access_flags", "Access Flags", base.HEX)
local f_region_len   = ProtoField.uint64("rdows.region_len", "Region Length", base.DEC)

-- MR_REG_ACK
local f_lkey         = ProtoField.uint32("rdows.lkey", "L_Key", base.HEX)
local f_rkey         = ProtoField.uint32("rdows.rkey", "R_Key", base.HEX)
local f_status       = ProtoField.uint16("rdows.status", "Status", base.HEX)

-- MR_DEREG
-- reuses f_pd_handle and f_lkey

-- WRITE
local f_remote_va    = ProtoField.uint64("rdows.remote_va", "Remote VA", base.HEX)
local f_write_len    = ProtoField.uint64("rdows.length", "Length", base.DEC)

-- READ_REQ
local f_read_len     = ProtoField.uint64("rdows.read_len", "Read Length", base.DEC)
local f_local_lkey   = ProtoField.uint32("rdows.local_lkey", "Local L_Key", base.HEX)
local f_local_va     = ProtoField.uint64("rdows.local_va", "Local VA", base.HEX)

-- READ_RESP
local f_frag_offset  = ProtoField.uint64("rdows.fragment_offset", "Fragment Offset", base.DEC)

-- ATOMIC_REQ
local f_atomic_type  = ProtoField.uint8("rdows.atomic_type", "Atomic Type", base.HEX)
local f_operand1     = ProtoField.uint64("rdows.operand1", "Operand 1", base.DEC)
local f_operand2     = ProtoField.uint64("rdows.operand2", "Operand 2", base.DEC)

-- ATOMIC_RESP
local f_orig_value   = ProtoField.uint64("rdows.original_value", "Original Value", base.DEC)

-- ERROR
local f_error_code   = ProtoField.uint16("rdows.error_code", "Error Code", base.HEX)
local f_failing_seq  = ProtoField.uint32("rdows.failing_seq", "Failing Sequence", base.DEC)
local f_desc_len     = ProtoField.uint16("rdows.desc_len", "Description Length", base.DEC)
local f_desc         = ProtoField.string("rdows.description", "Description")

-- CREDIT_UPDATE
local f_credit_inc   = ProtoField.uint32("rdows.credit_increment", "Credit Increment", base.DEC)

-- SG Entry
local f_sg_count     = ProtoField.uint16("rdows.sg_count", "SG Entry Count", base.DEC)
local f_sg_lkey      = ProtoField.uint32("rdows.sg.lkey", "SG L_Key", base.HEX)
local f_sg_offset    = ProtoField.uint64("rdows.sg.offset", "SG Offset", base.DEC)
local f_sg_length    = ProtoField.uint32("rdows.sg.length", "SG Length", base.DEC)

-- Data payload
local f_data         = ProtoField.bytes("rdows.data", "Data")
```

Register all fields with `rdows_proto.fields = { ... }`.

### Opcode name table

```lua
local opcode_names = {
    [0x01] = "CONNECT",
    [0x02] = "CONNECT_ACK",
    [0x03] = "DISCONNECT",
    [0x10] = "MR_REG",
    [0x11] = "MR_REG_ACK",
    [0x12] = "MR_DEREG",
    [0x13] = "MR_DEREG_ACK",
    [0x20] = "SEND",
    [0x21] = "SEND_DATA",
    [0x22] = "RECV_COMP",
    [0x30] = "WRITE",
    [0x31] = "WRITE_DATA",
    [0x32] = "WRITE_COMP",
    [0x40] = "READ_REQ",
    [0x41] = "READ_RESP",
    [0x50] = "ATOMIC_REQ",
    [0x51] = "ATOMIC_RESP",
    [0x60] = "ACK",
    [0x61] = "CREDIT_UPDATE",
    [0xF0] = "ERROR",
}
```

### Error code name table

```lua
local error_names = {
    [0x0000] = "SUCCESS",
    [0x0001] = "ERR_PROTO_VERSION",
    [0x0002] = "ERR_UNKNOWN_OPCODE",
    [0x0003] = "ERR_INVALID_PD",
    [0x0004] = "ERR_INVALID_LKEY",
    [0x0005] = "ERR_INVALID_MKEY",
    [0x0006] = "ERR_ACCESS_DENIED",
    [0x0007] = "ERR_BOUNDS",
    [0x0008] = "ERR_ALIGNMENT",
    [0x0009] = "ERR_PAYLOAD_SIZE",
    [0x0010] = "ERR_RNR",
    [0x0020] = "ERR_CQ_OVERFLOW",
    [0x0030] = "ERR_SEQ_GAP",
    [0x0040] = "ERR_TIMEOUT",
    [0xFFFF] = "ERR_INTERNAL",
}
```

### Atomic type name table

```lua
local atomic_type_names = {
    [0x01] = "Compare-and-Swap",
    [0x02] = "Fetch-and-Add",
}
```

### Access flags display

```lua
local function access_flags_str(flags)
    local parts = {}
    if bit.band(flags, 0x01) ~= 0 then table.insert(parts, "LOCAL_WRITE") end
    if bit.band(flags, 0x02) ~= 0 then table.insert(parts, "REMOTE_WRITE") end
    if bit.band(flags, 0x04) ~= 0 then table.insert(parts, "REMOTE_READ") end
    if bit.band(flags, 0x08) ~= 0 then table.insert(parts, "REMOTE_ATOMIC") end
    if #parts == 0 then return "NONE" end
    return table.concat(parts, " | ")
end
```

### Dissector function

The main `rdows_proto.dissector(buffer, pinfo, tree)` function should:

1. Check buffer length >= 24, otherwise return
2. Parse the 24-byte header
3. Set `pinfo.cols.protocol` to "RDoWS"
4. Set `pinfo.cols.info` to the opcode name + key details (e.g., "WRITE R_Key=0xCAFEBABE VA=0x0000 54 bytes" or "MR_REG_ACK L_Key=0x00000001 R_Key=0xABCD1234" or "CONNECT Session=0xDEADBEEF")
5. Add a subtree to the packet detail pane with all header fields
6. Parse the payload based on opcode, adding a payload subtree with opcode-specific fields
7. For SEND_DATA, WRITE_DATA, READ_RESP: show the data payload bytes
8. For WRITE, SEND: parse SG entries
9. For ERROR: show error code name and description string

### Registering on WebSocket

```lua
-- Register as a heuristic dissector on WebSocket binary payloads
local ws_dissector_table = DissectorTable.get("ws.protocol")
ws_dissector_table:add("rdows.v1", rdows_proto)
```

This hooks into WebSocket's subprotocol-based dissector routing. Since we negotiate "rdows.v1" as the subprotocol, Wireshark will route binary payloads to our dissector automatically.

If subprotocol-based routing doesn't work (it depends on Wireshark version), add a heuristic check as fallback: peek at byte 0 (version == 0x01) and byte 1 (valid opcode), and if both match, claim the payload.

```lua
-- Fallback heuristic dissector
local function rdows_heuristic(buffer, pinfo, tree)
    if buffer:len() < 24 then return false end
    local version = buffer(0, 1):uint()
    local opcode = buffer(1, 1):uint()
    if version ~= 0x01 then return false end
    if opcode_names[opcode] == nil then return false end
    rdows_proto.dissector(buffer, pinfo, tree)
    return true
end

rdows_proto:register_heuristic("ws", rdows_heuristic)
```

### Info column formatting

Make the info column useful at a glance. Examples of what it should show:

- `CONNECT Session=0xDEADBEEF MaxMsg=16777216`
- `CONNECT_ACK Session=0xDEADBEEF ICC=65535`
- `MR_REG PD=0x00000001 Len=4096 Flags=REMOTE_WRITE|REMOTE_READ`
- `MR_REG_ACK L_Key=0x00000001 R_Key=0xCAFEBABE`
- `WRITE R_Key=0xCAFEBABE VA=0x0000 54 bytes`
- `WRITE_DATA [54 bytes]`
- `WRITE_COMP WRID=100`
- `READ_REQ R_Key=0x12345678 VA=0x0000 Len=4096`
- `READ_RESP Offset=0 [128 bytes]`
- `SEND [1 SG entry, 13 bytes]`
- `SEND_DATA [13 bytes]`
- `RECV_COMP WRID=1`
- `ATOMIC_REQ CAS R_Key=0x00000001 VA=0x0000`
- `ATOMIC_RESP Original=100`
- `ERROR ERR_ACCESS_DENIED Seq=7 "description text"`
- `DISCONNECT Session=0xDEADBEEF`
- `ACK Seq=42`
- `CREDIT_UPDATE +128`

---

## File locations

- `crates/rdows-server/src/lib.rs` — SSLKEYLOGFILE on server TLS config
- `crates/rdows-server/src/main.rs` — may need minor change if config is built there
- `crates/rdows-client/src/main.rs` — SSLKEYLOGFILE on client TLS config  
- `crates/rdows-client/examples/*.rs` — add KeyLogFile to embedded server TLS configs
- `wireshark/rdows.lua` — new file, the dissector

## What NOT to do

- Don't add any CLI flags for SSLKEYLOGFILE — KeyLogFile::new() handles the env var automatically
- Don't add SSLKEYLOGFILE to integration tests — it's for manual capture only
- Don't modify any wire formats
- Don't try to decode the WebSocket framing in the Lua dissector — Wireshark already does that, the dissector only sees the binary payload inside the WebSocket frame

## Validation

For the Rust changes: `cargo test --workspace && cargo clippy --workspace`

For the dissector: manual testing. Document the steps in a `wireshark/README.md`:

1. Generate test certs: `cd crates/rdows-server && ./gen-certs.sh` (or use rcgen)
2. Start server: `SSLKEYLOGFILE=/tmp/rdows-keys.log cargo run -p rdows-server -- --cert server.crt --key server.key`
3. Start Wireshark capture on loopback, set TLS key log file to `/tmp/rdows-keys.log` in Preferences → Protocols → TLS
4. Run client: `SSLKEYLOGFILE=/tmp/rdows-keys.log cargo run -p rdows-client -- --cert server.crt`
5. See decrypted RDoWS frames in Wireshark with full protocol dissection

Include a note that `SSLKEYLOGFILE` must be set on BOTH client and server to see traffic in both directions.