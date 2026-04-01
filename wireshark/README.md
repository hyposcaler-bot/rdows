# RDoWS Wireshark Dissector

Lua dissector for inspecting RDoWS (RDMA over WebSockets) traffic in Wireshark with full TLS decryption and protocol-aware dissection.

## Setup

### 1. Install the dissector

Copy `rdows.lua` to your Wireshark plugins directory, or load it via **Edit > Preferences > Protocols > Lua > Lua script**.

Common plugin directories:
- Linux: `~/.local/lib/wireshark/plugins/`
- macOS: `~/.local/lib/wireshark/plugins/`
- Windows: `%APPDATA%\Wireshark\plugins\`

### 2. Generate test certificates

```bash
cd crates/rdows-server && ./gen-certs.sh
```

Or use the examples which generate ephemeral certs via `rcgen`.

### 3. Capture with TLS key logging

Set `SSLKEYLOGFILE` on **both** client and server to see traffic in both directions:

```bash
# Terminal 1 — server
SSLKEYLOGFILE=/tmp/rdows-keys.log cargo run -p rdows-server -- --cert server.crt --key server.key

# Terminal 2 — client
SSLKEYLOGFILE=/tmp/rdows-keys.log cargo run -p rdows-client -- --cert server.crt
```

### 4. Configure Wireshark TLS decryption

1. Start a capture on the loopback interface
2. Go to **Edit > Preferences > Protocols > TLS**
3. Set **(Pre)-Master-Secret log filename** to `/tmp/rdows-keys.log`
4. Apply

Wireshark will decrypt TLS traffic using the session keys and the RDoWS dissector will parse the WebSocket binary payloads automatically.

## How it works

The dissector registers on the `ws.protocol` dissector table keyed on the `rdows.v1` WebSocket subprotocol. It also registers a heuristic fallback that checks for version `0x01` and a valid opcode byte.

Each packet is displayed with:
- **Protocol column**: `RDoWS`
- **Info column**: Opcode name with key fields (e.g., `WRITE R_Key=0xCAFEBABE VA=0x0000 54 bytes`)
- **Packet detail pane**: Full 24-byte header breakdown and opcode-specific payload fields
