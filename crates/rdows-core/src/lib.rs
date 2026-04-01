pub mod error;
pub mod frame;
pub mod memory;
pub mod message;
pub mod opcode;
pub mod queue;

/// Protocol version. MUST be 0x01 per RFC Section 5.1.
pub const RDOWS_VERSION: u8 = 0x01;

/// WebSocket subprotocol identifier per RFC Section 4.
pub const SUBPROTOCOL: &str = "rdows.v1";

/// Fixed frame header size in bytes per RFC Section 5.1.
pub const HEADER_SIZE: usize = 24;

/// Default maximum message size (16 MiB).
pub const DEFAULT_MAX_MSG_SIZE: u32 = 16 * 1024 * 1024;

/// Default Initial Credit Count (effectively unlimited for MVP).
pub const DEFAULT_ICC: u32 = 65535;
