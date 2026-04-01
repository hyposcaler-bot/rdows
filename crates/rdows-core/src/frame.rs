use bytes::{Buf, BufMut, BytesMut};

use crate::error::RdowsError;
use crate::opcode::Opcode;
use crate::{HEADER_SIZE, RDOWS_VERSION};

/// Flag bit: Fragment (bit 15).
pub const FLAG_F: u16 = 0x8000;
/// Flag bit: Last fragment (bit 14). Valid only when FLAG_F is set.
pub const FLAG_L: u16 = 0x4000;
/// Flag bit: Solicited event (bit 13).
pub const FLAG_S: u16 = 0x2000;

/// The fixed 24-byte RDoWS frame header per RFC Section 5.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdowsHeader {
    pub version: u8,
    pub opcode: Opcode,
    pub flags: u16,
    pub session_id: u32,
    pub sequence: u32,
    pub wrid: u64,
    pub payload_length: u32,
}

impl RdowsHeader {
    pub fn new(opcode: Opcode, session_id: u32, sequence: u32, wrid: u64) -> Self {
        Self {
            version: RDOWS_VERSION,
            opcode,
            flags: 0,
            session_id,
            sequence,
            wrid,
            payload_length: 0,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.version);
        buf.put_u8(self.opcode.into());
        buf.put_u16(self.flags);
        buf.put_u32(self.session_id);
        buf.put_u32(self.sequence);
        buf.put_u64(self.wrid);
        buf.put_u32(self.payload_length);
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, RdowsError> {
        if buf.remaining() < HEADER_SIZE {
            return Err(RdowsError::HeaderTooShort(buf.remaining()));
        }

        let version = buf.get_u8();
        if version != RDOWS_VERSION {
            return Err(RdowsError::InvalidVersion(version));
        }

        let opcode_byte = buf.get_u8();
        let opcode =
            Opcode::try_from(opcode_byte).map_err(|_| RdowsError::InvalidOpcode(opcode_byte))?;

        let flags = buf.get_u16();
        let session_id = buf.get_u32();
        let sequence = buf.get_u32();
        let wrid = buf.get_u64();
        let payload_length = buf.get_u32();

        Ok(Self {
            version,
            opcode,
            flags,
            session_id,
            sequence,
            wrid,
            payload_length,
        })
    }

    pub fn is_fragment(&self) -> bool {
        self.flags & FLAG_F != 0
    }

    pub fn is_last_fragment(&self) -> bool {
        self.flags & FLAG_L != 0
    }

    pub fn is_solicited(&self) -> bool {
        self.flags & FLAG_S != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let header = RdowsHeader {
            version: RDOWS_VERSION,
            opcode: Opcode::Write,
            flags: FLAG_F | FLAG_S,
            session_id: 0xDEADBEEF,
            sequence: 42,
            wrid: 0x0123456789ABCDEF,
            payload_length: 1024,
        };

        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        assert_eq!(buf.len(), HEADER_SIZE);

        let decoded = RdowsHeader::decode(&mut buf.freeze()).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn boundary_values() {
        let header = RdowsHeader {
            version: RDOWS_VERSION,
            opcode: Opcode::Ack,
            flags: 0xFFFF,
            session_id: u32::MAX,
            sequence: u32::MAX,
            wrid: u64::MAX,
            payload_length: u32::MAX,
        };

        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        let decoded = RdowsHeader::decode(&mut buf.freeze()).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn invalid_version() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x02); // wrong version
        buf.put_u8(0x01); // opcode
        buf.put_bytes(0, 22); // rest of header

        let err = RdowsHeader::decode(&mut buf.freeze()).unwrap_err();
        assert!(matches!(err, RdowsError::InvalidVersion(0x02)));
    }

    #[test]
    fn invalid_opcode() {
        let mut buf = BytesMut::new();
        buf.put_u8(RDOWS_VERSION);
        buf.put_u8(0xFF); // invalid opcode
        buf.put_bytes(0, 22);

        let err = RdowsHeader::decode(&mut buf.freeze()).unwrap_err();
        assert!(matches!(err, RdowsError::InvalidOpcode(0xFF)));
    }

    #[test]
    fn too_short() {
        let buf = bytes::Bytes::from_static(&[0x01, 0x02, 0x03]);
        let err = RdowsHeader::decode(&mut buf.clone()).unwrap_err();
        assert!(matches!(err, RdowsError::HeaderTooShort(3)));
    }

    #[test]
    fn flag_helpers() {
        let mut h = RdowsHeader::new(Opcode::Send, 1, 0, 0);
        assert!(!h.is_fragment());
        assert!(!h.is_last_fragment());
        assert!(!h.is_solicited());

        h.flags = FLAG_F;
        assert!(h.is_fragment());
        assert!(!h.is_last_fragment());

        h.flags = FLAG_F | FLAG_L;
        assert!(h.is_fragment());
        assert!(h.is_last_fragment());

        h.flags = FLAG_S;
        assert!(h.is_solicited());
    }
}
