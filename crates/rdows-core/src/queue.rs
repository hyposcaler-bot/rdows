use bytes::{Buf, BufMut, BytesMut};

use crate::error::RdowsError;
use crate::memory::LKey;
use crate::opcode::Opcode;

/// Scatter/Gather Entry per RFC Section 7.1 (16 bytes on wire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScatterGatherEntry {
    pub lkey: LKey,
    pub offset: u64,
    pub length: u32,
}

/// Wire size of a single SG entry.
pub const SG_ENTRY_SIZE: usize = 16;

impl ScatterGatherEntry {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.lkey.0);
        buf.put_u64(self.offset);
        buf.put_u32(self.length);
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, RdowsError> {
        if buf.remaining() < SG_ENTRY_SIZE {
            return Err(RdowsError::PayloadTooShort {
                expected: SG_ENTRY_SIZE,
                got: buf.remaining(),
            });
        }
        Ok(Self {
            lkey: LKey(buf.get_u32()),
            offset: buf.get_u64(),
            length: buf.get_u32(),
        })
    }
}

/// Work Request Identifier — opaque 64-bit value from the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkRequestId(pub u64);

/// Completion Queue Entry per RFC Section 8 (24 bytes on wire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionQueueEntry {
    pub wrid: WorkRequestId,
    pub status: u16,
    pub opcode: Opcode,
    pub vendor_error: u8,
    pub byte_count: u32,
    pub qp_number: u32,
}

pub const CQE_SIZE: usize = 24;

impl CompletionQueueEntry {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u64(self.wrid.0);
        buf.put_u16(self.status);
        buf.put_u8(self.opcode.into());
        buf.put_u8(self.vendor_error);
        buf.put_u32(self.byte_count);
        buf.put_u32(self.qp_number);
        buf.put_u32(0); // reserved
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, RdowsError> {
        if buf.remaining() < CQE_SIZE {
            return Err(RdowsError::PayloadTooShort {
                expected: CQE_SIZE,
                got: buf.remaining(),
            });
        }
        let wrid = WorkRequestId(buf.get_u64());
        let status = buf.get_u16();
        let opcode_byte = buf.get_u8();
        let opcode =
            Opcode::try_from(opcode_byte).map_err(|_| RdowsError::InvalidOpcode(opcode_byte))?;
        let vendor_error = buf.get_u8();
        let byte_count = buf.get_u32();
        let qp_number = buf.get_u32();
        let _reserved = buf.get_u32();
        Ok(Self {
            wrid,
            status,
            opcode,
            vendor_error,
            byte_count,
            qp_number,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sg_entry_round_trip() {
        let entry = ScatterGatherEntry {
            lkey: LKey(0x12345678),
            offset: 0xDEADBEEFCAFEBABE,
            length: 4096,
        };

        let mut buf = BytesMut::new();
        entry.encode(&mut buf);
        assert_eq!(buf.len(), SG_ENTRY_SIZE);

        let decoded = ScatterGatherEntry::decode(&mut buf.freeze()).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn cqe_round_trip() {
        let cqe = CompletionQueueEntry {
            wrid: WorkRequestId(42),
            status: 0,
            opcode: Opcode::Write,
            vendor_error: 0,
            byte_count: 8192,
            qp_number: 0xDEADBEEF,
        };

        let mut buf = BytesMut::new();
        cqe.encode(&mut buf);
        assert_eq!(buf.len(), CQE_SIZE);

        let decoded = CompletionQueueEntry::decode(&mut buf.freeze()).unwrap();
        assert_eq!(decoded, cqe);
    }

    #[test]
    fn cqe_with_error() {
        let cqe = CompletionQueueEntry {
            wrid: WorkRequestId(99),
            status: 0x0005, // ERR_INVALID_MKEY
            opcode: Opcode::ReadReq,
            vendor_error: 0x42,
            byte_count: 0,
            qp_number: 1,
        };

        let mut buf = BytesMut::new();
        cqe.encode(&mut buf);
        let decoded = CompletionQueueEntry::decode(&mut buf.freeze()).unwrap();
        assert_eq!(decoded, cqe);
    }
}
