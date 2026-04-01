use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::{ErrorCode, RdowsError};
use crate::frame::RdowsHeader;
use crate::memory::{AccessFlags, LKey, ProtectionDomain, RKey};
use crate::opcode::Opcode;
use crate::queue::ScatterGatherEntry;
use crate::HEADER_SIZE;

// ---------------------------------------------------------------------------
// CONNECT / CONNECT_ACK payload (16 bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectPayload {
    pub pd: ProtectionDomain,
    pub capability_flags: u32,
    pub max_msg_size: u32,
    pub icc: u32,
}

const CONNECT_PAYLOAD_SIZE: usize = 16;

impl ConnectPayload {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.pd.0);
        buf.put_u32(self.capability_flags);
        buf.put_u32(self.max_msg_size);
        buf.put_u32(self.icc);
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, RdowsError> {
        if buf.remaining() < CONNECT_PAYLOAD_SIZE {
            return Err(RdowsError::PayloadTooShort {
                expected: CONNECT_PAYLOAD_SIZE,
                got: buf.remaining(),
            });
        }
        Ok(Self {
            pd: ProtectionDomain(buf.get_u32()),
            capability_flags: buf.get_u32(),
            max_msg_size: buf.get_u32(),
            icc: buf.get_u32(),
        })
    }
}

// ---------------------------------------------------------------------------
// MR_REG payload (16 or 20 bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MrRegPayload {
    pub pd: ProtectionDomain,
    pub access_flags: AccessFlags,
    pub region_len: u64,
    pub suggested_lkey: Option<LKey>,
}

impl MrRegPayload {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.pd.0);
        buf.put_u32(self.access_flags.0);
        buf.put_u32((self.region_len >> 32) as u32);
        buf.put_u32(self.region_len as u32);
        if let Some(lkey) = self.suggested_lkey {
            buf.put_u32(lkey.0);
        }
    }

    pub fn decode(buf: &mut impl Buf, payload_length: u32) -> Result<Self, RdowsError> {
        if buf.remaining() < 16 {
            return Err(RdowsError::PayloadTooShort {
                expected: 16,
                got: buf.remaining(),
            });
        }
        let pd = ProtectionDomain(buf.get_u32());
        let access_flags = AccessFlags(buf.get_u32());
        let high = buf.get_u32() as u64;
        let low = buf.get_u32() as u64;
        let region_len = (high << 32) | low;

        let suggested_lkey = if payload_length >= 20 && buf.remaining() >= 4 {
            Some(LKey(buf.get_u32()))
        } else {
            None
        };

        Ok(Self {
            pd,
            access_flags,
            region_len,
            suggested_lkey,
        })
    }

    pub fn encoded_len(&self) -> usize {
        if self.suggested_lkey.is_some() {
            20
        } else {
            16
        }
    }
}

// ---------------------------------------------------------------------------
// MR_REG_ACK payload (16 bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MrRegAckPayload {
    pub pd: ProtectionDomain,
    pub lkey: LKey,
    pub rkey: RKey,
    pub status: u16,
}

const MR_REG_ACK_SIZE: usize = 16;

impl MrRegAckPayload {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.pd.0);
        buf.put_u32(self.lkey.0);
        buf.put_u32(self.rkey.0);
        buf.put_u16(self.status);
        buf.put_u16(0); // reserved
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, RdowsError> {
        if buf.remaining() < MR_REG_ACK_SIZE {
            return Err(RdowsError::PayloadTooShort {
                expected: MR_REG_ACK_SIZE,
                got: buf.remaining(),
            });
        }
        let pd = ProtectionDomain(buf.get_u32());
        let lkey = LKey(buf.get_u32());
        let rkey = RKey(buf.get_u32());
        let status = buf.get_u16();
        let _reserved = buf.get_u16();
        Ok(Self {
            pd,
            lkey,
            rkey,
            status,
        })
    }
}

// ---------------------------------------------------------------------------
// MR_DEREG payload (8 bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MrDeregPayload {
    pub pd: ProtectionDomain,
    pub lkey: LKey,
}

const MR_DEREG_SIZE: usize = 8;

impl MrDeregPayload {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.pd.0);
        buf.put_u32(self.lkey.0);
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, RdowsError> {
        if buf.remaining() < MR_DEREG_SIZE {
            return Err(RdowsError::PayloadTooShort {
                expected: MR_DEREG_SIZE,
                got: buf.remaining(),
            });
        }
        Ok(Self {
            pd: ProtectionDomain(buf.get_u32()),
            lkey: LKey(buf.get_u32()),
        })
    }
}

// ---------------------------------------------------------------------------
// MR_DEREG_ACK payload (8 bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MrDeregAckPayload {
    pub status: u16,
}

const MR_DEREG_ACK_SIZE: usize = 8;

impl MrDeregAckPayload {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.status);
        buf.put_bytes(0, 6); // reserved
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, RdowsError> {
        if buf.remaining() < MR_DEREG_ACK_SIZE {
            return Err(RdowsError::PayloadTooShort {
                expected: MR_DEREG_ACK_SIZE,
                got: buf.remaining(),
            });
        }
        let status = buf.get_u16();
        buf.advance(6); // reserved
        Ok(Self { status })
    }
}

// ---------------------------------------------------------------------------
// SEND payload (4 + 16*N bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendPayload {
    pub sg_list: Vec<ScatterGatherEntry>,
}

impl SendPayload {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.sg_list.len() as u16);
        buf.put_u16(0); // reserved
        for entry in &self.sg_list {
            entry.encode(buf);
        }
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, RdowsError> {
        if buf.remaining() < 4 {
            return Err(RdowsError::PayloadTooShort {
                expected: 4,
                got: buf.remaining(),
            });
        }
        let count = buf.get_u16() as usize;
        let _reserved = buf.get_u16();

        let needed = count * crate::queue::SG_ENTRY_SIZE;
        if buf.remaining() < needed {
            return Err(RdowsError::PayloadTooShort {
                expected: 4 + needed,
                got: 4 + buf.remaining(),
            });
        }

        let mut sg_list = Vec::with_capacity(count);
        for _ in 0..count {
            sg_list.push(ScatterGatherEntry::decode(buf)?);
        }
        Ok(Self { sg_list })
    }

    pub fn encoded_len(&self) -> usize {
        4 + self.sg_list.len() * crate::queue::SG_ENTRY_SIZE
    }
}

// ---------------------------------------------------------------------------
// WRITE payload (24 + 16*N bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WritePayload {
    pub rkey: RKey,
    pub remote_va: u64,
    pub length: u64,
    pub sg_list: Vec<ScatterGatherEntry>,
}

const WRITE_HEADER_SIZE: usize = 24;

impl WritePayload {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.rkey.0);
        buf.put_u32(0); // reserved
        buf.put_u64(self.remote_va);
        buf.put_u64(self.length);
        for entry in &self.sg_list {
            entry.encode(buf);
        }
    }

    pub fn decode(buf: &mut impl Buf, payload_length: u32) -> Result<Self, RdowsError> {
        if buf.remaining() < WRITE_HEADER_SIZE {
            return Err(RdowsError::PayloadTooShort {
                expected: WRITE_HEADER_SIZE,
                got: buf.remaining(),
            });
        }
        let rkey = RKey(buf.get_u32());
        let _reserved = buf.get_u32();
        let remote_va = buf.get_u64();
        let length = buf.get_u64();

        let sg_bytes = payload_length as usize - WRITE_HEADER_SIZE;
        let count = sg_bytes / crate::queue::SG_ENTRY_SIZE;

        let mut sg_list = Vec::with_capacity(count);
        for _ in 0..count {
            sg_list.push(ScatterGatherEntry::decode(buf)?);
        }
        Ok(Self {
            rkey,
            remote_va,
            length,
            sg_list,
        })
    }

    pub fn encoded_len(&self) -> usize {
        WRITE_HEADER_SIZE + self.sg_list.len() * crate::queue::SG_ENTRY_SIZE
    }
}

// ---------------------------------------------------------------------------
// READ_REQ payload (40 bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadReqPayload {
    pub rkey: RKey,
    pub remote_va: u64,
    pub read_len: u64,
    pub local_lkey: LKey,
    pub local_va: u64,
}

const READ_REQ_SIZE: usize = 40;

impl ReadReqPayload {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.rkey.0);
        buf.put_u32(0); // reserved
        buf.put_u64(self.remote_va);
        buf.put_u64(self.read_len);
        buf.put_u32(self.local_lkey.0);
        buf.put_u32(0); // reserved
        buf.put_u64(self.local_va);
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, RdowsError> {
        if buf.remaining() < READ_REQ_SIZE {
            return Err(RdowsError::PayloadTooShort {
                expected: READ_REQ_SIZE,
                got: buf.remaining(),
            });
        }
        let rkey = RKey(buf.get_u32());
        let _reserved = buf.get_u32();
        let remote_va = buf.get_u64();
        let read_len = buf.get_u64();
        let local_lkey = LKey(buf.get_u32());
        let _reserved2 = buf.get_u32();
        let local_va = buf.get_u64();
        Ok(Self {
            rkey,
            remote_va,
            read_len,
            local_lkey,
            local_va,
        })
    }
}

// ---------------------------------------------------------------------------
// READ_RESP payload (8 + variable)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRespPayload {
    pub fragment_offset: u64,
    pub data: Bytes,
}

impl ReadRespPayload {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u64(self.fragment_offset);
        buf.put_slice(&self.data);
    }

    pub fn decode(buf: &mut impl Buf, payload_length: u32) -> Result<Self, RdowsError> {
        if buf.remaining() < 8 {
            return Err(RdowsError::PayloadTooShort {
                expected: 8,
                got: buf.remaining(),
            });
        }
        let fragment_offset = buf.get_u64();
        let data_len = payload_length as usize - 8;
        if buf.remaining() < data_len {
            return Err(RdowsError::PayloadTooShort {
                expected: payload_length as usize,
                got: 8 + buf.remaining(),
            });
        }
        let data = buf.copy_to_bytes(data_len);
        Ok(Self {
            fragment_offset,
            data,
        })
    }

    pub fn encoded_len(&self) -> usize {
        8 + self.data.len()
    }
}

// ---------------------------------------------------------------------------
// ERROR payload (10 + variable)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorPayload {
    pub error_code: ErrorCode,
    pub failing_seq: u32,
    pub description: String,
}

const ERROR_FIXED_SIZE: usize = 10;

impl ErrorPayload {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.error_code.into());
        buf.put_u16(0); // reserved
        buf.put_u32(self.failing_seq);
        let desc_bytes = self.description.as_bytes();
        buf.put_u16(desc_bytes.len() as u16);
        buf.put_slice(desc_bytes);
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, RdowsError> {
        if buf.remaining() < ERROR_FIXED_SIZE {
            return Err(RdowsError::PayloadTooShort {
                expected: ERROR_FIXED_SIZE,
                got: buf.remaining(),
            });
        }
        let code_val = buf.get_u16();
        let error_code = ErrorCode::try_from(code_val)
            .unwrap_or(ErrorCode::ErrInternal);
        let _reserved = buf.get_u16();
        let failing_seq = buf.get_u32();
        let desc_len = buf.get_u16() as usize;

        let description = if desc_len > 0 && buf.remaining() >= desc_len {
            let desc_bytes = buf.copy_to_bytes(desc_len);
            String::from_utf8_lossy(&desc_bytes).into_owned()
        } else {
            String::new()
        };

        Ok(Self {
            error_code,
            failing_seq,
            description,
        })
    }

    pub fn encoded_len(&self) -> usize {
        ERROR_FIXED_SIZE + self.description.len()
    }
}

// ---------------------------------------------------------------------------
// CREDIT_UPDATE payload (8 bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditUpdatePayload {
    pub credit_increment: u32,
}

const CREDIT_UPDATE_SIZE: usize = 8;

impl CreditUpdatePayload {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.credit_increment);
        buf.put_u32(0); // reserved
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, RdowsError> {
        if buf.remaining() < CREDIT_UPDATE_SIZE {
            return Err(RdowsError::PayloadTooShort {
                expected: CREDIT_UPDATE_SIZE,
                got: buf.remaining(),
            });
        }
        let credit_increment = buf.get_u32();
        let _reserved = buf.get_u32();
        Ok(Self { credit_increment })
    }
}

// ---------------------------------------------------------------------------
// ATOMIC_REQ payload (32 bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicReqPayload {
    pub rkey: RKey,
    pub atomic_type: u8,
    pub remote_va: u64,
    pub operand1: u64,
    pub operand2: u64,
}

pub const ATOMIC_TYPE_CAS: u8 = 0x01;
pub const ATOMIC_TYPE_FAA: u8 = 0x02;

const ATOMIC_REQ_SIZE: usize = 32;

impl AtomicReqPayload {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.rkey.0);
        buf.put_u8(self.atomic_type);
        buf.put_bytes(0, 3); // reserved
        buf.put_u64(self.remote_va);
        buf.put_u64(self.operand1);
        buf.put_u64(self.operand2);
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, RdowsError> {
        if buf.remaining() < ATOMIC_REQ_SIZE {
            return Err(RdowsError::PayloadTooShort {
                expected: ATOMIC_REQ_SIZE,
                got: buf.remaining(),
            });
        }
        let rkey = RKey(buf.get_u32());
        let atomic_type = buf.get_u8();
        buf.advance(3); // reserved
        let remote_va = buf.get_u64();
        let operand1 = buf.get_u64();
        let operand2 = buf.get_u64();
        Ok(Self {
            rkey,
            atomic_type,
            remote_va,
            operand1,
            operand2,
        })
    }
}

// ---------------------------------------------------------------------------
// ATOMIC_RESP payload (16 bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicRespPayload {
    pub original_value: u64,
    pub status: u16,
}

const ATOMIC_RESP_SIZE: usize = 16;

impl AtomicRespPayload {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u64(self.original_value);
        buf.put_u16(self.status);
        buf.put_bytes(0, 6); // reserved
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, RdowsError> {
        if buf.remaining() < ATOMIC_RESP_SIZE {
            return Err(RdowsError::PayloadTooShort {
                expected: ATOMIC_RESP_SIZE,
                got: buf.remaining(),
            });
        }
        let original_value = buf.get_u64();
        let status = buf.get_u16();
        buf.advance(6); // reserved
        Ok(Self {
            original_value,
            status,
        })
    }
}

// ---------------------------------------------------------------------------
// SEND_DATA / WRITE_DATA payload (raw bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPayload {
    pub data: Bytes,
}

impl DataPayload {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(&self.data);
    }

    pub fn decode(buf: &mut impl Buf, payload_length: u32) -> Result<Self, RdowsError> {
        let len = payload_length as usize;
        if buf.remaining() < len {
            return Err(RdowsError::PayloadTooShort {
                expected: len,
                got: buf.remaining(),
            });
        }
        Ok(Self {
            data: buf.copy_to_bytes(len),
        })
    }
}

// ===========================================================================
// RdowsMessage — unified message enum
// ===========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdowsMessage {
    Connect(RdowsHeader, ConnectPayload),
    ConnectAck(RdowsHeader, ConnectPayload),
    Disconnect(RdowsHeader),
    MrReg(RdowsHeader, MrRegPayload),
    MrRegAck(RdowsHeader, MrRegAckPayload),
    MrDereg(RdowsHeader, MrDeregPayload),
    MrDeregAck(RdowsHeader, MrDeregAckPayload),
    Send(RdowsHeader, SendPayload),
    SendData(RdowsHeader, DataPayload),
    RecvComp(RdowsHeader),
    Write(RdowsHeader, WritePayload),
    WriteData(RdowsHeader, DataPayload),
    WriteComp(RdowsHeader),
    ReadReq(RdowsHeader, ReadReqPayload),
    ReadResp(RdowsHeader, ReadRespPayload),
    AtomicReq(RdowsHeader, AtomicReqPayload),
    AtomicResp(RdowsHeader, AtomicRespPayload),
    Ack(RdowsHeader),
    CreditUpdate(RdowsHeader, CreditUpdatePayload),
    Error(RdowsHeader, ErrorPayload),
}

impl RdowsMessage {
    pub fn header(&self) -> &RdowsHeader {
        match self {
            Self::Connect(h, _) => h,
            Self::ConnectAck(h, _) => h,
            Self::Disconnect(h) => h,
            Self::MrReg(h, _) => h,
            Self::MrRegAck(h, _) => h,
            Self::MrDereg(h, _) => h,
            Self::MrDeregAck(h, _) => h,
            Self::Send(h, _) => h,
            Self::SendData(h, _) => h,
            Self::RecvComp(h) => h,
            Self::Write(h, _) => h,
            Self::WriteData(h, _) => h,
            Self::WriteComp(h) => h,
            Self::ReadReq(h, _) => h,
            Self::ReadResp(h, _) => h,
            Self::AtomicReq(h, _) => h,
            Self::AtomicResp(h, _) => h,
            Self::Ack(h) => h,
            Self::CreditUpdate(h, _) => h,
            Self::Error(h, _) => h,
        }
    }

    pub fn encode(&self) -> BytesMut {
        let mut payload_buf = BytesMut::new();

        match self {
            Self::Connect(_, p) | Self::ConnectAck(_, p) => p.encode(&mut payload_buf),
            Self::Disconnect(_) | Self::RecvComp(_) | Self::WriteComp(_) | Self::Ack(_) => {}
            Self::MrReg(_, p) => p.encode(&mut payload_buf),
            Self::MrRegAck(_, p) => p.encode(&mut payload_buf),
            Self::MrDereg(_, p) => p.encode(&mut payload_buf),
            Self::MrDeregAck(_, p) => p.encode(&mut payload_buf),
            Self::Send(_, p) => p.encode(&mut payload_buf),
            Self::SendData(_, p) | Self::WriteData(_, p) => p.encode(&mut payload_buf),
            Self::Write(_, p) => p.encode(&mut payload_buf),
            Self::ReadReq(_, p) => p.encode(&mut payload_buf),
            Self::ReadResp(_, p) => p.encode(&mut payload_buf),
            Self::AtomicReq(_, p) => p.encode(&mut payload_buf),
            Self::AtomicResp(_, p) => p.encode(&mut payload_buf),
            Self::CreditUpdate(_, p) => p.encode(&mut payload_buf),
            Self::Error(_, p) => p.encode(&mut payload_buf),
        }

        let mut header = self.header().clone();
        header.payload_length = payload_buf.len() as u32;

        let mut out = BytesMut::with_capacity(HEADER_SIZE + payload_buf.len());
        header.encode(&mut out);
        out.extend_from_slice(&payload_buf);
        out
    }

    pub fn decode(data: Bytes) -> Result<Self, RdowsError> {
        let mut buf = data;
        let header = RdowsHeader::decode(&mut buf)?;
        let pl = header.payload_length;

        match header.opcode {
            Opcode::Connect => {
                let p = ConnectPayload::decode(&mut buf)?;
                Ok(Self::Connect(header, p))
            }
            Opcode::ConnectAck => {
                let p = ConnectPayload::decode(&mut buf)?;
                Ok(Self::ConnectAck(header, p))
            }
            Opcode::Disconnect => Ok(Self::Disconnect(header)),
            Opcode::MrReg => {
                let p = MrRegPayload::decode(&mut buf, pl)?;
                Ok(Self::MrReg(header, p))
            }
            Opcode::MrRegAck => {
                let p = MrRegAckPayload::decode(&mut buf)?;
                Ok(Self::MrRegAck(header, p))
            }
            Opcode::MrDereg => {
                let p = MrDeregPayload::decode(&mut buf)?;
                Ok(Self::MrDereg(header, p))
            }
            Opcode::MrDeregAck => {
                let p = MrDeregAckPayload::decode(&mut buf)?;
                Ok(Self::MrDeregAck(header, p))
            }
            Opcode::Send => {
                let p = SendPayload::decode(&mut buf)?;
                Ok(Self::Send(header, p))
            }
            Opcode::SendData => {
                let p = DataPayload::decode(&mut buf, pl)?;
                Ok(Self::SendData(header, p))
            }
            Opcode::RecvComp => Ok(Self::RecvComp(header)),
            Opcode::Write => {
                let p = WritePayload::decode(&mut buf, pl)?;
                Ok(Self::Write(header, p))
            }
            Opcode::WriteData => {
                let p = DataPayload::decode(&mut buf, pl)?;
                Ok(Self::WriteData(header, p))
            }
            Opcode::WriteComp => Ok(Self::WriteComp(header)),
            Opcode::ReadReq => {
                let p = ReadReqPayload::decode(&mut buf)?;
                Ok(Self::ReadReq(header, p))
            }
            Opcode::ReadResp => {
                let p = ReadRespPayload::decode(&mut buf, pl)?;
                Ok(Self::ReadResp(header, p))
            }
            Opcode::AtomicReq => {
                let p = AtomicReqPayload::decode(&mut buf)?;
                Ok(Self::AtomicReq(header, p))
            }
            Opcode::AtomicResp => {
                let p = AtomicRespPayload::decode(&mut buf)?;
                Ok(Self::AtomicResp(header, p))
            }
            Opcode::Ack => Ok(Self::Ack(header)),
            Opcode::CreditUpdate => {
                let p = CreditUpdatePayload::decode(&mut buf)?;
                Ok(Self::CreditUpdate(header, p))
            }
            Opcode::Error => {
                let p = ErrorPayload::decode(&mut buf)?;
                Ok(Self::Error(header, p))
            }
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(msg: RdowsMessage) {
        let encoded = msg.encode();
        let decoded = RdowsMessage::decode(encoded.freeze()).unwrap();
        // The decoded header will have the correct payload_length filled in
        // by encode(), while the original has 0. Compare the re-encoded forms.
        let re_encoded = decoded.encode();
        let encoded2 = msg.encode();
        assert_eq!(re_encoded, encoded2);
        // Also verify payload equality by re-decoding
        let decoded2 = RdowsMessage::decode(encoded2.freeze()).unwrap();
        assert_eq!(decoded, decoded2);
    }

    fn make_header(opcode: Opcode) -> RdowsHeader {
        RdowsHeader::new(opcode, 0xABCD, 1, 42)
    }

    #[test]
    fn connect_round_trip() {
        round_trip(RdowsMessage::Connect(
            make_header(Opcode::Connect),
            ConnectPayload {
                pd: ProtectionDomain(1),
                capability_flags: 0,
                max_msg_size: 16 * 1024 * 1024,
                icc: 65535,
            },
        ));
    }

    #[test]
    fn connect_ack_round_trip() {
        round_trip(RdowsMessage::ConnectAck(
            make_header(Opcode::ConnectAck),
            ConnectPayload {
                pd: ProtectionDomain(2),
                capability_flags: 0xFF,
                max_msg_size: 1024,
                icc: 128,
            },
        ));
    }

    #[test]
    fn disconnect_round_trip() {
        round_trip(RdowsMessage::Disconnect(make_header(Opcode::Disconnect)));
    }

    #[test]
    fn mr_reg_without_suggested_lkey() {
        round_trip(RdowsMessage::MrReg(
            make_header(Opcode::MrReg),
            MrRegPayload {
                pd: ProtectionDomain(1),
                access_flags: AccessFlags::REMOTE_WRITE | AccessFlags::REMOTE_READ,
                region_len: 4096,
                suggested_lkey: None,
            },
        ));
    }

    #[test]
    fn mr_reg_with_suggested_lkey() {
        round_trip(RdowsMessage::MrReg(
            make_header(Opcode::MrReg),
            MrRegPayload {
                pd: ProtectionDomain(1),
                access_flags: AccessFlags::LOCAL_WRITE,
                region_len: 0x1_0000_0000, // >4GiB
                suggested_lkey: Some(LKey(99)),
            },
        ));
    }

    #[test]
    fn mr_reg_ack_round_trip() {
        round_trip(RdowsMessage::MrRegAck(
            make_header(Opcode::MrRegAck),
            MrRegAckPayload {
                pd: ProtectionDomain(1),
                lkey: LKey(10),
                rkey: RKey(0xDEADBEEF),
                status: 0,
            },
        ));
    }

    #[test]
    fn mr_dereg_round_trip() {
        round_trip(RdowsMessage::MrDereg(
            make_header(Opcode::MrDereg),
            MrDeregPayload {
                pd: ProtectionDomain(1),
                lkey: LKey(10),
            },
        ));
    }

    #[test]
    fn mr_dereg_ack_round_trip() {
        round_trip(RdowsMessage::MrDeregAck(
            make_header(Opcode::MrDeregAck),
            MrDeregAckPayload { status: 0 },
        ));
    }

    #[test]
    fn send_empty_sg() {
        round_trip(RdowsMessage::Send(
            make_header(Opcode::Send),
            SendPayload {
                sg_list: vec![],
            },
        ));
    }

    #[test]
    fn send_multiple_sg() {
        round_trip(RdowsMessage::Send(
            make_header(Opcode::Send),
            SendPayload {
                sg_list: vec![
                    ScatterGatherEntry {
                        lkey: LKey(1),
                        offset: 0,
                        length: 100,
                    },
                    ScatterGatherEntry {
                        lkey: LKey(2),
                        offset: 256,
                        length: 200,
                    },
                    ScatterGatherEntry {
                        lkey: LKey(3),
                        offset: 0,
                        length: 50,
                    },
                ],
            },
        ));
    }

    #[test]
    fn send_data_round_trip() {
        round_trip(RdowsMessage::SendData(
            make_header(Opcode::SendData),
            DataPayload {
                data: Bytes::from_static(b"Hello, RDoWS!"),
            },
        ));
    }

    #[test]
    fn recv_comp_round_trip() {
        round_trip(RdowsMessage::RecvComp(make_header(Opcode::RecvComp)));
    }

    #[test]
    fn write_round_trip() {
        round_trip(RdowsMessage::Write(
            make_header(Opcode::Write),
            WritePayload {
                rkey: RKey(0xCAFEBABE),
                remote_va: 1024,
                length: 100,
                sg_list: vec![ScatterGatherEntry {
                    lkey: LKey(1),
                    offset: 0,
                    length: 100,
                }],
            },
        ));
    }

    #[test]
    fn write_data_round_trip() {
        round_trip(RdowsMessage::WriteData(
            make_header(Opcode::WriteData),
            DataPayload {
                data: Bytes::from(vec![0xAB; 256]),
            },
        ));
    }

    #[test]
    fn write_comp_round_trip() {
        round_trip(RdowsMessage::WriteComp(make_header(Opcode::WriteComp)));
    }

    #[test]
    fn read_req_round_trip() {
        round_trip(RdowsMessage::ReadReq(
            make_header(Opcode::ReadReq),
            ReadReqPayload {
                rkey: RKey(0x12345678),
                remote_va: 0,
                read_len: 4096,
                local_lkey: LKey(5),
                local_va: 0,
            },
        ));
    }

    #[test]
    fn read_resp_round_trip() {
        round_trip(RdowsMessage::ReadResp(
            make_header(Opcode::ReadResp),
            ReadRespPayload {
                fragment_offset: 0,
                data: Bytes::from(vec![42u8; 128]),
            },
        ));
    }

    #[test]
    fn atomic_req_round_trip() {
        round_trip(RdowsMessage::AtomicReq(
            make_header(Opcode::AtomicReq),
            AtomicReqPayload {
                rkey: RKey(1),
                atomic_type: ATOMIC_TYPE_CAS,
                remote_va: 0,
                operand1: 100,
                operand2: 200,
            },
        ));
    }

    #[test]
    fn atomic_resp_round_trip() {
        round_trip(RdowsMessage::AtomicResp(
            make_header(Opcode::AtomicResp),
            AtomicRespPayload {
                original_value: 100,
                status: 0,
            },
        ));
    }

    #[test]
    fn ack_round_trip() {
        round_trip(RdowsMessage::Ack(make_header(Opcode::Ack)));
    }

    #[test]
    fn credit_update_round_trip() {
        round_trip(RdowsMessage::CreditUpdate(
            make_header(Opcode::CreditUpdate),
            CreditUpdatePayload {
                credit_increment: 128,
            },
        ));
    }

    #[test]
    fn error_with_description() {
        round_trip(RdowsMessage::Error(
            make_header(Opcode::Error),
            ErrorPayload {
                error_code: ErrorCode::ErrInvalidMkey,
                failing_seq: 7,
                description: "R_Key 0xDEADBEEF not found".to_string(),
            },
        ));
    }

    #[test]
    fn error_without_description() {
        round_trip(RdowsMessage::Error(
            make_header(Opcode::Error),
            ErrorPayload {
                error_code: ErrorCode::ErrRnr,
                failing_seq: 0,
                description: String::new(),
            },
        ));
    }
}
