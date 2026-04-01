/// RDoWS opcode definitions per RFC Section 5.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Opcode {
    Connect = 0x01,
    ConnectAck = 0x02,
    Disconnect = 0x03,
    MrReg = 0x10,
    MrRegAck = 0x11,
    MrDereg = 0x12,
    MrDeregAck = 0x13,
    Send = 0x20,
    SendData = 0x21,
    RecvComp = 0x22,
    Write = 0x30,
    WriteData = 0x31,
    WriteComp = 0x32,
    ReadReq = 0x40,
    ReadResp = 0x41,
    AtomicReq = 0x50,
    AtomicResp = 0x51,
    Ack = 0x60,
    CreditUpdate = 0x61,
    Error = 0xF0,
}

impl Opcode {
    /// Returns true if this opcode is a protocol-level message (WRID should be zero).
    pub fn is_protocol_message(self) -> bool {
        matches!(
            self,
            Opcode::Connect
                | Opcode::ConnectAck
                | Opcode::Ack
                | Opcode::Error
                | Opcode::CreditUpdate
        )
    }
}

impl From<Opcode> for u8 {
    fn from(op: Opcode) -> u8 {
        op as u8
    }
}

impl TryFrom<u8> for Opcode {
    type Error = InvalidOpcode;

    fn try_from(value: u8) -> Result<Self, InvalidOpcode> {
        match value {
            0x01 => Ok(Opcode::Connect),
            0x02 => Ok(Opcode::ConnectAck),
            0x03 => Ok(Opcode::Disconnect),
            0x10 => Ok(Opcode::MrReg),
            0x11 => Ok(Opcode::MrRegAck),
            0x12 => Ok(Opcode::MrDereg),
            0x13 => Ok(Opcode::MrDeregAck),
            0x20 => Ok(Opcode::Send),
            0x21 => Ok(Opcode::SendData),
            0x22 => Ok(Opcode::RecvComp),
            0x30 => Ok(Opcode::Write),
            0x31 => Ok(Opcode::WriteData),
            0x32 => Ok(Opcode::WriteComp),
            0x40 => Ok(Opcode::ReadReq),
            0x41 => Ok(Opcode::ReadResp),
            0x50 => Ok(Opcode::AtomicReq),
            0x51 => Ok(Opcode::AtomicResp),
            0x60 => Ok(Opcode::Ack),
            0x61 => Ok(Opcode::CreditUpdate),
            0xF0 => Ok(Opcode::Error),
            _ => Err(InvalidOpcode(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidOpcode(pub u8);

impl std::fmt::Display for InvalidOpcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid RDoWS opcode: 0x{:02X}", self.0)
    }
}

impl std::error::Error for InvalidOpcode {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_opcodes() {
        let opcodes = [
            (0x01u8, Opcode::Connect),
            (0x02, Opcode::ConnectAck),
            (0x03, Opcode::Disconnect),
            (0x10, Opcode::MrReg),
            (0x11, Opcode::MrRegAck),
            (0x12, Opcode::MrDereg),
            (0x13, Opcode::MrDeregAck),
            (0x20, Opcode::Send),
            (0x21, Opcode::SendData),
            (0x22, Opcode::RecvComp),
            (0x30, Opcode::Write),
            (0x31, Opcode::WriteData),
            (0x32, Opcode::WriteComp),
            (0x40, Opcode::ReadReq),
            (0x41, Opcode::ReadResp),
            (0x50, Opcode::AtomicReq),
            (0x51, Opcode::AtomicResp),
            (0x60, Opcode::Ack),
            (0x61, Opcode::CreditUpdate),
            (0xF0, Opcode::Error),
        ];

        for (byte, expected) in opcodes {
            let op = Opcode::try_from(byte).unwrap();
            assert_eq!(op, expected);
            assert_eq!(u8::from(op), byte);
        }
    }

    #[test]
    fn unknown_opcode_errors() {
        for byte in [0x00, 0x04, 0x0F, 0x14, 0x23, 0x33, 0x42, 0x52, 0x62, 0xEF, 0xF1, 0xFF] {
            assert!(Opcode::try_from(byte).is_err());
        }
    }

    #[test]
    fn protocol_messages() {
        assert!(Opcode::Connect.is_protocol_message());
        assert!(Opcode::ConnectAck.is_protocol_message());
        assert!(Opcode::Ack.is_protocol_message());
        assert!(Opcode::Error.is_protocol_message());
        assert!(Opcode::CreditUpdate.is_protocol_message());
        assert!(!Opcode::Send.is_protocol_message());
        assert!(!Opcode::Write.is_protocol_message());
    }
}
