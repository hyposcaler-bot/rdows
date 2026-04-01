use rdows_core::error::{ErrorCode, RdowsError};
use rdows_core::memory::AccessFlags;
use rdows_core::message::{
    MrDeregAckPayload, MrRegAckPayload, ReadRespPayload, RdowsMessage,
};
use rdows_core::opcode::Opcode;

use crate::session::{send_error, send_message, Session, WsSink};

pub async fn dispatch(
    session: &mut Session,
    msg: RdowsMessage,
    sink: &mut WsSink,
) -> Result<(), RdowsError> {
    let seq = msg.header().sequence;

    match msg {
        RdowsMessage::MrReg(header, payload) => {
            handle_mr_reg(session, header.wrid, payload, sink).await
        }
        RdowsMessage::MrDereg(header, payload) => {
            handle_mr_dereg(session, header.wrid, payload, sink).await
        }
        RdowsMessage::Send(header, payload) => {
            handle_send(session, header, payload, sink).await
        }
        RdowsMessage::SendData(header, payload) => {
            handle_send_data(session, header, payload, sink).await
        }
        RdowsMessage::Write(header, payload) => {
            handle_write(session, header, payload, sink).await
        }
        RdowsMessage::WriteData(header, payload) => {
            handle_write_data(session, header, payload, sink).await
        }
        RdowsMessage::ReadReq(header, payload) => {
            handle_read_req(session, header, payload, sink).await
        }
        RdowsMessage::AtomicReq(..) | RdowsMessage::AtomicResp(..) => {
            send_error(
                session,
                sink,
                ErrorCode::ErrUnknownOpcode,
                seq,
                "atomic operations not supported",
            )
            .await
        }
        RdowsMessage::Ack(_) => {
            // Accept and ignore
            Ok(())
        }
        _ => {
            send_error(
                session,
                sink,
                ErrorCode::ErrUnknownOpcode,
                seq,
                "unsupported opcode",
            )
            .await
        }
    }
}

async fn handle_mr_reg(
    session: &mut Session,
    wrid: u64,
    payload: rdows_core::message::MrRegPayload,
    sink: &mut WsSink,
) -> Result<(), RdowsError> {
    match session
        .memory_store
        .register(payload.pd, payload.access_flags, payload.region_len)
    {
        Ok((lkey, rkey)) => {
            let header = session.next_header(Opcode::MrRegAck, wrid);
            let ack = MrRegAckPayload {
                pd: payload.pd,
                lkey,
                rkey,
                status: 0,
            };
            send_message(sink, &RdowsMessage::MrRegAck(header, ack)).await
        }
        Err(code) => {
            let header = session.next_header(Opcode::MrRegAck, wrid);
            let ack = MrRegAckPayload {
                pd: payload.pd,
                lkey: rdows_core::memory::LKey(0),
                rkey: rdows_core::memory::RKey(0),
                status: code.into(),
            };
            send_message(sink, &RdowsMessage::MrRegAck(header, ack)).await
        }
    }
}

async fn handle_mr_dereg(
    session: &mut Session,
    wrid: u64,
    payload: rdows_core::message::MrDeregPayload,
    sink: &mut WsSink,
) -> Result<(), RdowsError> {
    let status = match session
        .memory_store
        .deregister(payload.pd, payload.lkey)
    {
        Ok(()) => 0,
        Err(code) => code.into(),
    };

    let header = session.next_header(Opcode::MrDeregAck, wrid);
    let ack = MrDeregAckPayload { status };
    send_message(sink, &RdowsMessage::MrDeregAck(header, ack)).await
}

// Phase 4: SEND/RECV

#[derive(Debug)]
pub enum PendingOp {
    None,
    AwaitingSendData { wrid: u64 },
    AwaitingWriteData {
        wrid: u64,
        rkey: rdows_core::memory::RKey,
        remote_va: u64,
        expected_len: u64,
    },
}

async fn handle_send(
    session: &mut Session,
    header: rdows_core::frame::RdowsHeader,
    _payload: rdows_core::message::SendPayload,
    _sink: &mut WsSink,
) -> Result<(), RdowsError> {
    // Check if server has posted receives (MVP: auto-accept)
    session.pending_op = PendingOp::AwaitingSendData {
        wrid: header.wrid,
    };
    Ok(())
}

async fn handle_send_data(
    session: &mut Session,
    _header: rdows_core::frame::RdowsHeader,
    payload: rdows_core::message::DataPayload,
    sink: &mut WsSink,
) -> Result<(), RdowsError> {
    let wrid = match std::mem::replace(&mut session.pending_op, PendingOp::None) {
        PendingOp::AwaitingSendData { wrid } => wrid,
        _ => {
            return send_error(
                session,
                sink,
                ErrorCode::ErrUnknownOpcode,
                0,
                "unexpected SEND_DATA without preceding SEND",
            )
            .await;
        }
    };

    // Data received. Send RECV_COMP back to initiator.
    let _data = payload.data; // In a real implementation, we'd copy to receive buffer
    let header = session.next_header(Opcode::RecvComp, wrid);
    send_message(sink, &RdowsMessage::RecvComp(header)).await
}

// Phase 5: RDMA Write + Read

async fn handle_write(
    session: &mut Session,
    header: rdows_core::frame::RdowsHeader,
    payload: rdows_core::message::WritePayload,
    sink: &mut WsSink,
) -> Result<(), RdowsError> {
    // Validate R_Key and access before accepting data
    if let Err(code) = session
        .memory_store
        .validate_rkey(payload.rkey, AccessFlags::REMOTE_WRITE)
    {
        return send_error(session, sink, code, header.sequence, "").await;
    }

    session.pending_op = PendingOp::AwaitingWriteData {
        wrid: header.wrid,
        rkey: payload.rkey,
        remote_va: payload.remote_va,
        expected_len: payload.length,
    };
    Ok(())
}

async fn handle_write_data(
    session: &mut Session,
    _header: rdows_core::frame::RdowsHeader,
    payload: rdows_core::message::DataPayload,
    sink: &mut WsSink,
) -> Result<(), RdowsError> {
    let (wrid, rkey, remote_va) =
        match std::mem::replace(&mut session.pending_op, PendingOp::None) {
            PendingOp::AwaitingWriteData {
                wrid,
                rkey,
                remote_va,
                ..
            } => (wrid, rkey, remote_va),
            _ => {
                return send_error(
                    session,
                    sink,
                    ErrorCode::ErrUnknownOpcode,
                    0,
                    "unexpected WRITE_DATA without preceding WRITE",
                )
                .await;
            }
        };

    // Write data into memory region
    if let Err(code) = session
        .memory_store
        .write_region(rkey, remote_va, &payload.data)
    {
        return send_error(session, sink, code, 0, "").await;
    }

    // Send WRITE_COMP
    let header = session.next_header(Opcode::WriteComp, wrid);
    send_message(sink, &RdowsMessage::WriteComp(header)).await
}

async fn handle_read_req(
    session: &mut Session,
    header: rdows_core::frame::RdowsHeader,
    payload: rdows_core::message::ReadReqPayload,
    sink: &mut WsSink,
) -> Result<(), RdowsError> {
    let data = match session
        .memory_store
        .read_region(payload.rkey, payload.remote_va, payload.read_len)
    {
        Ok(slice) => bytes::Bytes::copy_from_slice(slice),
        Err(code) => {
            return send_error(session, sink, code, header.sequence, "").await;
        }
    };

    let resp_header = session.next_header(Opcode::ReadResp, header.wrid);
    let resp_payload = ReadRespPayload {
        fragment_offset: 0,
        data,
    };
    send_message(sink, &RdowsMessage::ReadResp(resp_header, resp_payload)).await
}
