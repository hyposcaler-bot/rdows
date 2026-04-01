pub mod completion;
pub mod connection;
pub mod verbs;

use rdows_core::error::RdowsError;
use rdows_core::frame::RdowsHeader;
use rdows_core::memory::ProtectionDomain;
use rdows_core::message::RdowsMessage;
use rdows_core::opcode::Opcode;

use crate::completion::CompletionQueue;
use crate::connection::{ClientSink, ClientStream, ConnectionParams};

pub use rdows_core;

const DEFAULT_CQ_CAPACITY: usize = 65536;

pub struct RdowsConnection {
    pub(crate) sink: ClientSink,
    pub(crate) stream: ClientStream,
    pub(crate) session_id: u32,
    pub(crate) pd: ProtectionDomain,
    #[allow(dead_code)]
    pub(crate) max_msg_size: u32,
    pub(crate) next_seq: u32,
    pub(crate) cq: CompletionQueue,
    pub(crate) local_mrs: std::collections::HashMap<u32, verbs::MemoryRegionHandle>,
}

impl RdowsConnection {
    pub async fn connect(
        url: &str,
        tls_config: rustls::ClientConfig,
    ) -> Result<Self, RdowsError> {
        let (sink, stream, params) = connection::connect(url, tls_config).await?;
        let ConnectionParams {
            session_id,
            pd,
            max_msg_size,
        } = params;

        Ok(Self {
            sink,
            stream,
            session_id,
            pd,
            max_msg_size,
            next_seq: 1, // 0 was used for CONNECT
            cq: CompletionQueue::new(DEFAULT_CQ_CAPACITY),
            local_mrs: std::collections::HashMap::new(),
        })
    }

    pub async fn disconnect(mut self) -> Result<(), RdowsError> {
        let header = self.next_header(Opcode::Disconnect, 0);
        let msg = RdowsMessage::Disconnect(header);
        connection::send_message(&mut self.sink, &msg).await
    }

    pub fn poll_cq(&mut self, max: usize) -> Vec<rdows_core::queue::CompletionQueueEntry> {
        self.cq.poll_cq(max)
    }

    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    pub(crate) fn next_header(&mut self, opcode: Opcode, wrid: u64) -> RdowsHeader {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        RdowsHeader::new(opcode, self.session_id, seq, wrid)
    }

    pub(crate) async fn send_and_recv(
        &mut self,
        msg: RdowsMessage,
    ) -> Result<RdowsMessage, RdowsError> {
        connection::send_message(&mut self.sink, &msg).await?;
        connection::recv_message(&mut self.stream).await
    }
}
