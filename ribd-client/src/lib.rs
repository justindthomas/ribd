//! Producer-side client for ribd.
//!
//! Connects to the ribd Unix socket, handles the Hello handshake,
//! encodes [`ClientMsg`] frames, and decodes [`ServerMsg`] replies.
//! Automatic reconnect with exponential backoff is the caller's job
//! — this crate exposes a low-level `RibClient::connect` and a
//! higher-level `RibConnection::push_bulk` helper.
//!
//! Producer contract: on every connect (including after a reconnect),
//! the producer MUST send a `Bulk` with its full current view of
//! routes before issuing individual `Update` messages. ribd uses
//! the Bulk as the recovery primitive.

use std::path::Path;
use std::time::Duration;

use std::sync::atomic::{AtomicU64, Ordering};

use ribd_proto::{
    decode, encode, Action, ClientMsg, CodecError, QueryReply, QueryRequest, Route, ServerMsg,
    Source, PROTOCOL_VERSION,
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    #[error("server refused hello: {0}")]
    HelloRejected(String),
    #[error("server error: {0}")]
    ServerError(String),
    #[error("unexpected server reply: {0}")]
    Unexpected(String),
    #[error("timeout")]
    Timeout,
}

pub struct RibConnection {
    stream: UnixStream,
}

impl RibConnection {
    /// Connect to ribd and complete the Hello handshake.
    pub async fn connect(
        socket_path: impl AsRef<Path>,
        client_name: &str,
    ) -> Result<Self, ClientError> {
        let stream = UnixStream::connect(socket_path).await?;
        let mut conn = RibConnection { stream };
        conn.send(&ClientMsg::Hello {
            client_name: client_name.to_string(),
            protocol_version: PROTOCOL_VERSION,
        })
        .await?;
        match conn.recv().await? {
            ServerMsg::HelloAck { server_version: _ } => Ok(conn),
            ServerMsg::Error { message } => Err(ClientError::HelloRejected(message)),
            other => Err(ClientError::Unexpected(format!("{:?}", other))),
        }
    }

    /// Send a Bulk — the sole atomic replace-all primitive per source.
    /// On success the server's RIB now reflects exactly the given set
    /// of routes for that source. Bounded by `MAX_FRAME_LEN` (16 MB
    /// of bincode-encoded routes, ~80k routes); large producers like
    /// bgpd should use `push_bulk_chunked` instead.
    pub async fn push_bulk(
        &mut self,
        source: Source,
        routes: Vec<Route>,
    ) -> Result<(), ClientError> {
        self.send(&ClientMsg::Bulk { source, routes }).await?;
        match self.recv().await? {
            ServerMsg::Ok => Ok(()),
            ServerMsg::Error { message } => Err(ClientError::ServerError(message)),
            other => Err(ClientError::Unexpected(format!("{:?}", other))),
        }
    }

    /// Push a large route set as a chunked bulk: BulkBegin, then N
    /// BulkChunk frames of `chunk_size` routes each, then BulkEnd.
    /// The server atomically swaps the source's route set on
    /// BulkEnd; if the connection drops or any chunk fails, the
    /// staging buffer is discarded and the server's previous view of
    /// `source` remains in effect.
    ///
    /// `chunk_size` should be sized so each chunk's bincode encoding
    /// stays under `MAX_FRAME_LEN` (16 MB). A safe default for IPv4
    /// unicast routes with single recursive next-hops is ~50_000.
    pub async fn push_bulk_chunked(
        &mut self,
        source: Source,
        routes: Vec<Route>,
        chunk_size: usize,
    ) -> Result<(), ClientError> {
        let generation = next_generation();
        self.send(&ClientMsg::BulkBegin { source, generation })
            .await?;
        match self.recv().await? {
            ServerMsg::Ok => {}
            ServerMsg::Error { message } => return Err(ClientError::ServerError(message)),
            other => return Err(ClientError::Unexpected(format!("{:?}", other))),
        }
        for chunk in routes.chunks(chunk_size.max(1)) {
            self.send(&ClientMsg::BulkChunk {
                generation,
                routes: chunk.to_vec(),
            })
            .await?;
            match self.recv().await? {
                ServerMsg::Ok => {}
                ServerMsg::Error { message } => return Err(ClientError::ServerError(message)),
                other => return Err(ClientError::Unexpected(format!("{:?}", other))),
            }
        }
        self.send(&ClientMsg::BulkEnd { source, generation }).await?;
        match self.recv().await? {
            ServerMsg::Ok => Ok(()),
            ServerMsg::Error { message } => Err(ClientError::ServerError(message)),
            other => Err(ClientError::Unexpected(format!("{:?}", other))),
        }
    }

    /// Incremental add/delete. Use between Bulks to avoid resending
    /// the whole table on small changes.
    pub async fn update(&mut self, action: Action, route: Route) -> Result<(), ClientError> {
        self.send(&ClientMsg::Update { action, route }).await?;
        match self.recv().await? {
            ServerMsg::Ok => Ok(()),
            ServerMsg::Error { message } => Err(ClientError::ServerError(message)),
            other => Err(ClientError::Unexpected(format!("{:?}", other))),
        }
    }

    pub async fn query(&mut self, req: QueryRequest) -> Result<QueryReply, ClientError> {
        self.send(&ClientMsg::Query(req)).await?;
        match self.recv().await? {
            ServerMsg::QueryReply(r) => Ok(r),
            ServerMsg::Error { message } => Err(ClientError::ServerError(message)),
            other => Err(ClientError::Unexpected(format!("{:?}", other))),
        }
    }

    pub async fn heartbeat(&mut self) -> Result<(), ClientError> {
        self.send(&ClientMsg::Heartbeat).await?;
        match self.recv().await? {
            ServerMsg::Ok => Ok(()),
            ServerMsg::Error { message } => Err(ClientError::ServerError(message)),
            other => Err(ClientError::Unexpected(format!("{:?}", other))),
        }
    }

    async fn send(&mut self, msg: &ClientMsg) -> Result<(), ClientError> {
        let buf = encode(msg)?;
        self.stream.write_all(&buf).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<ServerMsg, ClientError> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > ribd_proto::MAX_FRAME_LEN {
            return Err(CodecError::FrameTooLarge(len).into());
        }
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await?;
        Ok(decode(&buf)?)
    }
}

/// Monotonically-increasing generation IDs for chunked bulks.
/// Producer-local: each connection's first chunked bulk picks up
/// where the previous one left off, but since the server keys
/// staging by `(connection, generation)`, collisions across
/// connections are harmless.
fn next_generation() -> u64 {
    static GEN: AtomicU64 = AtomicU64::new(1);
    GEN.fetch_add(1, Ordering::Relaxed)
}

/// Connect with a bounded retry schedule. Useful at daemon startup
/// when ribd may not be ready yet.
pub async fn connect_with_retry(
    socket_path: impl AsRef<Path>,
    client_name: &str,
    max_wait: Duration,
) -> Result<RibConnection, ClientError> {
    let deadline = tokio::time::Instant::now() + max_wait;
    let mut backoff = Duration::from_millis(100);
    loop {
        match timeout(
            Duration::from_secs(2),
            RibConnection::connect(socket_path.as_ref(), client_name),
        )
        .await
        {
            Ok(Ok(c)) => return Ok(c),
            Ok(Err(e)) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(e);
                }
                tracing::debug!("ribd connect failed, retrying: {}", e);
            }
            Err(_) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(ClientError::Timeout);
                }
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(5));
    }
}
