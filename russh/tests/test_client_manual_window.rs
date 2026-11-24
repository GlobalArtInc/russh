//! `client::Config::manual_window`: a channel's receive window on the client
//! grows only through `client::Handle::grant_window`. A russh client and
//! server talk in process over a duplex pipe; the server writes into the
//! channel and reports every window adjust and every `ack` from the client in
//! the order it reads them.
//!
//! Ordering, not time: russh writes any window adjust it makes for a packet
//! before it hands the packet to the channel, and a grant is handled before
//! channel data queued after it, so an adjust always reaches the server before
//! the `ack` the client sends next.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use russh::client;
use russh::keys::PrivateKey;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg, ChannelWriteHalf, Disconnect, MethodKind, MethodSet};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// The client's initial window, two packets.
const WINDOW: u32 = 64 * 1024;
const PACKET: u32 = 32 * 1024;
/// A liveness bound only: every wait here ends in milliseconds when healthy.
const LIVENESS: Duration = Duration::from_secs(30);

#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Adjust(u32),
    Ack,
}

struct Server {
    opened: mpsc::UnboundedSender<Channel<Msg>>,
    seen: mpsc::UnboundedSender<Seen>,
}

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        let _ = self.opened.send(channel);
        Ok(())
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        assert_eq!(data, b"ack");
        let _ = self.seen.send(Seen::Ack);
        Ok(())
    }

    async fn window_adjusted(
        &mut self,
        _channel: ChannelId,
        new_size: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = self.seen.send(Seen::Adjust(new_size));
        Ok(())
    }
}

struct Client;

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct Pair {
    client: client::Handle<Client>,
    channel: Channel<client::Msg>,
    server: Option<ChannelWriteHalf<Msg>>,
    seen: mpsc::UnboundedReceiver<Seen>,
}

impl Pair {
    /// The server writes `bytes` into the channel, as extended data if `ext`
    /// is set, waiting for window as it goes.
    fn write(&mut self, bytes: u32, ext: Option<u32>) -> JoinHandle<Result<(), russh::Error>> {
        let server = self.server.take().expect("one writer per test");
        let data = Bytes::from(vec![b'x'; bytes as usize]);
        tokio::spawn(async move {
            match ext {
                Some(ext) => server.extended_data_bytes(ext, data).await,
                None => server.data_bytes(data).await,
            }
        })
    }

    /// Reads exactly `bytes` of (extended) data from the channel.
    async fn receive(&mut self, bytes: u32) {
        let mut received = 0;
        while received < bytes as usize {
            match tokio::time::timeout(LIVENESS, self.channel.wait()).await {
                Ok(Some(ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. })) => {
                    received += data.len();
                }
                Ok(Some(_)) => {}
                Ok(None) => panic!("the channel closed"),
                Err(_) => panic!("no data within {LIVENESS:?}"),
            }
        }
        assert_eq!(received, bytes as usize, "the server sent past the window");
    }

    fn grant(&self, bytes: u32) {
        self.client
            .grant_window(self.channel.id(), bytes)
            .expect("the session is running");
    }

    /// Sends an `ack` and returns what the server saw up to and including it.
    async fn ack(&mut self) -> Vec<Seen> {
        tokio::time::timeout(LIVENESS, self.channel.data(&b"ack"[..]))
            .await
            .expect("the ack was sent in time")
            .unwrap();
        let mut seen = Vec::new();
        loop {
            match tokio::time::timeout(LIVENESS, self.seen.recv()).await {
                Ok(Some(Seen::Ack)) => {
                    seen.push(Seen::Ack);
                    return seen;
                }
                Ok(Some(adjust)) => seen.push(adjust),
                Ok(None) => panic!("the server ended"),
                Err(_) => panic!("no ack within {LIVENESS:?}"),
            }
        }
    }
}

async fn connect(manual_window: bool) -> Pair {
    tokio::time::timeout(LIVENESS, setup(manual_window))
        .await
        .expect("setup finished in time")
}

async fn setup(manual_window: bool) -> Pair {
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
    let server_config = server::Config {
        methods: MethodSet::from(&[MethodKind::None][..]),
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![key],
        ..Default::default()
    };
    let client_config = client::Config {
        window_size: WINDOW,
        maximum_packet_size: PACKET,
        manual_window,
        ..Default::default()
    };
    let (client_io, server_io) = tokio::io::duplex(8 << 20);
    let (opened, mut open) = mpsc::unbounded_channel();
    let (seen, seen_rx) = mpsc::unbounded_channel();
    let handler = Server { opened, seen };
    let running = server::run_stream(Arc::new(server_config), server_io, handler);
    let connecting = client::connect_stream(Arc::new(client_config), client_io, Client);
    let (running, client) = tokio::join!(running, connecting);
    tokio::spawn(running.expect("server handshake"));
    let mut client = client.expect("client handshake");
    let auth = client.authenticate_none("anyone").await.unwrap();
    assert!(auth.success(), "{auth:?}");
    let channel = client.channel_open_session().await.unwrap();
    let (server_read, server) = open.recv().await.unwrap().split();
    drop(server_read);
    Pair {
        client,
        channel,
        server: Some(server),
        seen: seen_rx,
    }
}

#[tokio::test]
async fn with_manual_window_the_server_sends_only_what_was_granted() {
    let mut pair = connect(true).await;
    let writer = pair.write(3 * WINDOW, None);
    pair.receive(WINDOW).await;
    assert_eq!(pair.ack().await, [Seen::Ack], "refilled without a grant");
    assert!(!writer.is_finished());
    // Each grant opens an empty window, so the server's new window is the grant.
    for grant in [WINDOW, PACKET, WINDOW - PACKET] {
        pair.grant(grant);
        pair.receive(grant).await;
        assert_eq!(
            pair.ack().await,
            [Seen::Adjust(grant), Seen::Ack],
            "one window adjust of its size per grant"
        );
    }
    tokio::time::timeout(LIVENESS, writer)
        .await
        .expect("the writer finished in time")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn with_manual_window_extended_data_uses_up_the_window_too() {
    let mut pair = connect(true).await;
    let _writer = pair.write(WINDOW, Some(1));
    pair.receive(WINDOW).await;
    assert_eq!(pair.ack().await, [Seen::Ack], "refilled without a grant");
    pair.grant(u32::MAX);
    assert_eq!(
        pair.ack().await,
        [Seen::Adjust(u32::MAX), Seen::Ack],
        "the largest grant fits only into an empty window"
    );
}

#[tokio::test]
async fn without_manual_window_the_client_refills_the_window_on_receipt() {
    let mut pair = connect(false).await;
    let _writer = pair.write(WINDOW, None);
    pair.receive(WINDOW).await;
    let seen = pair.ack().await;
    assert!(seen.len() > 1, "russh's own refill came before the ack");
}

#[tokio::test]
async fn a_grant_fails_once_the_session_ended() {
    let pair = connect(true).await;
    let id = pair.channel.id();
    pair.client
        .disconnect(Disconnect::ByApplication, "", "en")
        .await
        .unwrap();
    tokio::time::timeout(LIVENESS, async {
        while pair.client.grant_window(id, 1).is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the grant failed in time");
}

#[test]
fn manual_window_is_off_by_default_and_shown_in_the_config() {
    let config = client::Config::default();
    assert!(!config.manual_window);
    assert!(format!("{config:?}").contains("manual_window: false"));
}
