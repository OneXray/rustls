//! Public configuration and key-share negotiation tests. The labelled hybrid
//! sentinel uses real X25519 but deliberately does not implement ML-KEM.

use rustls::client::{RealityClientConfig, RealityConfigError};
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup, ring};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

#[test]
fn default_reality_remains_classic_even_when_hybrid_is_first() {
    let hello = client_hello(reality(), vec![&HYBRID, ring::kx_group::X25519]);
    assert_eq!(key_shares(&hello).len(), 1);
    assert_eq!(key_share(&hello), (u16::from(NamedGroup::X25519), 32));
}

#[test]
fn explicit_hybrid_reaches_provider_and_client_hello() {
    let hello = client_hello(
        reality()
            .with_key_exchange_group(NamedGroup::X25519MLKEM768)
            .unwrap(),
        vec![ring::kx_group::X25519, &HYBRID],
    );
    assert_eq!(
        key_share(&hello),
        (u16::from(NamedGroup::X25519MLKEM768), 1216)
    );
}

#[test]
fn hybrid_fallback_offers_the_same_classical_component_in_both_shares() {
    let hello = client_hello(
        reality()
            .with_key_exchange_group(NamedGroup::X25519MLKEM768)
            .unwrap(),
        vec![ring::kx_group::X25519, &HYBRID],
    );
    let shares = key_shares(&hello);
    assert_eq!(shares.len(), 2);
    assert_eq!((shares[0].0, shares[0].1.len()), (0x11ec, 1216));
    assert_eq!((shares[1].0, shares[1].1.len()), (0x001d, 32));
    assert_eq!(&shares[0].1[1184..], shares[1].1);
}

#[test]
fn offered_classical_fallback_is_reported_as_classical_not_hybrid() {
    let (mut connection, hello) = connection_and_hello(
        reality()
            .with_key_exchange_group(NamedGroup::X25519MLKEM768)
            .unwrap(),
        vec![ring::kx_group::X25519, &HYBRID],
    );
    connection
        .read_tls(&mut classical_server_hello(&hello).as_slice())
        .unwrap();
    connection
        .process_new_packets()
        .unwrap();
    assert_eq!(
        connection
            .negotiated_key_exchange_group()
            .unwrap()
            .name(),
        NamedGroup::X25519
    );
    // Only ServerHello was supplied: this does not claim certificate authentication.
    assert!(connection.is_handshaking());
}

#[test]
fn strict_hybrid_neither_offers_nor_accepts_the_classical_component() {
    let (mut connection, hello) = connection_and_hello(
        reality()
            .with_key_exchange_group(NamedGroup::X25519MLKEM768)
            .unwrap(),
        vec![&HYBRID],
    );
    let shares = key_shares(&hello);
    assert_eq!(shares.len(), 1);
    assert_eq!((shares[0].0, shares[0].1.len()), (0x11ec, 1216));
    connection
        .read_tls(&mut classical_server_hello(&hello).as_slice())
        .unwrap();
    assert!(matches!(
        connection.process_new_packets(),
        Err(Error::PeerMisbehaved(PeerMisbehaved::WrongGroupForKeyShare))
    ));
    assert!(
        connection
            .negotiated_key_exchange_group()
            .is_none()
    );
}

#[test]
fn unsupported_reality_group_is_rejected() {
    for group in [
        NamedGroup::secp256r1,
        NamedGroup::MLKEM768,
        NamedGroup::Unknown(0xffff),
    ] {
        assert_eq!(
            reality()
                .with_key_exchange_group(group)
                .unwrap_err(),
            RealityConfigError::UnsupportedKeyExchangeGroup
        );
    }
}

#[test]
fn hybrid_request_never_silently_selects_a_classic_provider() {
    assert!(
        config(
            reality()
                .with_key_exchange_group(NamedGroup::X25519MLKEM768)
                .unwrap(),
            vec![ring::kx_group::X25519],
        )
        .is_err()
    );
}

#[test]
fn hybrid_name_without_reality_capability_is_rejected() {
    // A capable duplicate must not hide the first unusable implementation.
    assert!(
        config(
            reality()
                .with_key_exchange_group(NamedGroup::X25519MLKEM768)
                .unwrap(),
            vec![&NAMED_ONLY_HYBRID, &HYBRID],
        )
        .is_err()
    );
}

#[test]
fn low_order_reality_key_fails_before_hybrid_client_hello() {
    let reality = RealityClientConfig::new([0; 32], &[], [26, 7, 11])
        .unwrap()
        .with_key_exchange_group(NamedGroup::X25519MLKEM768)
        .unwrap();
    let config = config(reality, vec![&HYBRID]).unwrap();
    assert!(
        ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap()).is_err()
    );
}

fn reality() -> RealityClientConfig {
    let mut key = [0; 32];
    key[0] = 9;
    RealityClientConfig::new(key, &[1, 2, 3, 4], [26, 7, 11]).unwrap()
}

fn config(
    reality: RealityClientConfig,
    groups: Vec<&'static dyn SupportedKxGroup>,
) -> Result<ClientConfig, Error> {
    let mut provider = ring::default_provider();
    provider.kx_groups = groups;
    Ok(ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_reality(reality)?
        .with_no_client_auth())
}

fn client_hello(
    reality: RealityClientConfig,
    groups: Vec<&'static dyn SupportedKxGroup>,
) -> Vec<u8> {
    connection_and_hello(reality, groups).1
}

fn connection_and_hello(
    reality: RealityClientConfig,
    groups: Vec<&'static dyn SupportedKxGroup>,
) -> (ClientConnection, Vec<u8>) {
    let mut connection = ClientConnection::new(
        config(reality, groups).unwrap().into(),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut hello = Vec::new();
    connection
        .write_tls(&mut hello)
        .unwrap();
    (connection, hello)
}

fn classical_server_hello(client_hello: &[u8]) -> Vec<u8> {
    // RFC 8446 ServerHello fixture: echo the session ID and select TLS 1.3,
    // TLS_AES_128_GCM_SHA256 and a genuine freshly generated X25519 public key.
    let session_id_offset = 5 + 4 + 2 + 32;
    let session_id_len = usize::from(client_hello[session_id_offset]);
    let server_key = ring::kx_group::X25519.start().unwrap();
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x5a; 32]);
    body.extend_from_slice(
        &client_hello[session_id_offset..session_id_offset + 1 + session_id_len],
    );
    body.extend_from_slice(&[
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x00, // legacy_compression_method
        0x00, 0x2e, // extensions length: 46
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, // supported_versions: TLS 1.3
        0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, // key_share: X25519
    ]);
    body.extend_from_slice(server_key.pub_key());
    let mut record = vec![0x16, 0x03, 0x03];
    record.extend_from_slice(
        &u16::try_from(body.len() + 4)
            .unwrap()
            .to_be_bytes(),
    );
    record.push(0x02); // HandshakeType::ServerHello
    record.extend_from_slice(
        &u32::try_from(body.len())
            .unwrap()
            .to_be_bytes()[1..],
    );
    record.extend_from_slice(&body);
    record
}

fn key_share(hello: &[u8]) -> (u16, usize) {
    let shares = key_shares(hello);
    (shares[0].0, shares[0].1.len())
}

fn key_shares(hello: &[u8]) -> Vec<(u16, &[u8])> {
    // One TLS record containing one ClientHello, generated by this library.
    assert_eq!(hello[0], 22);
    assert_eq!(hello[5], 1);
    let mut pos = 5 + 4 + 2 + 32;
    pos += 1 + usize::from(hello[pos]);
    pos += 2 + word(hello, pos);
    pos += 1 + usize::from(hello[pos]);
    let end = pos + 2 + word(hello, pos);
    pos += 2;
    while pos < end {
        let kind = word(hello, pos);
        let len = word(hello, pos + 2);
        if kind == 51 {
            assert_eq!(word(hello, pos + 4), len - 2);
            let shares_end = pos + 4 + len;
            pos += 6;
            let mut shares = Vec::new();
            while pos < shares_end {
                let group = word(hello, pos) as u16;
                let share_len = word(hello, pos + 2);
                shares.push((group, &hello[pos + 4..pos + 4 + share_len]));
                pos += 4 + share_len;
            }
            assert_eq!(pos, shares_end);
            return shares;
        }
        pos += 4 + len;
    }
    panic!("missing key_share");
}

fn word(bytes: &[u8], offset: usize) -> usize {
    usize::from(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]))
}

static HYBRID: HybridSentinel = HybridSentinel { capable: true };
static NAMED_ONLY_HYBRID: HybridSentinel = HybridSentinel { capable: false };

#[derive(Debug)]
struct HybridSentinel {
    capable: bool,
}

impl SupportedKxGroup for HybridSentinel {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        panic!("REALITY must dispatch start_reality, not start")
    }

    fn supports_reality(&self) -> bool {
        self.capable
    }

    fn start_reality(
        &self,
        key: &[u8; 32],
    ) -> Result<(Box<dyn ActiveKeyExchange>, SharedSecret), Error> {
        let (classical, auth) = ring::kx_group::X25519.start_reality(key)?;
        let mut public = vec![0; 1184];
        public.extend_from_slice(classical.pub_key());
        Ok((Box::new(HybridShare { classical, public }), auth))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct HybridShare {
    classical: Box<dyn ActiveKeyExchange>,
    public: Vec<u8>,
}

impl ActiveKeyExchange for HybridShare {
    fn complete(self: Box<Self>, _: &[u8]) -> Result<SharedSecret, Error> {
        panic!("sentinel only tests ClientHello dispatch, not cryptography")
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((NamedGroup::X25519, self.classical.pub_key()))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        self.classical.complete(peer_pub_key)
    }
}
