//! Explicit, loopback-only REALITY/VLESS roundtrip. No system proxy or TUN setup.

use std::collections::HashMap;
use std::error::Error;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reality_hybrid_probe::HYBRID;
use rustls::client::RealityClientConfig;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, NamedGroup, StreamOwned};

fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.len() % 2 != 0 {
        return Err("expected --name value pairs".into());
    }
    let options: HashMap<_, _> = arguments
        .chunks_exact(2)
        .map(|pair| (pair[0].as_str(), pair[1].as_str()))
        .collect();
    let required = |name| {
        options
            .get(name)
            .copied()
            .ok_or("missing required argument")
    };
    let peer: SocketAddr = required("--peer")?.parse()?;
    let target: SocketAddr = required("--target")?.parse()?;
    if !peer.ip().is_loopback() || !target.ip().is_loopback() {
        return Err("this acceptance probe permits loopback addresses only".into());
    }
    let public_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(required("--public-key")?)?
        .try_into()
        .map_err(|_| "REALITY public key must be 32 bytes")?;
    let short_id = parse_hex(required("--short-id")?)?;
    let uuid: [u8; 16] = parse_hex(&required("--uuid")?.replace('-', ""))?
        .try_into()
        .map_err(|_| "UUID must be 16 bytes")?;
    let mode = required("--mode")?;
    let selected_group = match mode {
        "hybrid" => NamedGroup::X25519MLKEM768,
        "fallback" => NamedGroup::X25519MLKEM768,
        "classic" => NamedGroup::X25519,
        _ => return Err("mode must be hybrid, fallback or classic".into()),
    };
    let expected_group = if mode == "fallback" {
        NamedGroup::X25519
    } else {
        selected_group
    };
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = match mode {
        "hybrid" => vec![&HYBRID],
        "fallback" => vec![&HYBRID, rustls::crypto::ring::kx_group::X25519],
        _ => vec![rustls::crypto::ring::kx_group::X25519],
    };
    let reality = RealityClientConfig::new(public_key, &short_id, [26, 7, 11])?
        .with_key_exchange_group(selected_group)?;
    let config = ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_reality(reality)?
        .with_no_client_auth();
    let mut connection = ClientConnection::new(
        config.into(),
        ServerName::try_from(required("--sni")?.to_owned())?,
    )?;
    let mut socket = TcpStream::connect_timeout(&peer, Duration::from_secs(10))?;
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(Duration::from_secs(10)))?;
    while connection.is_handshaking() {
        connection.complete_io(&mut socket)?;
    }
    let negotiated_group = connection
        .negotiated_key_exchange_group()
        .ok_or("missing negotiated key exchange group")?
        .name();
    if negotiated_group != expected_group {
        return Err("peer negotiated a different group than explicitly requested".into());
    }
    let mut stream = StreamOwned::new(connection, socket);
    let mut request = vec![0];
    request.extend_from_slice(&uuid);
    request.extend_from_slice(&[0, 1]); // no add-ons, TCP command
    request.extend_from_slice(&target.port().to_be_bytes());
    match target.ip() {
        IpAddr::V4(address) => {
            request.push(1);
            request.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            request.push(3);
            request.extend_from_slice(&address.octets());
        }
    }
    const PAYLOAD: &[u8] = b"rustls-reality-hybrid-loopback\n";
    request.extend_from_slice(PAYLOAD);
    stream.write_all(&request)?;
    stream.flush()?;
    let mut response_header = [0u8; 2];
    stream.read_exact(&mut response_header)?;
    if response_header != [0, 0] {
        return Err("unexpected VLESS response header".into());
    }
    let mut echoed = vec![0; PAYLOAD.len()];
    stream.read_exact(&mut echoed)?;
    if echoed != PAYLOAD {
        return Err("VLESS tunneled payload mismatch".into());
    }
    println!(
        "PASS negotiated={negotiated_group:?} tls=TLSv1_3 vless_echo_bytes={}",
        echoed.len()
    );
    Ok(())
}

fn parse_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if value.len() % 2 != 0 || !value.is_ascii() {
        return Err("expected even-length ASCII hex".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).map_err(Into::into))
        .collect()
}
