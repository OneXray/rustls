//! Client-side support for Xray's classic REALITY authentication.
//!
//! The public configuration in this module is deliberately inert.  Ephemeral
//! secrets and the derived authentication key live in [`RealityHandshakeState`],
//! which is owned by one TLS connection and is never shared through a
//! [`crate::ClientConfig`].

use alloc::vec::Vec;
use core::{fmt, mem::size_of};

use pki_types::{CertificateDer, ServerName, UnixTime};
use ring::{aead, hkdf, hmac, signature};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypto::SharedSecret;
use crate::error::CertificateError;
use crate::sync::Arc;
use crate::verify::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use crate::{DigitallySignedStruct, Error, SignatureScheme};

const REALITY_INFO: &[u8] = b"REALITY";
const REALITY_AUTH_KEY_LEN: usize = 32;
const REALITY_CERT_MAX_LEN: usize = 16 * 1024;
const ED25519_OID: &[u8] = &[0x2b, 0x65, 0x70];

/// Immutable client configuration for Xray's classic REALITY protocol.
///
/// This type contains public connection parameters only.  It is therefore safe
/// to share between connections.  Connection-specific secrets are kept in
/// `RealityHandshakeState` instead.
#[derive(Clone, Debug)]
pub struct RealityClientConfig {
    server_public_key: [u8; 32],
    short_id: [u8; 8],
    client_version: [u8; 3],
}

impl RealityClientConfig {
    /// Construct a REALITY client configuration.
    ///
    /// `short_id` may contain zero through eight bytes.  It is stored in its
    /// eight-byte, zero-padded wire representation.
    pub fn new(
        server_public_key: [u8; 32],
        short_id: &[u8],
        client_version: [u8; 3],
    ) -> Result<Self, RealityConfigError> {
        if short_id.len() > 8 {
            return Err(RealityConfigError::ShortIdTooLong);
        }

        let mut fixed_short_id = [0u8; 8];
        fixed_short_id[..short_id.len()].copy_from_slice(short_id);

        Ok(Self {
            server_public_key,
            short_id: fixed_short_id,
            client_version,
        })
    }

    pub(crate) fn server_public_key(&self) -> &[u8; 32] {
        &self.server_public_key
    }

    pub(crate) fn short_id(&self) -> &[u8; 8] {
        &self.short_id
    }

    pub(crate) fn client_version(&self) -> [u8; 3] {
        self.client_version
    }
}

/// An invalid REALITY client configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealityConfigError {
    /// A REALITY short ID is limited to eight bytes.
    ShortIdTooLong,
}

impl fmt::Display for RealityConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortIdTooLong => f.write_str("REALITY short ID must be at most 8 bytes"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RealityConfigError {}

/// Per-connection REALITY authentication state.
///
/// The input shared secret is consumed after the session ID is sealed.  The
/// derived authentication key is consumed after the certificate is
/// authenticated, and the authenticated Ed25519 key is consumed after the
/// TLS 1.3 CertificateVerify message is checked.
pub(crate) struct RealityHandshakeState {
    config: Arc<RealityClientConfig>,
    auth_secret: Option<SharedSecret>,
    auth_key: Option<Zeroizing<[u8; REALITY_AUTH_KEY_LEN]>>,
    authenticated_public_key: Option<[u8; 32]>,
}

impl fmt::Debug for RealityHandshakeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityHandshakeState")
            .field("config", &self.config)
            .field("has_auth_secret", &self.auth_secret.is_some())
            .field("has_auth_key", &self.auth_key.is_some())
            .field(
                "has_authenticated_public_key",
                &self.authenticated_public_key.is_some(),
            )
            .finish()
    }
}

impl RealityHandshakeState {
    pub(crate) fn new(config: Arc<RealityClientConfig>, auth: SharedSecret) -> Self {
        Self {
            config,
            auth_secret: Some(auth),
            auth_key: None,
            authenticated_public_key: None,
        }
    }

    /// Seal the classic REALITY session ID.
    ///
    /// `client_hello_aad` must be the complete encoded ClientHello handshake
    /// message with its 32-byte legacy session ID set to zero.  `client_random`
    /// is split exactly as Xray does: its first 20 bytes are the HKDF salt and
    /// its last 12 bytes are the AES-GCM nonce.
    pub(crate) fn seal_session_id(
        &mut self,
        client_hello_aad: &[u8],
        client_random: &[u8; 32],
        unix_time: u32,
    ) -> Result<[u8; 32], Error> {
        let auth_secret = self
            .auth_secret
            .take()
            .ok_or_else(|| Error::General("REALITY session ID was already sealed".into()))?;

        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &client_random[..20]);
        let pseudo_random_key = salt.extract(auth_secret.secret_bytes());
        let info = [REALITY_INFO];
        let output_key_material = pseudo_random_key
            .expand(&info, RealityAuthKeyLength)
            .map_err(|_| Error::General("REALITY HKDF expansion failed".into()))?;

        let mut auth_key = Zeroizing::new([0u8; REALITY_AUTH_KEY_LEN]);
        output_key_material
            .fill(auth_key.as_mut())
            .map_err(|_| Error::General("REALITY HKDF output failed".into()))?;

        let mut session_id = [0u8; 32];
        session_id[..3].copy_from_slice(&self.config.client_version());
        // Byte 3 is reserved and remains zero.
        session_id[4..8].copy_from_slice(&unix_time.to_be_bytes());
        session_id[8..16].copy_from_slice(self.config.short_id());

        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, auth_key.as_ref())
            .map_err(|_| Error::General("REALITY AES-256-GCM key rejected".into()))?;
        let sealing_key = aead::LessSafeKey::new(unbound_key);
        let nonce_bytes: [u8; 12] = client_random[20..]
            .try_into()
            .map_err(|_| Error::General("REALITY nonce has the wrong length".into()))?;
        let tag = sealing_key
            .seal_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(nonce_bytes),
                aead::Aad::from(client_hello_aad),
                &mut session_id[..16],
            )
            .map_err(|_| Error::General("REALITY session ID encryption failed".into()))?;
        session_id[16..].copy_from_slice(tag.as_ref());

        self.auth_key = Some(auth_key);
        Ok(session_id)
    }

    /// Authenticate the server's classic REALITY certificate.
    ///
    /// No PKI fallback exists here.  The certificate must contain an Ed25519
    /// SubjectPublicKeyInfo and its outer signatureValue must equal
    /// HMAC-SHA512(auth_key, public_key).  Classic REALITY sends no
    /// intermediates.
    pub(crate) fn verify_server_certificate(
        &mut self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> Result<ServerCertVerified, Error> {
        let result = (|| {
            if !intermediates.is_empty() {
                return Err(invalid_certificate(CertificateError::BadEncoding));
            }

            let auth_key = self
                .auth_key
                .as_ref()
                .ok_or_else(|| invalid_certificate(CertificateError::BadSignature))?;
            let certificate = parse_reality_certificate(end_entity.as_ref())
                .map_err(|_| invalid_certificate(CertificateError::BadEncoding))?;

            let key = hmac::Key::new(hmac::HMAC_SHA512, auth_key.as_ref());
            let expected = hmac::sign(&key, &certificate.public_key);
            if !bool::from(
                expected
                    .as_ref()
                    .ct_eq(certificate.signature_value),
            ) {
                return Err(invalid_certificate(CertificateError::BadSignature));
            }

            Ok(certificate.public_key)
        })();

        // The authentication key is no longer needed after this operation,
        // whether it succeeds or fails.
        self.auth_key = None;

        match result {
            Ok(public_key) => {
                self.authenticated_public_key = Some(public_key);
                Ok(ServerCertVerified::assertion())
            }
            Err(error) => {
                self.authenticated_public_key = None;
                Err(error)
            }
        }
    }

    /// Verify and consume the TLS 1.3 CertificateVerify authentication state.
    pub(crate) fn verify_tls13_signature(
        &mut self,
        message: &[u8],
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // Clear every remaining authentication secret/state even on failure.
        self.auth_key = None;
        let public_key = self
            .authenticated_public_key
            .take()
            .ok_or_else(|| invalid_certificate(CertificateError::BadSignature))?;

        if dss.scheme != SignatureScheme::ED25519 {
            return Err(invalid_certificate(CertificateError::BadSignature));
        }

        signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
            .verify(message, dss.signature())
            .map_err(|_| invalid_certificate(CertificateError::BadSignature))?;

        Ok(HandshakeSignatureValid::assertion())
    }
}

#[derive(Clone, Copy)]
struct RealityAuthKeyLength;

impl hkdf::KeyType for RealityAuthKeyLength {
    fn len(&self) -> usize {
        REALITY_AUTH_KEY_LEN
    }
}

fn invalid_certificate(error: CertificateError) -> Error {
    Error::InvalidCertificate(error)
}

struct ParsedRealityCertificate<'a> {
    public_key: [u8; 32],
    signature_value: &'a [u8],
}

/// Parse just the security-relevant fields of a REALITY X.509 certificate.
///
/// This is a fixed-depth, allocation-free DER parser.  It accepts only
/// canonical definite lengths, the RFC 5280 Certificate/TBSCertificate field
/// order, Ed25519 AlgorithmIdentifiers with absent parameters, and byte-aligned
/// fixed-size public-key/signature BIT STRINGs.
fn parse_reality_certificate(
    certificate_der: &[u8],
) -> Result<ParsedRealityCertificate<'_>, DerError> {
    if certificate_der.is_empty() || certificate_der.len() > REALITY_CERT_MAX_LEN {
        return Err(DerError);
    }

    let mut document = DerReader::new(certificate_der);
    let certificate = document.read_expected(0x30)?;
    document.finish()?;

    let mut certificate = DerReader::new(certificate);
    let tbs_certificate = certificate.read_expected(0x30)?;
    let outer_algorithm = certificate.read_expected(0x30)?;
    parse_ed25519_algorithm(outer_algorithm)?;
    let signature_value = parse_bit_string(certificate.read_expected(0x03)?, 64)?;
    certificate.finish()?;

    let public_key = parse_tbs_certificate(tbs_certificate)?;
    Ok(ParsedRealityCertificate {
        public_key,
        signature_value,
    })
}

/// Exercise the strict REALITY certificate parser from the fuzz harness.
///
/// This is only reachable through the explicitly unstable
/// `crate::internal::fuzzing` namespace.
pub(crate) fn fuzz_reality_certificate(certificate_der: &[u8]) -> bool {
    parse_reality_certificate(certificate_der).is_ok()
}

fn parse_tbs_certificate(tbs_certificate: &[u8]) -> Result<[u8; 32], DerError> {
    let mut tbs = DerReader::new(tbs_certificate);

    if tbs.peek_tag() == Some(0xa0) {
        let mut version = DerReader::new(tbs.read_expected(0xa0)?);
        let version_number = version.read_expected(0x02)?;
        if version_number.len() != 1 || version_number[0] > 2 {
            return Err(DerError);
        }
        version.finish()?;
    }

    validate_positive_integer(tbs.read_expected(0x02)?)?;
    parse_ed25519_algorithm(tbs.read_expected(0x30)?)?;
    // Issuer and subject Names may be empty for Xray's ephemeral certificate.
    let _issuer = tbs.read_expected(0x30)?;
    parse_validity(tbs.read_expected(0x30)?)?;
    let _subject = tbs.read_expected(0x30)?;
    let public_key = parse_ed25519_spki(tbs.read_expected(0x30)?)?;

    // RFC 5280 optional fields must be ordered and may occur at most once.
    let mut last_optional_tag = 0u8;
    while let Some(tag) = tbs.peek_tag() {
        if !matches!(tag, 0x81 | 0x82 | 0xa3) || tag <= last_optional_tag {
            return Err(DerError);
        }
        last_optional_tag = tag;
        let _ = tbs.read_expected(tag)?;
    }
    tbs.finish()?;

    Ok(public_key)
}

fn parse_ed25519_spki(spki: &[u8]) -> Result<[u8; 32], DerError> {
    let mut spki = DerReader::new(spki);
    parse_ed25519_algorithm(spki.read_expected(0x30)?)?;
    let key_bytes = parse_bit_string(spki.read_expected(0x03)?, 32)?;
    spki.finish()?;

    key_bytes
        .try_into()
        .map_err(|_| DerError)
}

fn parse_ed25519_algorithm(algorithm: &[u8]) -> Result<(), DerError> {
    let mut algorithm = DerReader::new(algorithm);
    if algorithm.read_expected(0x06)? != ED25519_OID {
        return Err(DerError);
    }
    // RFC 8410 requires parameters to be absent for Ed25519.
    algorithm.finish()
}

fn parse_bit_string(bit_string: &[u8], bytes: usize) -> Result<&[u8], DerError> {
    if bit_string.len() != bytes.checked_add(1).ok_or(DerError)? || bit_string[0] != 0 {
        return Err(DerError);
    }
    Ok(&bit_string[1..])
}

fn parse_validity(validity: &[u8]) -> Result<(), DerError> {
    let mut validity = DerReader::new(validity);
    for _ in 0..2 {
        let tag = validity.peek_tag().ok_or(DerError)?;
        if !matches!(tag, 0x17 | 0x18) {
            return Err(DerError);
        }
        let time = validity.read_expected(tag)?;
        if time.is_empty() {
            return Err(DerError);
        }
    }
    validity.finish()
}

fn validate_positive_integer(integer: &[u8]) -> Result<(), DerError> {
    if integer.is_empty() || integer[0] & 0x80 != 0 {
        return Err(DerError);
    }
    if integer.len() > 1 && integer[0] == 0 && integer[1] & 0x80 == 0 {
        return Err(DerError);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct DerError;

struct DerReader<'a> {
    remaining: &'a [u8],
}

impl<'a> DerReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn peek_tag(&self) -> Option<u8> {
        self.remaining.first().copied()
    }

    fn read_expected(&mut self, expected_tag: u8) -> Result<&'a [u8], DerError> {
        let tag = *self.remaining.first().ok_or(DerError)?;
        // REALITY's certificate needs no high-tag-number DER values.
        if tag != expected_tag || tag & 0x1f == 0x1f {
            return Err(DerError);
        }
        self.remaining = &self.remaining[1..];

        let first_length = *self.remaining.first().ok_or(DerError)?;
        self.remaining = &self.remaining[1..];
        let length = if first_length & 0x80 == 0 {
            first_length as usize
        } else {
            let length_bytes = (first_length & 0x7f) as usize;
            if length_bytes == 0
                || length_bytes > size_of::<usize>()
                || self.remaining.len() < length_bytes
                || self.remaining[0] == 0
            {
                return Err(DerError);
            }

            let mut length = 0usize;
            for byte in &self.remaining[..length_bytes] {
                length = length.checked_shl(8).ok_or(DerError)?;
                length = length
                    .checked_add(*byte as usize)
                    .ok_or(DerError)?;
            }
            self.remaining = &self.remaining[length_bytes..];
            // Long-form length is non-canonical below 128.
            if length < 128 {
                return Err(DerError);
            }
            length
        };

        if self.remaining.len() < length {
            return Err(DerError);
        }
        let (value, rest) = self.remaining.split_at(length);
        self.remaining = rest;
        Ok(value)
    }

    fn finish(self) -> Result<(), DerError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(DerError)
        }
    }
}

/// A builder placeholder used only to advertise signature schemes in ClientHello.
///
/// The complete provider list is retained so a REALITY camouflage target can
/// select its ordinary certificate. Actual REALITY authentication is
/// connection-local and still requires Ed25519. Every verification method here
/// therefore fails closed if it is ever reached.
#[derive(Debug)]
struct FailClosedRealityVerifier {
    signature_schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for FailClosedRealityVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Err(invalid_certificate(CertificateError::UnknownIssuer))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(invalid_certificate(CertificateError::BadSignature))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(invalid_certificate(CertificateError::BadSignature))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_schemes.clone()
    }
}

pub(super) fn config_verifier(
    signature_schemes: Vec<SignatureScheme>,
) -> Arc<dyn ServerCertVerifier> {
    Arc::new(FailClosedRealityVerifier { signature_schemes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[derive(Debug)]
    struct NamedOnlyX25519;

    impl crate::crypto::SupportedKxGroup for NamedOnlyX25519 {
        fn start(&self) -> Result<alloc::boxed::Box<dyn crate::crypto::ActiveKeyExchange>, Error> {
            crate::crypto::ring::kx_group::X25519.start()
        }

        fn name(&self) -> crate::NamedGroup {
            crate::NamedGroup::X25519
        }
    }

    static NAMED_ONLY_X25519: NamedOnlyX25519 = NamedOnlyX25519;

    // Independent fixed vectors derived from RFC 7748/RFC 8032 inputs with
    // Xray's classic REALITY wire algorithm.
    const AUTH_SECRET_HEX: &str =
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    const AUTH_KEY_HEX: &str = "68e5a4d6fbfc0f93477d737fbdd45bd5f81578fbd172327b6db8e963e2ba4a3c";
    const SERVER_STATIC_PUBLIC_KEY_HEX: &str =
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const CLIENT_PUBLIC_KEY_HEX: &str =
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const CLIENT_HELLO_AAD_HEX: &str = concat!(
        "0100008c0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        "00000000000000000000000000000000000000000000000000000000000000000002130101000041002b",
        "0003020304000a00040002001d000d000400020807003300260024001d00208520f0098930a754748b7ddc",
        "b43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    );
    const ED25519_PUBLIC_KEY_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const CERT_HMAC_HEX: &str = concat!(
        "b393ce0d664a88657f0d1b8bef84cb8281b3f980e66c4d3bdb40aaf948bc0b67",
        "668fb1cff4e8517a58478e0430ac6253bd6f43b58706b8fca5e5fe1a4edc2259"
    );
    const CERTIFICATE_VERIFY_MESSAGE_HEX: &str = concat!(
        "2020202020202020202020202020202020202020202020202020202020202020",
        "2020202020202020202020202020202020202020202020202020202020202020",
        "544c5320312e332c2073657276657220436572746966696361746556657269667900",
        "f3a6f211a126138659a03d0963165e5cd8bacec77f10171baebcff3f965892e6"
    );
    const CERTIFICATE_VERIFY_SIGNATURE_HEX: &str = concat!(
        "6eab8d8a5f311f8e699f15851f9d395377259b0865c358b8b6f957f606dad483",
        "386564bf758304bcadf24c1c9900de20ca0cddfe65a3b169c5ecfc36b71aeb0f"
    );

    #[test]
    fn config_uses_fixed_short_id_storage() {
        let config = RealityClientConfig::new([7; 32], &[1, 2, 3], [4, 5, 6]).unwrap();
        assert_eq!(config.server_public_key(), &[7; 32]);
        assert_eq!(config.short_id(), &[1, 2, 3, 0, 0, 0, 0, 0]);
        assert_eq!(config.client_version(), [4, 5, 6]);
        assert_eq!(
            RealityClientConfig::new([0; 32], &[0; 9], [0; 3]).unwrap_err(),
            RealityConfigError::ShortIdTooLong
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn builder_requires_tls13_only_and_rejects_early_data() {
        use crate::ClientConfig;
        use crate::version::TLS13;

        let provider = Arc::new(crate::crypto::ring::default_provider());
        let reality = RealityClientConfig::new([7; 32], &[], [1, 2, 3]).unwrap();
        let default_versions = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap();
        assert!(
            default_versions
                .with_reality(reality.clone())
                .is_err()
        );

        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_reality(reality)
            .unwrap()
            .with_no_client_auth();
        assert!(config.reality_config.is_some());
        config.enable_early_data = true;
        let name = ServerName::try_from("example.com")
            .unwrap()
            .to_owned();
        assert!(crate::ClientConnection::new(Arc::new(config), name).is_err());
    }

    #[cfg(feature = "std")]
    #[test]
    fn builder_rejects_provider_without_reality_key_reuse() {
        use crate::ClientConfig;
        use crate::version::TLS13;

        let mut provider = crate::crypto::ring::default_provider();
        // The handshake selects the first TLS 1.3-capable group with this
        // name. A later capable duplicate must not let the builder accept an
        // earlier group which only claims the X25519 code point.
        provider.kx_groups = vec![&NAMED_ONLY_X25519, crate::crypto::ring::kx_group::X25519];
        let reality = RealityClientConfig::new([7; 32], &[], [1, 2, 3]).unwrap();
        let result = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_reality(reality);

        assert!(matches!(
            result,
            Err(Error::General(message))
                if message == "crypto provider does not support REALITY X25519 key reuse"
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn builder_rejects_provider_without_ed25519_verification() {
        use crate::ClientConfig;
        use crate::version::TLS13;

        let mut provider = crate::crypto::ring::default_provider();
        let mappings = provider
            .signature_verification_algorithms
            .mapping
            .iter()
            .copied()
            .filter(|(scheme, _)| *scheme != SignatureScheme::ED25519)
            .collect::<Vec<_>>();
        provider
            .signature_verification_algorithms
            .mapping = mappings.leak();
        assert!(
            !provider
                .signature_verification_algorithms
                .supported_schemes()
                .contains(&SignatureScheme::ED25519)
        );

        let reality = RealityClientConfig::new([7; 32], &[], [1, 2, 3]).unwrap();
        let result = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_reality(reality);

        assert!(matches!(
            result,
            Err(Error::General(message))
                if message == "crypto provider does not support REALITY Ed25519 verification"
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn low_order_server_public_key_fails_before_client_hello() {
        use crate::ClientConfig;
        use crate::version::TLS13;

        let provider = Arc::new(crate::crypto::ring::default_provider());
        let reality = RealityClientConfig::new([0; 32], &[], [1, 2, 3]).unwrap();
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_reality(reality)
            .unwrap()
            .with_no_client_auth();
        let name = ServerName::try_from("example.com")
            .unwrap()
            .to_owned();
        assert!(crate::ClientConnection::new(Arc::new(config), name).is_err());
    }

    #[test]
    fn xray_x25519_shared_secret_vector() {
        let private_key = x25519_dalek::StaticSecret::from(decode_fixed(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let public_key = x25519_dalek::PublicKey::from(&private_key);
        assert_eq!(public_key.to_bytes(), decode_fixed(CLIENT_PUBLIC_KEY_HEX));

        let server_public_key =
            x25519_dalek::PublicKey::from(decode_fixed(SERVER_STATIC_PUBLIC_KEY_HEX));
        let shared_secret = private_key.diffie_hellman(&server_public_key);
        assert!(shared_secret.was_contributory());
        assert_eq!(shared_secret.to_bytes(), decode_fixed(AUTH_SECRET_HEX));
    }

    #[test]
    fn xray_classic_session_id_vector() {
        let server_public_key = decode_fixed(SERVER_STATIC_PUBLIC_KEY_HEX);
        let config = Arc::new(
            RealityClientConfig::new(
                server_public_key,
                &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
                [0x1a, 0x07, 0x0b],
            )
            .unwrap(),
        );
        let auth_secret: [u8; 32] = decode_fixed(AUTH_SECRET_HEX);
        let mut state = RealityHandshakeState::new(config, SharedSecret::from(&auth_secret[..]));
        let random =
            decode_fixed("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let aad = hex::decode(CLIENT_HELLO_AAD_HEX).unwrap();
        assert_eq!(aad.len(), 144);
        let expected =
            decode_fixed("1619cad10c8b0025361002d9a21507bfb3d2d9e4e1f7b7db713ef292496dac86");
        let expected_auth_key = decode_fixed(AUTH_KEY_HEX);

        assert_eq!(
            state
                .seal_session_id(&aad, &random, 0x0102_0304)
                .unwrap(),
            expected
        );
        assert_eq!(state.auth_key.as_deref(), Some(&expected_auth_key));
        assert!(
            state
                .seal_session_id(&aad, &random, 0x0102_0304)
                .is_err()
        );
    }

    #[test]
    fn certificate_and_certificate_verify_vectors() {
        let public_key = decode_fixed(ED25519_PUBLIC_KEY_HEX);
        let certificate_hmac = decode_fixed(CERT_HMAC_HEX);
        let auth_key = decode_fixed(AUTH_KEY_HEX);
        let certificate = reality_certificate(&public_key, &certificate_hmac);
        let parsed = parse_reality_certificate(&certificate).unwrap();
        assert_eq!(parsed.public_key, public_key);
        assert_eq!(parsed.signature_value, certificate_hmac);

        let config = Arc::new(RealityClientConfig::new([0; 32], &[], [0; 3]).unwrap());
        let mut state = RealityHandshakeState::new(config, SharedSecret::from(&[][..]));
        state.auth_secret = None;
        state.auth_key = Some(Zeroizing::new(auth_key));
        state
            .verify_server_certificate(&CertificateDer::from(certificate), &[])
            .unwrap();
        assert!(state.auth_key.is_none());

        let message = hex::decode(CERTIFICATE_VERIFY_MESSAGE_HEX).unwrap();
        assert_eq!(message.len(), 130);
        let signature = hex::decode(CERTIFICATE_VERIFY_SIGNATURE_HEX).unwrap();
        let dss = DigitallySignedStruct::new(SignatureScheme::ED25519, signature);
        state
            .verify_tls13_signature(&message, &dss)
            .unwrap();
        assert!(state.authenticated_public_key.is_none());
        assert!(
            state
                .verify_tls13_signature(&message, &dss)
                .is_err()
        );
    }

    #[test]
    fn certificate_authentication_is_fail_closed() {
        let public_key = decode_fixed(ED25519_PUBLIC_KEY_HEX);
        let certificate_hmac = decode_fixed(CERT_HMAC_HEX);
        let auth_key = decode_fixed(AUTH_KEY_HEX);
        let certificate = reality_certificate(&public_key, &certificate_hmac);
        let config = Arc::new(RealityClientConfig::new([0; 32], &[], [0; 3]).unwrap());

        let mut wrong_hmac = state_with_auth_key(config.clone(), auth_key);
        let mut changed = certificate.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(
            wrong_hmac
                .verify_server_certificate(&CertificateDer::from(changed), &[])
                .is_err()
        );
        assert!(wrong_hmac.auth_key.is_none());

        let mut intermediates = state_with_auth_key(config.clone(), auth_key);
        assert!(
            intermediates
                .verify_server_certificate(
                    &CertificateDer::from(certificate.clone()),
                    &[CertificateDer::from(vec![0x30, 0x00])],
                )
                .is_err()
        );

        let mut missing_key = RealityHandshakeState::new(config, SharedSecret::from(&[][..]));
        assert!(
            missing_key
                .verify_server_certificate(&CertificateDer::from(certificate), &[])
                .is_err()
        );
    }

    #[test]
    fn strict_der_parser_rejects_truncation_and_malformed_forms() {
        let public_key = decode_fixed(ED25519_PUBLIC_KEY_HEX);
        let certificate_hmac = decode_fixed(CERT_HMAC_HEX);
        let certificate = reality_certificate(&public_key, &certificate_hmac);
        for length in 0..certificate.len() {
            assert!(parse_reality_certificate(&certificate[..length]).is_err());
        }

        let mut trailing = certificate.clone();
        trailing.push(0);
        assert!(parse_reality_certificate(&trailing).is_err());

        let mut indefinite = certificate.clone();
        indefinite[1] = 0x80;
        assert!(parse_reality_certificate(&indefinite).is_err());

        let mut bad_public_key_algorithm = certificate.clone();
        let oid = bad_public_key_algorithm
            .windows(ED25519_OID.len())
            .position(|window| window == ED25519_OID)
            .unwrap();
        // The first OID is TBSCertificate.signature; the second is SPKI.
        let second_oid = bad_public_key_algorithm[oid + ED25519_OID.len()..]
            .windows(ED25519_OID.len())
            .position(|window| window == ED25519_OID)
            .unwrap()
            + oid
            + ED25519_OID.len();
        bad_public_key_algorithm[second_oid] ^= 1;
        assert!(parse_reality_certificate(&bad_public_key_algorithm).is_err());

        let mut non_byte_aligned_signature = certificate;
        let signature = non_byte_aligned_signature
            .windows(certificate_hmac.len())
            .position(|window| window == certificate_hmac)
            .unwrap();
        non_byte_aligned_signature[signature - 1] = 1;
        assert!(parse_reality_certificate(&non_byte_aligned_signature).is_err());
    }

    #[test]
    fn placeholder_verifier_never_authenticates() {
        let signature_schemes = vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ];
        let verifier = config_verifier(signature_schemes.clone());
        assert_eq!(verifier.supported_verify_schemes(), signature_schemes);
        let name = ServerName::try_from("example.com").unwrap();
        assert!(
            verifier
                .verify_server_cert(
                    &CertificateDer::from(vec![0x30, 0x00]),
                    &[],
                    &name,
                    &[],
                    UnixTime::since_unix_epoch(core::time::Duration::ZERO),
                )
                .is_err()
        );
    }

    fn state_with_auth_key(
        config: Arc<RealityClientConfig>,
        auth_key: [u8; 32],
    ) -> RealityHandshakeState {
        let mut state = RealityHandshakeState::new(config, SharedSecret::from(&[][..]));
        state.auth_secret = None;
        state.auth_key = Some(Zeroizing::new(auth_key));
        state
    }

    fn decode_fixed<const N: usize>(encoded: &str) -> [u8; N] {
        hex::decode(encoded)
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn reality_certificate(public_key: &[u8; 32], signature_value: &[u8; 64]) -> Vec<u8> {
        let algorithm = der(0x30, &der(0x06, ED25519_OID));
        let version = der(0xa0, &der(0x02, &[2]));
        let serial = der(0x02, &[0]);
        let empty_name = der(0x30, &[]);
        let mut validity_value = der(0x17, b"000101000000Z");
        validity_value.extend_from_slice(&der(0x17, b"491231235959Z"));
        let validity = der(0x30, &validity_value);
        let mut public_key_bits = vec![0];
        public_key_bits.extend_from_slice(public_key);
        let mut spki_value = algorithm.clone();
        spki_value.extend_from_slice(&der(0x03, &public_key_bits));
        let spki = der(0x30, &spki_value);

        let mut tbs_value = version;
        tbs_value.extend_from_slice(&serial);
        tbs_value.extend_from_slice(&algorithm);
        tbs_value.extend_from_slice(&empty_name);
        tbs_value.extend_from_slice(&validity);
        tbs_value.extend_from_slice(&empty_name);
        tbs_value.extend_from_slice(&spki);

        let mut certificate_value = der(0x30, &tbs_value);
        certificate_value.extend_from_slice(&algorithm);
        let mut signature_bits = vec![0];
        signature_bits.extend_from_slice(signature_value);
        certificate_value.extend_from_slice(&der(0x03, &signature_bits));
        der(0x30, &certificate_value)
    }

    fn der(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag];
        if value.len() < 128 {
            encoded.push(value.len() as u8);
        } else {
            assert!(value.len() <= u8::MAX as usize);
            encoded.extend_from_slice(&[0x81, value.len() as u8]);
        }
        encoded.extend_from_slice(value);
        encoded
    }
}
