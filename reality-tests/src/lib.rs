//! Test-only hybrid provider. Not a production cryptography dependency decision.

use ml_kem::ml_kem_768::{Ciphertext, DecapsulationKey};
use ml_kem::{Decapsulate, KeyExport, Seed};
use rustls::crypto::ring::kx_group::X25519;
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};
use zeroize::Zeroizing;

#[derive(Debug)]
pub struct HybridGroup;

pub static HYBRID: HybridGroup = HybridGroup;

impl SupportedKxGroup for HybridGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        Ok(Box::new(HybridExchange::new(X25519.start()?)?))
    }

    fn supports_reality(&self) -> bool {
        true
    }

    fn start_reality(
        &self,
        server_public_key: &[u8; 32],
    ) -> Result<(Box<dyn ActiveKeyExchange>, SharedSecret), Error> {
        let (classical, authentication) = X25519.start_reality(server_public_key)?;
        Ok((Box::new(HybridExchange::new(classical)?), authentication))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct HybridExchange {
    classical: Box<dyn ActiveKeyExchange>,
    mlkem: DecapsulationKey,
    public_key: Vec<u8>,
}

impl HybridExchange {
    fn new(classical: Box<dyn ActiveKeyExchange>) -> Result<Self, Error> {
        let mut seed = Zeroizing::new(Seed::default());
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(seed.as_mut_slice())?;
        let mlkem = DecapsulationKey::from_seed(*seed);
        let mut public_key = mlkem
            .encapsulation_key()
            .to_bytes()
            .to_vec();
        public_key.extend_from_slice(classical.pub_key());
        Ok(Self {
            classical,
            mlkem,
            public_key,
        })
    }
}

impl ActiveKeyExchange for HybridExchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        if peer.len() != 1120 {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        let ciphertext =
            Ciphertext::try_from(&peer[..1088]).map_err(|_| PeerMisbehaved::InvalidKeyShare)?;
        let pq_secret = Zeroizing::new(self.mlkem.decapsulate(&ciphertext));
        let classical = self.classical.complete(&peer[1088..])?;
        let mut combined = Zeroizing::new([0u8; 64]);
        combined[..32].copy_from_slice(pq_secret.as_slice());
        combined[32..].copy_from_slice(classical.secret_bytes());
        Ok(SharedSecret::from(combined.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public_key
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((NamedGroup::X25519, self.classical.pub_key()))
    }

    fn complete_hybrid_component(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        self.classical.complete(peer)
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use ml_kem::ml_kem_768::EncapsulationKey;
    use ml_kem::{Encapsulate, TryKeyInit};
    use rustls::crypto::SupportedKxGroup;
    use rustls::crypto::ring::kx_group::X25519;
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::HYBRID;

    #[test]
    fn hybrid_exchange_authenticates_with_the_classical_key_sent_in_its_keyshare() {
        // Static fixture server key, never a production credential.
        let server_private = StaticSecret::from([0x67; 32]);
        let server_public = PublicKey::from(&server_private);
        let (client, auth) = HYBRID
            .start_reality(server_public.as_bytes())
            .unwrap();
        let client_public = client.pub_key();
        assert_eq!(client_public.len(), 1216);

        let classical_public: [u8; 32] = client_public[1184..]
            .try_into()
            .unwrap();
        assert_eq!(
            auth.secret_bytes(),
            server_private
                .diffie_hellman(&PublicKey::from(classical_public))
                .as_bytes()
        );

        let mlkem_public = EncapsulationKey::new_from_slice(&client_public[..1184]).unwrap();
        let (ciphertext, pq_secret) = mlkem_public.encapsulate();
        let server_classical = X25519.start().unwrap();
        let mut server_share = ciphertext.to_vec();
        server_share.extend_from_slice(server_classical.pub_key());
        assert_eq!(server_share.len(), 1120);
        let server_secret = server_classical
            .complete(&classical_public)
            .unwrap();
        let shared = client.complete(&server_share).unwrap();
        assert_eq!(shared.secret_bytes().len(), 64);
        assert_eq!(&shared.secret_bytes()[..32], pq_secret.as_slice());
        assert_eq!(&shared.secret_bytes()[32..], server_secret.secret_bytes());
    }

    #[test]
    fn provider_can_explicitly_allow_classical_fallback_using_the_same_public_key() {
        let (client, _) = HYBRID
            .start_reality(&PublicKey::from(&StaticSecret::from([0x67; 32])).to_bytes())
            .unwrap();
        let (group, public_key) = client.hybrid_component().unwrap();
        assert_eq!(group, rustls::NamedGroup::X25519);
        assert_eq!(public_key, &client.pub_key()[1184..]);
        let server = X25519.start().unwrap();
        let server_public = server.pub_key().to_vec();
        let expected = server.complete(public_key).unwrap();
        let actual = client
            .complete_hybrid_component(&server_public)
            .unwrap();
        assert_eq!(actual.secret_bytes(), expected.secret_bytes());
    }

    #[test]
    fn hybrid_rejects_malformed_and_low_order_server_keyshares() {
        for length in [0, 32, 1088, 1119, 1120, 1121, 1216] {
            let client = HYBRID.start().unwrap();
            // The length-correct case still has an all-zero, low-order
            // X25519 key. Arbitrary KEM ciphertext must not mask that error.
            assert!(matches!(
                client.complete(&vec![0; length]),
                Err(rustls::Error::PeerMisbehaved(
                    rustls::PeerMisbehaved::InvalidKeyShare
                ))
            ));
        }
    }

    #[test]
    fn hybrid_reality_rejects_a_low_order_authentication_key() {
        assert!(matches!(
            HYBRID.start_reality(&[0; 32]),
            Err(rustls::Error::PeerMisbehaved(
                rustls::PeerMisbehaved::InvalidKeyShare
            ))
        ));
    }
}
