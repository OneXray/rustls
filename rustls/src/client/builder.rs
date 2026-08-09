use alloc::vec::Vec;
use core::marker::PhantomData;

use pki_types::{CertificateDer, PrivateKeyDer};

use super::client_conn::Resumption;
use crate::builder::{ConfigBuilder, WantsVerifier};
#[cfg(feature = "reality")]
use crate::client::reality::{RealityClientConfig, config_verifier};
use crate::client::{ClientConfig, EchMode, ResolvesClientCert, handy};
#[cfg(feature = "reality")]
use crate::enums::ProtocolVersion;
use crate::error::Error;
use crate::key_log::NoKeyLog;
use crate::sign::{CertifiedKey, SingleCertAndKey};
use crate::sync::Arc;
use crate::versions::TLS13;
use crate::webpki::{self, WebPkiServerVerifier};
#[cfg(feature = "reality")]
use crate::{NamedGroup, SignatureScheme};
use crate::{WantsVersions, compress, verify, versions};

impl ConfigBuilder<ClientConfig, WantsVersions> {
    /// Enable Encrypted Client Hello (ECH) in the given mode.
    ///
    /// This implicitly selects TLS 1.3 as the only supported protocol version to meet the
    /// requirement to support ECH.
    ///
    /// The `ClientConfig` that will be produced by this builder will be specific to the provided
    /// [`crate::client::EchConfig`] and may not be appropriate for all connections made by the program.
    /// In this case the configuration should only be shared by connections intended for domains
    /// that offer the provided [`crate::client::EchConfig`] in their DNS zone.
    pub fn with_ech(
        self,
        mode: EchMode,
    ) -> Result<ConfigBuilder<ClientConfig, WantsVerifier>, Error> {
        let mut res = self.with_protocol_versions(&[&TLS13][..])?;
        res.state.client_ech_mode = Some(mode);
        Ok(res)
    }
}

impl ConfigBuilder<ClientConfig, WantsVerifier> {
    /// Choose how to verify server certificates.
    ///
    /// Using this function does not configure revocation.  If you wish to
    /// configure revocation, instead use:
    ///
    /// ```diff
    /// - .with_root_certificates(root_store)
    /// + .with_webpki_verifier(
    /// +   WebPkiServerVerifier::builder_with_provider(root_store, crypto_provider)
    /// +   .with_crls(...)
    /// +   .build()?
    /// + )
    /// ```
    pub fn with_root_certificates(
        self,
        root_store: impl Into<Arc<webpki::RootCertStore>>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        let algorithms = self
            .provider
            .signature_verification_algorithms;
        self.with_webpki_verifier(
            WebPkiServerVerifier::new_without_revocation(root_store, algorithms).into(),
        )
    }

    /// Choose how to verify server certificates using a webpki verifier.
    ///
    /// See [`webpki::WebPkiServerVerifier::builder`] and
    /// [`webpki::WebPkiServerVerifier::builder_with_provider`] for more information.
    pub fn with_webpki_verifier(
        self,
        verifier: Arc<WebPkiServerVerifier>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        ConfigBuilder {
            state: WantsClientCert {
                versions: self.state.versions,
                verifier,
                client_ech_mode: self.state.client_ech_mode,
                #[cfg(feature = "reality")]
                reality_config: None,
            },
            provider: self.provider,
            time_provider: self.time_provider,
            side: PhantomData,
        }
    }

    /// Use Xray-compatible REALITY authentication for this client.
    ///
    /// REALITY is a complete, fail-closed server authentication policy and
    /// therefore replaces the normal WebPKI verifier. It requires a TLS 1.3
    /// only builder with X25519 available and cannot be combined with ECH.
    #[cfg(feature = "reality")]
    pub fn with_reality(
        self,
        reality_config: RealityClientConfig,
    ) -> Result<ConfigBuilder<ClientConfig, WantsClientCert>, Error> {
        if !self
            .state
            .versions
            .contains(ProtocolVersion::TLSv1_3)
            || self
                .state
                .versions
                .contains(ProtocolVersion::TLSv1_2)
        {
            return Err(Error::General(
                "REALITY requires TLS 1.3 as the only protocol version".into(),
            ));
        }
        if self.state.client_ech_mode.is_some() {
            return Err(Error::General(
                "REALITY cannot be combined with encrypted client hello".into(),
            ));
        }
        let reality_group = self
            .provider
            .kx_groups
            .iter()
            .copied()
            .find(|group| {
                group.usable_for_version(ProtocolVersion::TLSv1_3)
                    && group.name() == NamedGroup::X25519
            });
        if !matches!(reality_group, Some(group) if group.supports_reality()) {
            return Err(Error::General(
                "crypto provider does not support REALITY X25519 key reuse".into(),
            ));
        }
        let signature_schemes = self
            .provider
            .signature_verification_algorithms
            .supported_schemes();
        if !signature_schemes.contains(&SignatureScheme::ED25519) {
            return Err(Error::General(
                "crypto provider does not support REALITY Ed25519 verification".into(),
            ));
        }

        Ok(ConfigBuilder {
            state: WantsClientCert {
                versions: self.state.versions,
                verifier: config_verifier(signature_schemes),
                client_ech_mode: None,
                reality_config: Some(Arc::new(reality_config)),
            },
            provider: self.provider,
            time_provider: self.time_provider,
            side: PhantomData,
        })
    }

    /// Access configuration options whose use is dangerous and requires
    /// extra care.
    pub fn dangerous(self) -> danger::DangerousClientConfigBuilder {
        danger::DangerousClientConfigBuilder { cfg: self }
    }
}

/// Container for unsafe APIs
pub(super) mod danger {
    use core::marker::PhantomData;

    use crate::client::WantsClientCert;
    use crate::sync::Arc;
    use crate::{ClientConfig, ConfigBuilder, WantsVerifier, verify};

    /// Accessor for dangerous configuration options.
    #[derive(Debug)]
    pub struct DangerousClientConfigBuilder {
        /// The underlying ClientConfigBuilder
        pub cfg: ConfigBuilder<ClientConfig, WantsVerifier>,
    }

    impl DangerousClientConfigBuilder {
        /// Set a custom certificate verifier.
        pub fn with_custom_certificate_verifier(
            self,
            verifier: Arc<dyn verify::ServerCertVerifier>,
        ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
            ConfigBuilder {
                state: WantsClientCert {
                    versions: self.cfg.state.versions,
                    verifier,
                    client_ech_mode: self.cfg.state.client_ech_mode,
                    #[cfg(feature = "reality")]
                    reality_config: None,
                },
                provider: self.cfg.provider,
                time_provider: self.cfg.time_provider,
                side: PhantomData,
            }
        }
    }
}

/// A config builder state where the caller needs to supply whether and how to provide a client
/// certificate.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone)]
pub struct WantsClientCert {
    versions: versions::EnabledVersions,
    verifier: Arc<dyn verify::ServerCertVerifier>,
    client_ech_mode: Option<EchMode>,
    #[cfg(feature = "reality")]
    reality_config: Option<Arc<RealityClientConfig>>,
}

impl ConfigBuilder<ClientConfig, WantsClientCert> {
    /// Sets a single certificate chain and matching private key for use
    /// in client authentication.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded private key as PKCS#1, PKCS#8, or SEC1. The
    /// `aws-lc-rs` and `ring` [`CryptoProvider`][crate::CryptoProvider]s support
    /// all three encodings, but other `CryptoProviders` may not.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn with_client_auth_cert(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<ClientConfig, Error> {
        let certified_key = CertifiedKey::from_der(cert_chain, key_der, &self.provider)?;
        Ok(self.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key))))
    }

    /// Do not support client auth.
    pub fn with_no_client_auth(self) -> ClientConfig {
        self.with_client_cert_resolver(Arc::new(handy::FailResolveClientCert {}))
    }

    /// Sets a custom [`ResolvesClientCert`].
    pub fn with_client_cert_resolver(
        self,
        client_auth_cert_resolver: Arc<dyn ResolvesClientCert>,
    ) -> ClientConfig {
        #[cfg(feature = "tls12")]
        let require_ems = self.provider.fips();

        #[cfg(feature = "reality")]
        let resumption = if self.state.reality_config.is_some() {
            Resumption::disabled()
        } else {
            Resumption::default()
        };
        #[cfg(not(feature = "reality"))]
        let resumption = Resumption::default();

        ClientConfig {
            provider: self.provider,
            alpn_protocols: Vec::new(),
            check_selected_alpn: true,
            resumption,
            max_fragment_size: None,
            client_auth_cert_resolver,
            versions: self.state.versions,
            enable_sni: true,
            verifier: self.state.verifier,
            key_log: Arc::new(NoKeyLog {}),
            enable_secret_extraction: false,
            enable_early_data: false,
            #[cfg(feature = "tls12")]
            require_ems,
            time_provider: self.time_provider,
            cert_compressors: compress::default_cert_compressors().to_vec(),
            cert_compression_cache: Arc::new(compress::CompressionCache::default()),
            cert_decompressors: compress::default_cert_decompressors().to_vec(),
            ech_mode: self.state.client_ech_mode,
            #[cfg(feature = "reality")]
            reality_config: self.state.reality_config,
            send_ticket_request: None,
        }
    }
}
