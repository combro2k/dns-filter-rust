use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// A thread-safe, lock-free TLS certificate resolver that supports atomic
/// hot-swapping of certificates at runtime.
///
/// Implements [`ResolvesServerCert`] so it can be used directly with
/// [`rustls::ServerConfig`]. On each TLS handshake, the current certificate
/// is read via `arc_swap::ArcSwap` — no locks are held during reads.
///
/// When ACME renews a certificate, call [`SharedCertResolver::update`] to
/// atomically swap in the new cert. All subsequent TLS connections will use
/// the updated certificate immediately.
pub struct SharedCertResolver {
    certified_key: ArcSwap<CertifiedKey>,
}

impl SharedCertResolver {
    /// Creates a new resolver with the given initial certificate and key.
    pub fn new(certified_key: Arc<CertifiedKey>) -> Self {
        Self {
            certified_key: ArcSwap::new(certified_key),
        }
    }

    /// Atomically replaces the current certificate with a new one.
    /// Subsequent TLS handshakes will use the new certificate.
    pub fn update(&self, certified_key: Arc<CertifiedKey>) {
        self.certified_key.store(certified_key);
        tracing::info!("TLS certificate updated (hot-reload)");
    }

    /// Returns a clone of the current `Arc<CertifiedKey>`.
    pub fn current(&self) -> Arc<CertifiedKey> {
        self.certified_key.load_full()
    }
}

impl ResolvesServerCert for SharedCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.certified_key.load_full())
    }
}

impl std::fmt::Debug for SharedCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedCertResolver")
            .field("has_cert", &true)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    fn make_test_certified_key() -> Arc<CertifiedKey> {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::default()
            .self_signed(&key_pair)
            .unwrap();

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der().to_vec()));
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der).unwrap();

        Arc::new(CertifiedKey::new(vec![cert_der], signing_key))
    }

    #[test]
    fn test_current_returns_initial() {
        let key = make_test_certified_key();
        let resolver = SharedCertResolver::new(Arc::clone(&key));
        assert!(Arc::ptr_eq(&resolver.current(), &key));
    }

    #[test]
    fn test_update_swaps_cert() {
        let key1 = make_test_certified_key();
        let key2 = make_test_certified_key();
        let resolver = SharedCertResolver::new(Arc::clone(&key1));

        assert!(Arc::ptr_eq(&resolver.current(), &key1));
        resolver.update(Arc::clone(&key2));
        assert!(Arc::ptr_eq(&resolver.current(), &key2));
        assert!(!Arc::ptr_eq(&resolver.current(), &key1));
    }

    #[test]
    fn test_concurrent_reads_during_update() {
        use std::thread;

        let key1 = make_test_certified_key();
        let resolver = Arc::new(SharedCertResolver::new(Arc::clone(&key1)));

        let resolver_clone = Arc::clone(&resolver);
        let handle = thread::spawn(move || {
            for _ in 0..1000 {
                let _ = resolver_clone.current();
            }
        });

        // Update while reader thread is active
        for _ in 0..100 {
            let new_key = make_test_certified_key();
            resolver.update(new_key);
        }

        handle.join().unwrap();
    }
}
