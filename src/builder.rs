// Typestate builder for WinrmClient.
//
// Provides a compile-time-safe builder pattern that requires credentials
// to be set before building the client.

use std::panic::AssertUnwindSafe;

use crate::client::WinrmClient;
use crate::config::{WinrmConfig, WinrmCredentials};
use crate::error::WinrmError;

/// Typestate marker: credentials have not yet been provided.
pub struct NeedsCredentials;
/// Typestate marker: all required fields are set and [`build`](WinrmClientBuilder::build) can be called.
pub struct Ready;

/// Builder for [`WinrmClient`] with compile-time state tracking.
///
/// Ensures that credentials are always provided before the client is built.
///
/// # Example
/// ```no_run
/// use winrm_rs::{WinrmClientBuilder, WinrmConfig, WinrmCredentials};
///
/// let client = WinrmClientBuilder::new(WinrmConfig::default())
///     .credentials(WinrmCredentials::new("admin", "pass", ""))
///     .build()
///     .unwrap();
/// ```
pub struct WinrmClientBuilder<S = NeedsCredentials> {
    config: WinrmConfig,
    credentials: Option<WinrmCredentials>,
    // `AssertUnwindSafe` keeps the builder `UnwindSafe` and `RefUnwindSafe`
    // as it was before the hook existed; the hook is never called here.
    before_send: Option<AssertUnwindSafe<crate::transport::BeforeSend>>,
    options: crate::transport::TransportOptions,
    _state: std::marker::PhantomData<S>,
}

impl WinrmClientBuilder<NeedsCredentials> {
    /// Create a new builder with the given configuration.
    pub fn new(config: WinrmConfig) -> Self {
        Self {
            config,
            credentials: None,
            before_send: None,
            options: crate::transport::TransportOptions::default(),
            _state: std::marker::PhantomData,
        }
    }

    /// Set the authentication credentials, transitioning to the `Ready` state.
    pub fn credentials(self, creds: WinrmCredentials) -> WinrmClientBuilder<Ready> {
        WinrmClientBuilder {
            config: self.config,
            credentials: Some(creds),
            before_send: self.before_send,
            options: self.options,
            _state: std::marker::PhantomData,
        }
    }
}

impl WinrmClientBuilder<Ready> {
    /// Install a hook that runs before every SOAP request this client sends,
    /// and before each retry of one. Return `true` to send, `false` to refuse:
    /// a refused request sends nothing and fails with [`WinrmError::Cancelled`].
    ///
    /// It runs for every authentication method, before anything is sealed or
    /// put on the wire, so a refusal never disturbs an NTLM or Kerberos session.
    /// One high-level call issues several requests (`run_command`: Create,
    /// Execute, one Receive per poll, Signal, Delete) and the hook sees each of
    /// them. A refusal also blocks the clean-up requests; the remote shell then
    /// stays open until the server drops it.
    ///
    /// The hook is called from async code, possibly from several tasks at once:
    /// keep it short and never block in it (no blocking lock, no I/O). A panic
    /// in the hook reaches the caller.
    ///
    /// # Example
    /// ```no_run
    /// use std::sync::Arc;
    /// use std::sync::atomic::{AtomicU32, Ordering};
    /// use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};
    ///
    /// // Send at most 100 requests.
    /// let sent = Arc::new(AtomicU32::new(0));
    /// let client = WinrmClient::builder(WinrmConfig::default())
    ///     .credentials(WinrmCredentials::new("admin", "pass", ""))
    ///     .before_send(move || sent.fetch_add(1, Ordering::Relaxed) < 100)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn before_send(mut self, hook: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        self.before_send = Some(AssertUnwindSafe(std::sync::Arc::new(hook)));
        self
    }

    /// Ignore proxies set in the environment (`HTTP_PROXY`, `HTTPS_PROXY`,
    /// `ALL_PROXY`, their lowercase forms, and `NO_PROXY`): connect to the
    /// WinRM host directly unless [`WinrmConfig::proxy`] names a proxy.
    ///
    /// By default the client honours them, like any reqwest client. With
    /// `accept_invalid_certs` that lets whatever proxy the environment names
    /// sit in the middle of every WinRM exchange without the client noticing.
    ///
    /// # Example
    /// ```no_run
    /// use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};
    ///
    /// let client = WinrmClient::builder(WinrmConfig::default())
    ///     .credentials(WinrmCredentials::new("admin", "pass", ""))
    ///     .no_env_proxy()
    ///     .build()
    ///     .unwrap();
    /// ```
    #[must_use]
    pub fn no_env_proxy(mut self) -> Self {
        self.options.no_env_proxy = true;
        self
    }

    /// Pin `host` to the end-entity certificate whose SHA-256 is `sha256`:
    /// a TLS handshake with `host` presenting any other certificate fails
    /// before anything is sent on that connection, credentials included.
    /// Other hosts are not affected. `host` is matched against the host
    /// passed to each call (IP literals in any notation, names
    /// case-insensitively).
    ///
    /// Meant for [`WinrmConfig::accept_invalid_certs`] setups, where nothing
    /// else ties a host to its certificate: pin on first use with
    /// [`WinrmClient::server_cert_sha256`]. Pinning again for the same host
    /// replaces the pin.
    #[must_use]
    pub fn pin_server_cert(mut self, host: &str, sha256: [u8; 32]) -> Self {
        self.options
            .cert_pins
            .insert(crate::tls::host_key(host), sha256);
        self
    }

    /// Build the [`WinrmClient`].
    ///
    /// Returns [`WinrmError::Http`] if the underlying HTTP client cannot be
    /// constructed.
    pub fn build(self) -> Result<WinrmClient, WinrmError> {
        // SAFETY: The typestate pattern guarantees that `credentials` is
        // `Some` when `build()` is callable (state = Ready).
        let mut client = WinrmClient::with_options(
            self.config,
            self.credentials
                .expect("typestate guarantees credentials are set"),
            self.options,
        )?;
        if let Some(hook) = self.before_send {
            client.transport.set_before_send(hook.0);
        }
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Holding a hook must not cost the builder its auto traits: losing them
    /// is a breaking change.
    #[test]
    fn builder_stays_unwind_safe() {
        fn assert_unwind_safe<T: std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {}
        assert_unwind_safe::<WinrmClientBuilder<NeedsCredentials>>();
        assert_unwind_safe::<WinrmClientBuilder<Ready>>();
    }

    #[test]
    fn no_env_proxy_reaches_the_transport() {
        let creds = || WinrmCredentials::new("admin", "pass", "");
        let default = WinrmClientBuilder::new(WinrmConfig::default())
            .credentials(creds())
            .build()
            .unwrap();
        assert!(!default.transport.options().no_env_proxy);
        let opted_out = WinrmClientBuilder::new(WinrmConfig::default())
            .credentials(creds())
            .no_env_proxy()
            .build()
            .unwrap();
        assert!(opted_out.transport.options().no_env_proxy);
    }

    #[test]
    fn pin_server_cert_reaches_the_transport_keyed_like_the_handshake() {
        let client = WinrmClientBuilder::new(WinrmConfig::default())
            .credentials(WinrmCredentials::new("admin", "pass", ""))
            .pin_server_cert("Win01.Corp", [7; 32])
            .build()
            .unwrap();
        assert_eq!(
            client.transport.options().cert_pins.get("win01.corp"),
            Some(&[7; 32])
        );
        assert_eq!(client.server_cert_sha256("win01.corp"), None);
    }

    #[test]
    fn builder_creates_client() {
        let client = WinrmClientBuilder::new(WinrmConfig::default())
            .credentials(WinrmCredentials::new("admin", "pass", ""))
            .build()
            .unwrap();
        // Verify the client was constructed (endpoint uses config values)
        assert_eq!(client.endpoint("test-host"), "http://test-host:5985/wsman");
    }

    #[test]
    fn builder_preserves_custom_config() {
        let config = WinrmConfig {
            port: 5986,
            use_tls: true,
            max_envelope_size: 512_000,
            ..Default::default()
        };
        let client = WinrmClientBuilder::new(config)
            .credentials(WinrmCredentials::new("user", "pw", "DOM"))
            .build()
            .unwrap();
        assert_eq!(client.endpoint("srv"), "https://srv:5986/wsman");
        assert_eq!(client.config().max_envelope_size, 512_000);
    }

    #[test]
    fn builder_via_client_static_method() {
        let client = WinrmClient::builder(WinrmConfig::default())
            .credentials(WinrmCredentials::new("admin", "pass", ""))
            .build()
            .unwrap();
        assert_eq!(client.endpoint("host"), "http://host:5985/wsman");
    }
}
