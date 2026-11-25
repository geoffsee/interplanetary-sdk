use super::Bytes;
use std::fmt;

/// Error kind categories for the SDK
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    /// Invalid configuration parameter
    InvalidConfig,
    /// Malformed wire input (CBOR, bundle structure)
    MalformedInput,
    /// Unsupported capability or feature
    UnsupportedCapability,
    /// Protocol violation (e.g., invalid state transition)
    ProtocolViolation,
    /// Policy rejected the operation
    PolicyRejected,
    /// Insufficient storage available
    InsufficientStorage,
    /// No route available now or within horizon
    NoRoute,
    /// Resource unavailable (contact, bandwidth, etc.)
    ResourceUnavailable,
    /// Transfer or transmission failed
    TransferFailed,
    /// Security operation failed (verification, decryption)
    SecurityFailure,
    /// Time arithmetic overflow
    TimeOverflow,
    /// Snapshot format incompatible or corrupted
    SnapshotIncompatible,
    /// Event processing budget exhausted
    EventBudgetExhausted,
    /// Resource not found
    NotFound,
    /// Generic/other error
    Other,
}

/// Main error type for the SDK
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    /// Create a new error with kind and message
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            source: None,
        }
    }

    /// Create error with source cause
    pub fn with_source(
        kind: ErrorKind,
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Get the error kind
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::InsufficientStorage
                | ErrorKind::ResourceUnavailable
                | ErrorKind::NoRoute
                | ErrorKind::TransferFailed
        )
    }

    // Convenience constructors

    /// Create an invalid configuration error
    pub fn invalid_config(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidConfig, message)
    }

    /// Create a malformed input error
    pub fn malformed_input(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::MalformedInput, message)
    }

    /// Create an unsupported capability error
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::UnsupportedCapability, message)
    }

    /// Create a protocol violation error
    pub fn protocol_violation(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::ProtocolViolation, message)
    }

    /// Create a not found error
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, message)
    }

    /// Create a policy rejected error
    pub fn policy_rejected(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::PolicyRejected, message)
    }

    /// Create an insufficient storage error
    pub fn insufficient_storage(requested: Bytes, available: Bytes) -> Self {
        Self::new(
            ErrorKind::InsufficientStorage,
            format!(
                "Insufficient storage: requested {}, available {}",
                requested.0, available.0
            ),
        )
    }

    /// Create a no route error
    pub fn no_route(reason: impl Into<String>) -> Self {
        Self::new(ErrorKind::NoRoute, format!("No route: {}", reason.into()))
    }

    /// Create a resource unavailable error
    pub fn resource_unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::ResourceUnavailable, message)
    }

    /// Create a transfer failed error
    pub fn transfer_failed(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::TransferFailed, message)
    }

    /// Create a security failure error
    pub fn security_failure(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::SecurityFailure, message)
    }

    /// Create a security policy violation error
    pub fn security_policy_violation(message: impl Into<String>) -> Self {
        Self::new(
            ErrorKind::SecurityFailure,
            format!("Security policy violation: {}", message.into()),
        )
    }

    /// Create a time overflow error
    pub fn time_overflow() -> Self {
        Self::new(ErrorKind::TimeOverflow, "Time arithmetic overflow")
    }

    /// Create a snapshot incompatible error
    pub fn snapshot_incompatible(reason: impl Into<String>) -> Self {
        Self::new(
            ErrorKind::SnapshotIncompatible,
            format!("Snapshot incompatible: {}", reason.into()),
        )
    }

    /// Create an event budget exhausted error
    pub fn event_budget_exhausted(limit: u64) -> Self {
        Self::new(
            ErrorKind::EventBudgetExhausted,
            format!("Event budget exhausted: {}", limit),
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(source) = &self.source {
            write!(f, ": {}", source)?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

/// Result type alias using SDK Error
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_construction() {
        let err = Error::invalid_config("missing field 'node_id'");
        assert_eq!(err.kind(), &ErrorKind::InvalidConfig);
        assert_eq!(err.to_string(), "missing field 'node_id'");
    }

    #[test]
    fn test_error_retryable() {
        assert!(Error::resource_unavailable("contact full").is_retryable());
        assert!(!Error::protocol_violation("invalid CRC").is_retryable());
    }

    #[test]
    fn test_insufficient_storage() {
        let err = Error::insufficient_storage(Bytes(1000), Bytes(500));
        assert_eq!(err.kind(), &ErrorKind::InsufficientStorage);
        assert!(err.to_string().contains("1000"));
        assert!(err.to_string().contains("500"));
    }
}
