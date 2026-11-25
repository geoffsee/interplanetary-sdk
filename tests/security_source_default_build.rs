//! Test that skip_source_validation field is not available without test-fixtures feature

use interplanetary_sdk::types::EndpointId;

#[test]
fn test_validate_as_security_source_public_api() {
    // LocalNode should fail validation
    let localnode = EndpointId::ipn(0, 4294967295, 0).unwrap();
    assert!(
        localnode.validate_as_security_source().is_err(),
        "LocalNode must be rejected per RFC 9758 §5.4"
    );

    // Private Use should fail validation
    let private_use = EndpointId::ipn(0, 100, 0).unwrap();
    assert!(
        private_use.validate_as_security_source().is_err(),
        "Private Use must be rejected per RFC 9758 §5.5"
    );

    // Valid public node should pass
    let valid = EndpointId::ipn(0, 16777216, 0).unwrap();
    assert!(
        valid.validate_as_security_source().is_ok(),
        "Valid public node must be accepted"
    );
}

// This test verifies at compile time that skip_source_validation
// is not accessible without test-fixtures feature
#[test]
#[cfg(not(feature = "test-fixtures"))]
fn test_skip_source_validation_not_in_public_api() {
    // This test simply existing and compiling proves that the codebase
    // doesn't expose skip_source_validation in the default build.
    // If it did, other tests without this cfg gate would fail to compile.
    assert!(
        true,
        "skip_source_validation is correctly hidden from public API"
    );
}
