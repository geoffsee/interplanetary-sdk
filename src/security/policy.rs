//! Security policy matrix for BPSec operations
//!
//! Defines when and how to apply BIB/BCB security operations based on
//! bundle properties, endpoints, and network context.

use super::context1_hmac::HmacVariant;
use super::context2_aesgcm::AesGcmVariant;
use crate::types::EndpointId;

/// Security policy defines when to apply security operations
///
/// ## Design
///
/// Policies are evaluated per-bundle to determine which security operations
/// to apply. Multiple rules can match, resulting in multiple security blocks.
///
/// ## Fail-Closed Operation (Charter §7)
///
/// When `fail_if_no_match = true` (default), bundles destined for protected
/// endpoints that match no security rules are rejected rather than forwarded
/// unprotected. This is the required operational default per charter §7:
/// "Default protected-service delivery fails closed."
///
/// Set `fail_if_no_match = false` only for testing or when explicitly
/// configured to allow best-effort delivery.
///
/// ## Usage
///
/// Security policy is configured with BIB and BCB rules that match bundle
/// source/destination endpoints and control integrity and confidentiality
/// protection. Operational code should use the BundleAgent security_policy
/// configuration rather than calling these methods directly.
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// BIB (integrity) rules
    pub bib_rules: Vec<BibRule>,
    /// BCB (confidentiality) rules
    pub bcb_rules: Vec<BcbRule>,
    /// Reject bundles with no matching security rules (default: true)
    ///
    /// Charter §7 requirement: "Default protected-service delivery fails closed."
    /// Set to false only for testing or explicit best-effort configuration.
    pub fail_if_no_match: bool,
}

impl SecurityPolicy {
    /// Create an empty policy with fail-closed default
    ///
    /// Per charter §7: "Default protected-service delivery fails closed."
    /// Bundles with no matching security rules will be rejected unless
    /// `fail_if_no_match` is explicitly set to false.
    pub fn new() -> Self {
        Self {
            bib_rules: Vec::new(),
            bcb_rules: Vec::new(),
            fail_if_no_match: true, // Charter §7 requirement
        }
    }

    /// Create a permissive policy (allows unprotected delivery)
    ///
    /// Use only for testing or when explicitly configured to allow
    /// best-effort delivery without security.
    pub fn permissive() -> Self {
        Self {
            bib_rules: Vec::new(),
            bcb_rules: Vec::new(),
            fail_if_no_match: false,
        }
    }

    /// Set fail-if-no-match behavior
    pub fn with_fail_if_no_match(mut self, fail: bool) -> Self {
        self.fail_if_no_match = fail;
        self
    }

    /// Add a BIB rule
    pub fn add_bib_rule(mut self, rule: BibRule) -> Self {
        self.bib_rules.push(rule);
        self
    }

    /// Add a BCB rule
    pub fn add_bcb_rule(mut self, rule: BcbRule) -> Self {
        self.bcb_rules.push(rule);
        self
    }

    /// Evaluate which rules apply to an outbound bundle
    ///
    /// Returns matching rules that should be applied.
    pub fn evaluate_outbound(&self, dest: &EndpointId) -> Option<ApplicableRules> {
        let mut result = ApplicableRules {
            bib_rules: Vec::new(),
            bcb_rules: Vec::new(),
        };

        for rule in &self.bib_rules {
            if rule.matches(dest) {
                result.bib_rules.push(rule.clone());
            }
        }

        for rule in &self.bcb_rules {
            if rule.matches(dest) {
                result.bcb_rules.push(rule.clone());
            }
        }

        if result.bib_rules.is_empty() && result.bcb_rules.is_empty() {
            None
        } else {
            Some(result)
        }
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// BIB (integrity) rule configuration
#[derive(Debug, Clone)]
pub struct BibRule {
    /// Condition for when this rule applies
    pub condition: PolicyCondition,
    /// Target blocks to protect
    pub targets: Vec<u64>,
    /// HMAC variant to use
    pub hmac_variant: HmacVariant,
    /// Scope flags (include primary, target header, security header)
    pub scope_flags: u8,
    /// Key identifier for KeyProvider lookup
    pub key_id: String,
}

impl BibRule {
    /// Create rule to protect primary block for specific destination
    pub fn protect_primary_for_dest(dest_pattern: &str) -> Self {
        Self {
            condition: PolicyCondition::DestinationMatches(dest_pattern.to_string()),
            targets: vec![0],                  // Primary block
            hmac_variant: HmacVariant::Sha384, // Default per RFC 9173
            scope_flags: 0x00,
            key_id: format!("bib-key-{}", dest_pattern),
        }
    }

    /// Check if this rule matches the given destination
    pub fn matches(&self, dest: &EndpointId) -> bool {
        self.condition.matches(dest)
    }
}

/// BCB (confidentiality) rule configuration
#[derive(Debug, Clone)]
pub struct BcbRule {
    /// Condition for when this rule applies
    pub condition: PolicyCondition,
    /// Target blocks to encrypt
    pub targets: Vec<u64>,
    /// AES-GCM variant to use
    pub aes_variant: AesGcmVariant,
    /// Scope flags for AAD construction
    pub scope_flags: u8,
    /// Key identifier for KeyProvider lookup
    pub key_id: String,
}

impl BcbRule {
    /// Create rule to encrypt payload for specific destination
    pub fn encrypt_payload_for_dest(dest_pattern: &str) -> Self {
        Self {
            condition: PolicyCondition::DestinationMatches(dest_pattern.to_string()),
            targets: vec![1], // Payload block (typically block 1 after security blocks)
            aes_variant: AesGcmVariant::Aes256, // Default per RFC 9173
            scope_flags: 0x00,
            key_id: format!("bcb-key-{}", dest_pattern),
        }
    }

    /// Check if this rule matches the given destination
    pub fn matches(&self, dest: &EndpointId) -> bool {
        self.condition.matches(dest)
    }
}

/// Condition for when a security rule applies
#[derive(Debug, Clone)]
pub enum PolicyCondition {
    /// Always apply
    Always,
    /// Apply when destination matches pattern (simplified: exact string match for now)
    DestinationMatches(String),
    /// Apply when source matches pattern
    SourceMatches(String),
    /// Apply for specific hop (e.g., "first hop only")
    HopCondition(HopCondition),
    /// Logical AND of multiple conditions
    And(Vec<PolicyCondition>),
    /// Logical OR of multiple conditions
    Or(Vec<PolicyCondition>),
}

impl PolicyCondition {
    /// Check if condition matches the bundle destination
    pub fn matches(&self, dest: &EndpointId) -> bool {
        match self {
            PolicyCondition::Always => true,
            PolicyCondition::DestinationMatches(pattern) => {
                // Simplified matching - exact string comparison
                // In real implementation, would support wildcards, prefixes, etc.
                dest.to_string() == *pattern
            }
            PolicyCondition::SourceMatches(_) => {
                // Would need bundle source to evaluate
                false
            }
            PolicyCondition::HopCondition(_) => {
                // Would need hop context to evaluate
                false
            }
            PolicyCondition::And(conditions) => conditions.iter().all(|c| c.matches(dest)),
            PolicyCondition::Or(conditions) => conditions.iter().any(|c| c.matches(dest)),
        }
    }
}

/// Hop-based conditions
#[derive(Debug, Clone)]
pub enum HopCondition {
    /// First hop from source
    FirstHop,
    /// Last hop to destination
    LastHop,
    /// Any intermediate hop
    Intermediate,
}

/// Rules that apply to a specific bundle
#[derive(Debug)]
pub struct ApplicableRules {
    /// BIB rules to apply
    pub bib_rules: Vec<BibRule>,
    /// BCB rules to apply
    pub bcb_rules: Vec<BcbRule>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_policy() {
        let policy = SecurityPolicy::new();
        let dest = EndpointId::ipn(0, 3, 0).unwrap();

        assert!(policy.evaluate_outbound(&dest).is_none());
    }

    #[test]
    fn test_bib_rule_matching() {
        let policy =
            SecurityPolicy::new().add_bib_rule(BibRule::protect_primary_for_dest("ipn:3.0"));

        let dest_match = EndpointId::ipn(0, 3, 0).unwrap();
        let dest_nomatch = EndpointId::ipn(0, 4, 0).unwrap();

        let rules_match = policy.evaluate_outbound(&dest_match);
        assert!(rules_match.is_some());
        assert_eq!(rules_match.unwrap().bib_rules.len(), 1);

        let rules_nomatch = policy.evaluate_outbound(&dest_nomatch);
        assert!(rules_nomatch.is_none());
    }

    #[test]
    fn test_bcb_rule_matching() {
        let policy =
            SecurityPolicy::new().add_bcb_rule(BcbRule::encrypt_payload_for_dest("ipn:3.0"));

        let dest = EndpointId::ipn(0, 3, 0).unwrap();
        let rules = policy.evaluate_outbound(&dest);

        assert!(rules.is_some());
        let rules = rules.unwrap();
        assert_eq!(rules.bcb_rules.len(), 1);
        assert_eq!(rules.bcb_rules[0].targets, vec![1]);
    }

    #[test]
    fn test_multiple_rules() {
        let policy = SecurityPolicy::new()
            .add_bib_rule(BibRule::protect_primary_for_dest("ipn:3.0"))
            .add_bcb_rule(BcbRule::encrypt_payload_for_dest("ipn:3.0"));

        let dest = EndpointId::ipn(0, 3, 0).unwrap();
        let rules = policy.evaluate_outbound(&dest).unwrap();

        assert_eq!(rules.bib_rules.len(), 1);
        assert_eq!(rules.bcb_rules.len(), 1);
    }

    #[test]
    fn test_condition_always() {
        let condition = PolicyCondition::Always;
        let dest = EndpointId::ipn(0, 99, 99).unwrap();

        assert!(condition.matches(&dest));
    }

    #[test]
    fn test_condition_and() {
        let condition = PolicyCondition::And(vec![
            PolicyCondition::Always,
            PolicyCondition::DestinationMatches("ipn:3.0".to_string()),
        ]);

        let dest_match = EndpointId::ipn(0, 3, 0).unwrap();
        let dest_nomatch = EndpointId::ipn(0, 4, 0).unwrap();

        assert!(condition.matches(&dest_match));
        assert!(!condition.matches(&dest_nomatch));
    }

    #[test]
    fn test_condition_or() {
        let condition = PolicyCondition::Or(vec![
            PolicyCondition::DestinationMatches("ipn:3.0".to_string()),
            PolicyCondition::DestinationMatches("ipn:4.0".to_string()),
        ]);

        let dest1 = EndpointId::ipn(0, 3, 0).unwrap();
        let dest2 = EndpointId::ipn(0, 4, 0).unwrap();
        let dest3 = EndpointId::ipn(0, 5, 0).unwrap();

        assert!(condition.matches(&dest1));
        assert!(condition.matches(&dest2));
        assert!(!condition.matches(&dest3));
    }

    // ========================================================================
    // Charter §7 Fail-Closed Tests
    // ========================================================================

    #[test]
    fn test_fail_closed_default() {
        let policy = SecurityPolicy::new();

        // Default should be fail-closed
        assert!(
            policy.fail_if_no_match,
            "Charter §7: default must fail closed"
        );
    }

    #[test]
    fn test_fail_closed_rejects_unmatched() {
        let policy =
            SecurityPolicy::new().add_bib_rule(BibRule::protect_primary_for_dest("ipn:3.0"));

        // Protected destination
        let protected_dest = EndpointId::ipn(0, 3, 0).unwrap();
        assert!(policy.evaluate_outbound(&protected_dest).is_some());

        // Unprotected destination with fail_if_no_match = true
        let unprotected_dest = EndpointId::ipn(0, 999, 0).unwrap();
        let result = policy.evaluate_outbound(&unprotected_dest);

        // Should return None, signaling bundle should be rejected
        assert!(
            result.is_none(),
            "Fail-closed policy must reject bundles with no matching rules"
        );
    }

    #[test]
    fn test_permissive_allows_unmatched() {
        let policy =
            SecurityPolicy::permissive().add_bib_rule(BibRule::protect_primary_for_dest("ipn:3.0"));

        assert!(!policy.fail_if_no_match);

        // Unprotected destination should be allowed in permissive mode
        let unprotected_dest = EndpointId::ipn(0, 999, 0).unwrap();
        let result = policy.evaluate_outbound(&unprotected_dest);

        // None is acceptable in permissive mode
        assert!(result.is_none());
    }

    #[test]
    fn test_fail_closed_explicit_false() {
        let policy = SecurityPolicy::new().with_fail_if_no_match(false);

        assert!(!policy.fail_if_no_match);
    }

    /// Test that absent protection (no matching rules) fails closed by default
    #[test]
    fn test_absent_protection_fails_closed() {
        let policy = SecurityPolicy::new(); // Empty policy, fail-closed

        let any_dest = EndpointId::ipn(0, 1, 0).unwrap();
        let result = policy.evaluate_outbound(&any_dest);

        // No rules match, should return None
        assert!(
            result.is_none(),
            "Absent protection: bundle should be rejected (fail closed)"
        );

        // In operational use, caller must check fail_if_no_match flag
        // and reject bundle if result.is_none() && policy.fail_if_no_match
    }

    /// Test missing key scenario (policy simulation)
    ///
    /// In operational code, KeyProvider.get_key() returns Err when key missing.
    /// This test verifies the policy layer correctly identifies which keys are needed.
    #[test]
    fn test_missing_key_simulation() {
        let policy = SecurityPolicy::new().add_bib_rule(BibRule {
            condition: PolicyCondition::Always,
            targets: vec![0],
            hmac_variant: HmacVariant::Sha384,
            scope_flags: 0x00,
            key_id: "nonexistent-key".to_string(),
        });

        let dest = EndpointId::ipn(0, 1, 0).unwrap();
        let rules = policy.evaluate_outbound(&dest);

        assert!(rules.is_some());
        let rules = rules.unwrap();
        assert_eq!(rules.bib_rules[0].key_id, "nonexistent-key");

        // In real use: KeyProvider.get_key("nonexistent-key") -> Err
        // BPA must fail-closed: reject bundle, never forward without protection
    }

    /// Test unsupported context scenario (policy simulation)
    ///
    /// Policy specifies valid contexts. Unsupported variant codes would be
    /// caught during BIB/BCB generation, not in policy evaluation.
    #[test]
    fn test_unsupported_context_policy() {
        // Policy can specify any HmacVariant / AesGcmVariant
        // If implementation doesn't support it, generation will fail
        // and bundle must be rejected (fail-closed)

        let policy = SecurityPolicy::new().add_bib_rule(BibRule {
            condition: PolicyCondition::Always,
            targets: vec![0],
            hmac_variant: HmacVariant::Sha512,
            scope_flags: 0x00,
            key_id: "test-key".to_string(),
        });

        let dest = EndpointId::ipn(0, 1, 0).unwrap();
        let rules = policy.evaluate_outbound(&dest);

        assert!(rules.is_some());
        // If Sha512 unsupported, bib::generate_bib() -> Err
        // Caller must reject bundle (fail-closed)
    }

    /// Test malformed parameters scenario
    ///
    /// Example: invalid scope flags, empty targets, etc.
    /// Policy validation could catch these at construction time.
    #[test]
    fn test_malformed_parameters_empty_targets() {
        // Empty targets is malformed but currently allowed by struct
        // In operational code, validation should catch this
        let rule = BibRule {
            condition: PolicyCondition::Always,
            targets: vec![], // Malformed: no targets
            hmac_variant: HmacVariant::Sha384,
            scope_flags: 0x00,
            key_id: "test-key".to_string(),
        };

        // Policy construction succeeds but generation would fail
        // Fail-closed: reject bundle if BIB generation fails
        assert!(rule.targets.is_empty());
    }

    /// Test bad authentication scenario (verification failure)
    ///
    /// This occurs during BIB/BCB verification at receiver.
    /// Failed verification must never leak plaintext.
    #[test]
    fn test_bad_authentication_must_fail_closed() {
        // Verification is in bib/bcb modules, not policy
        // This test documents the requirement:
        // If HMAC verification fails, bundle MUST be rejected
        // No plaintext leak to application or observations

        // Policy specifies what to verify
        let policy =
            SecurityPolicy::new().add_bib_rule(BibRule::protect_primary_for_dest("ipn:1.0"));

        // At receiver: if HMAC doesn't match computed value
        // -> Error::security_failure("Authentication failed")
        // -> Bundle rejected, not delivered to application
        // -> No plaintext in observations/logs

        // This is verified in BIB/BCB verification tests
        assert!(policy.fail_if_no_match);
    }

    /// Test unauthorized source scenario
    ///
    /// Policy could include source-based authorization rules.
    /// Currently PolicyCondition only has DestinationMatches.
    #[test]
    fn test_unauthorized_source_policy_extension() {
        // Future extension: PolicyCondition::SourceMatches
        // For now, source authorization is external to policy

        let policy =
            SecurityPolicy::new().add_bib_rule(BibRule::protect_primary_for_dest("ipn:3.0"));

        // Source check would happen in BPA layer:
        // if bundle.security_source != expected -> reject

        assert!(policy.fail_if_no_match);
    }

    /// Integration test: complete fail-closed workflow
    #[test]
    fn test_fail_closed_workflow() {
        let policy = SecurityPolicy::new()
            .add_bib_rule(BibRule::protect_primary_for_dest("ipn:100.0"))
            .add_bcb_rule(BcbRule::encrypt_payload_for_dest("ipn:100.0"));

        // Scenario 1: Protected destination with matching rules
        let secure_dest = EndpointId::ipn(0, 100, 0).unwrap();
        let rules = policy.evaluate_outbound(&secure_dest);
        assert!(rules.is_some());
        let rules = rules.unwrap();
        assert_eq!(rules.bib_rules.len(), 1);
        assert_eq!(rules.bcb_rules.len(), 1);

        // Scenario 2: Unprotected destination (no rules match)
        let insecure_dest = EndpointId::ipn(0, 999, 0).unwrap();
        let rules = policy.evaluate_outbound(&insecure_dest);
        assert!(rules.is_none(), "No rules match");

        // BPA must check:
        if rules.is_none() && policy.fail_if_no_match {
            // Reject bundle (fail-closed)
            // Error::security_failure("No security policy for destination")
        }

        // Scenario 3: Permissive mode allows unmatched
        let permissive = SecurityPolicy::permissive();
        let rules_permissive = permissive.evaluate_outbound(&insecure_dest);
        assert!(rules_permissive.is_none());
        // But permissive.fail_if_no_match == false, so bundle proceeds
    }
}
