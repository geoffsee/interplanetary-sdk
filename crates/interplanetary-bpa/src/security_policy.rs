//! BPSec Security Policy Model per RFC 9172
//!
//! Implements deterministic policy framework following NASA/JPL ION conventions:
//! - Security roles: source, verifier, acceptor
//! - Rule matching on bundle/security-source EIDs and target block types
//! - Required-security checks (missing/unexpected operations)
//! - Event actions: delete bundle, remove target, remove security operation, report

use interplanetary_bp::BlockType;
use interplanetary_types::{EndpointId, Error, Result};
use std::collections::HashMap;

/// Security role of this node for a bundle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityRole {
    /// Security source: applies security operations
    Source,
    /// Verifier: verifies security operations (intermediate node)
    Verifier,
    /// Acceptor: final destination, verifies and processes
    Acceptor,
}

/// Security operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityOperation {
    /// Block Integrity Block (BIB) for integrity
    Bib,
    /// Block Confidentiality Block (BCB) for confidentiality
    Bcb,
}

/// Action to take on security policy violation or failure
///
/// Note: For failed security operations (verification/decryption failures),
/// use `SecurityContext::bib_failure_policy` or `SecurityContext::bcb_failure_policy`
/// with `SecurityFailurePolicy::StripSecurityBlock` instead of policy rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityAction {
    /// Delete the entire bundle (RFC 9172 §5.1.1 default)
    DeleteBundle,
    /// Remove the security target block
    RemoveTarget,
    /// Generate status report with security failure reason code
    Report,
}

/// Security failure reason (RFC 9172 §11.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityFailureReason {
    /// No reason specified
    None = 0,
    /// Security operation missing when required by policy (RFC 9172 §11.2 code 12)
    MissingSecurityOperation = 12,
    /// Unknown security operation (context ID not recognized) (RFC 9172 §11.2 code 13)
    UnknownSecurityOperation = 13,
    /// Unexpected security operation (not allowed by policy) (RFC 9172 §11.2 code 14)
    UnexpectedSecurityOperation = 14,
    /// Security operation failed (verification/decryption failed) (RFC 9172 §11.2 code 15)
    FailedSecurityOperation = 15,
    /// Conflicting security operations (RFC 9172 §11.2 code 16)
    ConflictingSecurityOperation = 16,
}

/// Security policy rule
#[derive(Debug, Clone)]
pub struct SecurityPolicyRule {
    /// Match bundles from this source (None = any)
    pub source_match: Option<EndpointId>,
    /// Match bundles to this destination (None = any)
    pub destination_match: Option<EndpointId>,
    /// Match security operations from this security source (None = any)
    pub security_source_match: Option<EndpointId>,
    /// Target block type (None = any block)
    pub target_block_type: Option<BlockType>,
    /// Required security operation (None = no requirement)
    pub required_operation: Option<SecurityOperation>,
    /// Forbidden security operation (ION-style explicit forbid, generates code 14 if present)
    pub forbidden_operation: Option<SecurityOperation>,
    /// Actions to take on failure
    pub failure_actions: Vec<SecurityAction>,
}

impl SecurityPolicyRule {
    /// Check if this rule matches a bundle
    pub fn matches(
        &self,
        bundle_source: &EndpointId,
        bundle_dest: &EndpointId,
        security_source: Option<&EndpointId>,
        target_block: Option<BlockType>,
    ) -> bool {
        // Check source match
        if let Some(ref source_pattern) = self.source_match
            && bundle_source != source_pattern
        {
            return false;
        }

        // Check destination match
        if let Some(ref dest_pattern) = self.destination_match
            && bundle_dest != dest_pattern
        {
            return false;
        }

        // Check security source match
        if let Some(ref sec_source_pattern) = self.security_source_match {
            match security_source {
                Some(sec_src) => {
                    if sec_src != sec_source_pattern {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Check target block type match
        if let Some(target_type) = self.target_block_type {
            match target_block {
                Some(block_type) => {
                    if block_type != target_type {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}

/// BPSec security policy configuration
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Ordered list of policy rules (first match wins)
    rules: Vec<SecurityPolicyRule>,
    /// Default action when no rule matches
    default_action: SecurityAction,
    /// RFC9172-110: whether cipher suites whose ciphertext is larger than the
    /// initial plaintext are permitted (recommended default: true for payload).
    pub permit_ciphertext_expansion: bool,
    /// RFC9172-111: when true, security failures emit status reports with
    /// security reason codes (recommended default: true).
    pub emit_security_reason_codes: bool,
    /// RFC9172-108: when true, outbound security covers every block (primary,
    /// extensions, and payload) and receive policy requires BIB on each.
    pub apply_to_every_block: bool,
    /// RFC9172-109: when true, post-security bundle size is accounted for in
    /// storage-capacity and MTU/scheduling decisions.
    pub account_for_block_size_changes: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityPolicy {
    /// Create new empty security policy
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            default_action: SecurityAction::DeleteBundle,
            permit_ciphertext_expansion: true,
            // False in empty policy so existing call-sites keep status_report_policy control;
            // recommended_bpsec_default() enables emission (RFC9172-111).
            emit_security_reason_codes: false,
            apply_to_every_block: false,
            account_for_block_size_changes: false,
        }
    }

    /// RFC9172-108: recommended default — apply BPSec to every block and emit
    /// security reason codes; permit ciphertext expansion; account for size.
    pub fn recommended_bpsec_default() -> Self {
        let mut policy = Self::new();
        policy.emit_security_reason_codes = true;
        policy.permit_ciphertext_expansion = true;
        policy.apply_to_every_block = true;
        policy.account_for_block_size_changes = true;
        for block_type in [
            BlockType::Payload,
            BlockType::PreviousNode,
            BlockType::BundleAge,
            BlockType::HopCount,
        ] {
            policy.add_rule(SecurityPolicyRule {
                source_match: None,
                destination_match: None,
                security_source_match: None,
                target_block_type: Some(block_type),
                required_operation: Some(SecurityOperation::Bib),
                forbidden_operation: None,
                failure_actions: vec![SecurityAction::DeleteBundle, SecurityAction::Report],
            });
        }
        policy
    }

    /// Add a policy rule
    pub fn add_rule(&mut self, rule: SecurityPolicyRule) {
        self.rules.push(rule);
    }

    /// Set default action
    pub fn set_default_action(&mut self, action: SecurityAction) {
        self.default_action = action;
    }

    /// RFC9172-110: whether ciphertext larger than plaintext is permitted.
    pub fn permits_ciphertext_expansion(&self) -> bool {
        self.permit_ciphertext_expansion
    }

    /// RFC9172-111: whether to emit security reason codes on security failure.
    pub fn should_emit_security_reason_codes(&self) -> bool {
        self.emit_security_reason_codes
    }

    /// RFC9172-108: whether outbound/receive policy covers every block.
    pub fn applies_to_every_block(&self) -> bool {
        self.apply_to_every_block
    }

    /// RFC9172-109: whether post-security size feeds storage/MTU decisions.
    pub fn accounts_for_block_size_changes(&self) -> bool {
        self.account_for_block_size_changes
    }

    /// Find matching rule for a bundle
    pub fn find_matching_rule(
        &self,
        bundle_source: &EndpointId,
        bundle_dest: &EndpointId,
        security_source: Option<&EndpointId>,
        target_block: Option<BlockType>,
    ) -> Option<&SecurityPolicyRule> {
        self.rules
            .iter()
            .find(|rule| rule.matches(bundle_source, bundle_dest, security_source, target_block))
    }

    /// Check if security operation is required
    pub fn check_required_security(
        &self,
        bundle_source: &EndpointId,
        bundle_dest: &EndpointId,
        target_block: BlockType,
        present_operations: &HashMap<BlockType, Vec<SecurityOperation>>,
    ) -> Result<()> {
        // Find matching rule
        if let Some(rule) =
            self.find_matching_rule(bundle_source, bundle_dest, None, Some(target_block))
            && let Some(required_op) = rule.required_operation
        {
            // Check if required operation is present
            if let Some(ops) = present_operations.get(&target_block) {
                if !ops.contains(&required_op) {
                    return Err(Error::security_policy_violation(format!(
                        "Missing required {:?} for block {:?}",
                        required_op, target_block
                    )));
                }
            } else {
                return Err(Error::security_policy_violation(format!(
                    "Missing required {:?} for block {:?}",
                    required_op, target_block
                )));
            }
        }

        Ok(())
    }

    /// Get failure actions for a security failure
    pub fn get_failure_actions(
        &self,
        bundle_source: &EndpointId,
        bundle_dest: &EndpointId,
        security_source: Option<&EndpointId>,
        target_block: Option<BlockType>,
    ) -> Vec<SecurityAction> {
        if let Some(rule) =
            self.find_matching_rule(bundle_source, bundle_dest, security_source, target_block)
        {
            rule.failure_actions.clone()
        } else {
            vec![self.default_action]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_rule_matching() {
        let source = EndpointId::ipn(0, 1, 0).unwrap();
        let dest = EndpointId::ipn(0, 2, 0).unwrap();
        let _sec_source = EndpointId::ipn(0, 3, 0).unwrap();

        let rule = SecurityPolicyRule {
            source_match: Some(source.clone()),
            destination_match: Some(dest.clone()),
            security_source_match: None,
            target_block_type: Some(BlockType::Payload),
            required_operation: Some(SecurityOperation::Bib),
            forbidden_operation: None,
            failure_actions: vec![SecurityAction::DeleteBundle],
        };

        // Should match
        assert!(rule.matches(&source, &dest, None, Some(BlockType::Payload)));

        // Should not match (wrong source)
        let other_source = EndpointId::ipn(0, 99, 0).unwrap();
        assert!(!rule.matches(&other_source, &dest, None, Some(BlockType::Payload)));

        // Should not match (wrong block type)
        assert!(!rule.matches(&source, &dest, None, Some(BlockType::PreviousNode)));
    }

    #[test]
    fn test_required_security_check() {
        let mut policy = SecurityPolicy::new();
        let source = EndpointId::ipn(0, 1, 0).unwrap();
        let dest = EndpointId::ipn(0, 2, 0).unwrap();

        // Add rule requiring BIB for payload
        policy.add_rule(SecurityPolicyRule {
            source_match: Some(source.clone()),
            destination_match: Some(dest.clone()),
            security_source_match: None,
            target_block_type: Some(BlockType::Payload),
            required_operation: Some(SecurityOperation::Bib),
            forbidden_operation: None,
            failure_actions: vec![SecurityAction::DeleteBundle],
        });

        // Check without BIB - should fail
        let mut ops = HashMap::new();
        let result = policy.check_required_security(&source, &dest, BlockType::Payload, &ops);
        assert!(result.is_err());

        // Check with BIB - should succeed
        ops.insert(BlockType::Payload, vec![SecurityOperation::Bib]);
        let result = policy.check_required_security(&source, &dest, BlockType::Payload, &ops);
        assert!(result.is_ok());
    }
}
