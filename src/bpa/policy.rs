//! BPA policy configuration for status reports and administrative actions

use crate::bpa::admin::ReasonCode;
use crate::types::EndpointId;

/// Status report policy
#[derive(Debug, Clone)]
pub struct StatusReportPolicy {
    /// Generate report on bundle reception
    pub report_on_reception: bool,
    /// Generate report on bundle forwarding
    pub report_on_forwarding: bool,
    /// Generate report on bundle delivery
    pub report_on_delivery: bool,
    /// Generate report on bundle deletion
    pub report_on_deletion: bool,
    /// Destination for status reports
    pub report_to: Option<EndpointId>,
}

impl StatusReportPolicy {
    /// No status reports
    pub fn none() -> Self {
        Self {
            report_on_reception: false,
            report_on_forwarding: false,
            report_on_delivery: false,
            report_on_deletion: false,
            report_to: None,
        }
    }

    /// Report all events
    pub fn all(report_to: EndpointId) -> Self {
        Self {
            report_on_reception: true,
            report_on_forwarding: true,
            report_on_delivery: true,
            report_on_deletion: true,
            report_to: Some(report_to),
        }
    }

    /// Check if should report for given reason
    pub fn should_report_deletion(&self, _reason: ReasonCode) -> bool {
        self.report_on_deletion
    }
}

impl Default for StatusReportPolicy {
    fn default() -> Self {
        Self::none()
    }
}

/// RFC 9171 §5.4.2: Forwarding Failed policy
///
/// Determines how BPA responds when forwarding is contraindicated (no known route,
/// bundle too large without fragmentation, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardingFailedPolicy {
    /// Delete bundle immediately (RFC 9171 §5.4.2 Step 2: "Otherwise, the bundle MUST be deleted")
    /// This is the simplest and most common policy.
    Delete,

    /// Return bundle to previous node (RFC 9171 §5.4.2 Step 1: "BPA MAY forward the bundle
    /// back to the node that sent it, as identified by the Previous Node Block, if present")
    /// Only possible if Previous Node block exists and differs from local node.
    /// Falls back to Delete if no previous node or previous node is local.
    ReturnToPreviousNode,

    /// Retain bundle without deleting (hold for manual intervention or policy change)
    /// Not specified in RFC 9171 but useful for operational scenarios.
    /// Bundle remains in storage with ForwardPending constraint.
    Retain,
}

impl Default for ForwardingFailedPolicy {
    /// Default: Delete (matches ION behavior and RFC 9171 §5.4.2 "Otherwise" clause)
    fn default() -> Self {
        Self::Delete
    }
}
