//! ION contact plan parser
//!
//! Parses ION-style contact plan configuration per NASA JPL ion-config-tool format.
//! Reference: <https://github.com/nasa-jpl/ion-config-tool>
//!
//! This module parses the textual format only; it does not claim ION interoperability.
//!
//! Format:
//! ```text
//! a contact +start +stop from_node to_node xmit_rate [confidence]
//! a range +start +stop from_node to_node distance
//! ```
//!
//! Times are relative seconds from epoch (base_time parameter).
//! Distance can be one-way light time (OWLT) in seconds or range in meters.

use interplanetary_contacts::{Contact, ContactId, ContactPlan};
use interplanetary_types::{BitsPerSecond, Error, NodeId, Result, SimDuration, SimInstant};

/// ION contact plan parser
#[derive(Debug)]
pub struct IonParser {
    base_time: SimInstant,
    next_contact_id: u64,
}

impl IonParser {
    /// Create new parser with base time for relative timestamps
    pub fn new(base_time: SimInstant) -> Self {
        Self {
            base_time,
            next_contact_id: 1,
        }
    }

    /// Parse a contact line: "a contact +start +stop from to rate \[confidence\]"
    pub fn parse_contact_line(&mut self, line: &str) -> Result<Contact> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        // Expect at least 7 tokens: a contact +start +stop from to rate
        if parts.len() < 7 {
            return Err(Error::malformed_input(format!(
                "Invalid contact line (expected 7+ tokens): {}",
                line
            )));
        }

        // Check command
        if parts[0] != "a" || parts[1] != "contact" {
            return Err(Error::malformed_input(format!(
                "Expected 'a contact', got: {} {}",
                parts[0], parts[1]
            )));
        }

        // Parse relative times (remove + prefix)
        let start_secs = Self::parse_relative_time(parts[2])?;
        let stop_secs = Self::parse_relative_time(parts[3])?;

        // Parse node IDs (as ipn nodes with allocator=0)
        let from_node = Self::parse_node_id(parts[4])?;
        let to_node = Self::parse_node_id(parts[5])?;

        // Parse transmission rate (bits per second)
        let rate_bps = parts[6]
            .parse::<u64>()
            .map_err(|_| Error::malformed_input(format!("Invalid rate: {}", parts[6])))?;

        // Confidence is optional (parts[7]), we ignore it for now

        // Convert relative times to absolute
        let start = self
            .base_time
            .checked_add(SimDuration::from_secs(start_secs))
            .ok_or_else(|| Error::malformed_input("Contact start time overflow"))?;
        let stop = self
            .base_time
            .checked_add(SimDuration::from_secs(stop_secs))
            .ok_or_else(|| Error::malformed_input("Contact stop time overflow"))?;

        if stop <= start {
            return Err(Error::malformed_input("Contact stop must be after start"));
        }

        let contact_id = ContactId::new(self.next_contact_id);
        self.next_contact_id += 1;

        Ok(Contact {
            id: contact_id,
            from_node,
            to_node,
            start,
            end: stop,
            rate: BitsPerSecond::from_bps(rate_bps),
            delay: SimDuration::ZERO, // Default, will be updated by range if provided
            resource_group: None,
        })
    }

    /// Parse a range line: "a range +start +stop from to distance"
    ///
    /// Distance can be:
    /// - OWLT in seconds (will be parsed as float)
    /// - Range in meters (will be parsed as int)
    ///
    /// We assume OWLT in seconds for simplicity. Returns delay duration.
    pub fn parse_range_line(
        &mut self,
        line: &str,
    ) -> Result<(NodeId, NodeId, u64, u64, SimDuration)> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        // Expect 7 tokens: a range +start +stop from to distance
        if parts.len() < 7 {
            return Err(Error::malformed_input(format!(
                "Invalid range line (expected 7 tokens): {}",
                line
            )));
        }

        // Check command
        if parts[0] != "a" || parts[1] != "range" {
            return Err(Error::malformed_input(format!(
                "Expected 'a range', got: {} {}",
                parts[0], parts[1]
            )));
        }

        let start_secs = Self::parse_relative_time(parts[2])?;
        let stop_secs = Self::parse_relative_time(parts[3])?;
        let from_node = Self::parse_node_id(parts[4])?;
        let to_node = Self::parse_node_id(parts[5])?;

        // Parse distance as OWLT in seconds
        let owlt_secs = parts[6]
            .parse::<f64>()
            .map_err(|_| Error::malformed_input(format!("Invalid distance/OWLT: {}", parts[6])))?;

        // Convert to SimDuration (milliseconds precision)
        let delay = SimDuration::from_millis((owlt_secs * 1000.0) as u64);

        Ok((from_node, to_node, start_secs, stop_secs, delay))
    }

    /// Parse ION contact plan from string
    ///
    /// Parses all "a contact" and "a range" commands, applies ranges to matching contacts.
    pub fn parse_plan(&mut self, input: &str) -> Result<ContactPlan> {
        let mut contacts = Vec::new();
        let mut ranges = Vec::new();

        for line in input.lines() {
            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if trimmed.starts_with("a contact") {
                let contact = self.parse_contact_line(trimmed)?;
                contacts.push(contact);
            } else if trimmed.starts_with("a range") {
                let range = self.parse_range_line(trimmed)?;
                ranges.push(range);
            }
            // Ignore other commands
        }

        // Apply range delays to matching contacts
        for contact in &mut contacts {
            for (from, to, _start, _stop, delay) in &ranges {
                if contact.from_node == *from && contact.to_node == *to {
                    // Check time overlap (simplified: if ranges match, apply delay)
                    contact.delay = *delay;
                }
            }
        }

        // Build contact plan
        let mut plan = ContactPlan::new();
        for contact in contacts {
            plan.add_contact(contact);
        }

        Ok(plan)
    }

    /// Parse relative time (format: +N where N is seconds)
    fn parse_relative_time(s: &str) -> Result<u64> {
        let without_plus = s
            .strip_prefix('+')
            .ok_or_else(|| Error::malformed_input(format!("Time must start with +: {}", s)))?;

        without_plus
            .parse::<u64>()
            .map_err(|_| Error::malformed_input(format!("Invalid time: {}", s)))
    }

    /// Parse node ID (simple integer, represented as ipn with allocator=0)
    fn parse_node_id(s: &str) -> Result<NodeId> {
        let id = s
            .parse::<u64>()
            .map_err(|_| Error::malformed_input(format!("Invalid node ID: {}", s)))?;
        Ok(NodeId::Ipn {
            allocator: 0,
            node: id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_contact_line() {
        let base_time = SimInstant::from_nanos(0);
        let mut parser = IonParser::new(base_time);

        // Example: contact starts at +1s, ends at +100s, from node 1 to node 2, 100000 bps
        let line = "a contact +1 +100 1 2 100000";
        let contact = parser.parse_contact_line(line).unwrap();

        assert_eq!(
            contact.from_node,
            NodeId::Ipn {
                allocator: 0,
                node: 1
            }
        );
        assert_eq!(
            contact.to_node,
            NodeId::Ipn {
                allocator: 0,
                node: 2
            }
        );
        assert_eq!(
            contact.start,
            base_time.checked_add(SimDuration::from_secs(1)).unwrap()
        );
        assert_eq!(
            contact.end,
            base_time.checked_add(SimDuration::from_secs(100)).unwrap()
        );
        assert_eq!(contact.rate, BitsPerSecond::from_bps(100000));
    }

    #[test]
    fn test_parse_range_line() {
        let base_time = SimInstant::from_nanos(0);
        let mut parser = IonParser::new(base_time);

        // Example: range from +1s to +100s, node 1 to 2, 10 seconds OWLT
        let line = "a range +1 +100 1 2 10";
        let (from, to, _start, _stop, delay) = parser.parse_range_line(line).unwrap();

        assert_eq!(
            from,
            NodeId::Ipn {
                allocator: 0,
                node: 1
            }
        );
        assert_eq!(
            to,
            NodeId::Ipn {
                allocator: 0,
                node: 2
            }
        );
        assert_eq!(delay, SimDuration::from_secs(10));
    }

    #[test]
    fn test_parse_plan_with_contact_and_range() {
        let base_time = SimInstant::from_nanos(0);
        let mut parser = IonParser::new(base_time);

        let input = r#"
# Simple contact plan
a contact +10 +20 1 2 100000
a contact +30 +40 2 3 200000
a range +10 +20 1 2 5
"#;

        let plan = parser.parse_plan(input).unwrap();
        let contacts = plan.contacts();

        assert_eq!(contacts.len(), 2, "Should have 2 contacts");

        // First contact should have delay from range
        let c1 = contacts
            .iter()
            .find(|c| {
                c.from_node
                    == NodeId::Ipn {
                        allocator: 0,
                        node: 1,
                    }
            })
            .unwrap();
        assert_eq!(c1.delay, SimDuration::from_secs(5));
    }

    #[test]
    fn test_parse_plan_ignores_comments() {
        let base_time = SimInstant::from_nanos(0);
        let mut parser = IonParser::new(base_time);

        let input = r#"
# This is a comment
a contact +1 +10 1 2 100000
# Another comment
"#;

        let plan = parser.parse_plan(input).unwrap();
        assert_eq!(plan.contacts().len(), 1);
    }

    #[test]
    fn test_invalid_contact_line() {
        let base_time = SimInstant::from_nanos(0);
        let mut parser = IonParser::new(base_time);

        let line = "a contact +1"; // Too few tokens
        assert!(parser.parse_contact_line(line).is_err());
    }

    #[test]
    fn test_time_must_have_plus_prefix() {
        let base_time = SimInstant::from_nanos(0);
        let mut parser = IonParser::new(base_time);

        let line = "a contact 1 100 1 2 100000"; // Missing + prefix
        assert!(parser.parse_contact_line(line).is_err());
    }
}
