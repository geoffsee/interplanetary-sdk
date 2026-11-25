//! Static routing table

use interplanetary_types::{Error, NodeId, Result};
use std::collections::HashMap;

/// Static routing table
#[derive(Debug)]
pub struct StaticRouter {
    routes: HashMap<NodeId, NodeId>,
}

impl StaticRouter {
    /// Create new static router
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    /// Add route
    pub fn add_route(&mut self, destination: NodeId, next_hop: NodeId) {
        self.routes.insert(destination, next_hop);
    }

    /// Look up next hop
    pub fn lookup(&self, destination: &NodeId) -> Result<&NodeId> {
        self.routes
            .get(destination)
            .ok_or_else(|| Error::no_route(format!("No static route to {}", destination)))
    }
}

impl Default for StaticRouter {
    fn default() -> Self {
        Self::new()
    }
}
