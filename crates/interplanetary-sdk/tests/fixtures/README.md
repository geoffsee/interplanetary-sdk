# Test Fixtures

This directory contains test fixtures for interplanetary-sdk tests.

## ION Contact Plan Fixtures

### three_node.ionrc

A hand-written three-node contact plan (Earth-Relay-Mars) in ION format.

**Format reference:**
- [ion-config-tool](https://github.com/nasa-jpl/ion-config-tool) - ION configuration format documentation
- [ion-network-model](https://github.com/nasa-jpl/ion-network-model) - ION network modeling tools

**License:** Hand-written for this project, not copied from ION-DTN.

**Format:**
```
a contact +start +stop from_node to_node xmit_rate
a range +start +stop from_node to_node owlt_seconds
```

**Provenance:** Created based on documented ION ionrc format (a contact/a range commands).
This is a parser of the config format only; it does not claim ION interoperability.
