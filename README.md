# interplanetary-sdk

> Status: Pre-Alpha

Rust library for delay-tolerant networking (DTN). It implements Bundle Protocol version 7 (BPv7), TCPCLv4 modeling, and TIPTOP IP/QUIC profiles (experimental). 

BPA, BPSec, routing, and CLA logic currently live as a synchronous protocol kernel (temporary): each step is `(state, event, clock) → (state′, effects)`, with no sockets, TLS, or executor inside that path. I/O and async runtimes sit in adapters around the kernel. Feature gates separate the stable BPv7 profile from experimental modules.

1. [Scope](#scope)
1. [Getting Started](#getting-started)
1. [Resources](#resources)
1. [Communications](#communications)
1. [Contributing](#contributing)
1. [Conduct](#conduct)
1. [License](#license)

## Scope

`interplanetary-sdk` is intended to provide a DTN modeling library. It implements BPv7, BPSec defaults, discrete-event simulation, contact-plan routing, and TCPCLv4 modeling through a pure-Rust, `unsafe`-free crate with feature-gated profiles. It does not cover live deployment stacks, full production CLA/TLS termination, or orbital dynamics. This project will implement or has implemented:

* Bundle Protocol v7 encoding, decoding, and processing (RFC 9171 and related updates)
* BPSec default security contexts (HMAC, AES-GCM) and fail-closed protected-service delivery
* A discrete-event simulation engine with contact-aware routing (e.g. CGR)
* TCPCLv4 protocol state-machine modeling over virtual streams
* Experimental TIPTOP IP/QUIC modeling profiles (feature-gated, separately labeled)

## Getting Started

### Prerequisites
| Tool | Notes |
| --- | --- |
| [Git](https://git-scm.com/) | Clone the repository |
| [rustup](https://rustup.rs/) | Manages the toolchain pin in [`rust-toolchain.toml`](rust-toolchain.toml) |
| Rust `nightly` | Required for local builds: [`.cargo/config.toml`](.cargo/config.toml) enables nightly-only `-Z threads=4`. Components: `rustfmt`, `clippy`. Extra target: `x86_64-unknown-linux-gnu` |
| Make | Optional convenience wrapper; see [Makefile](#makefile). Cargo-only commands work without it |
| [direnv](https://direnv.net/) | Loads [`.envrc`](.envrc), which sets `core.hooksPath` to [`.githooks/`](.githooks) (requires Git) |
| `rustfmt` / `clippy` | Pulled by the toolchain file; used by `make fmt`, `make fmt-check`, and `make clippy` |
| mold + clang | Faster linking on Linux: `bash dev/scripts/INSTALL_LINKER.sh`, then uncomment the mold block in [`.cargo/config.toml`](.cargo/config.toml) (target `x86_64-unknown-linux-gnu` only). Details: [`dev/docs/internal/environment.md`](dev/docs/internal/environment.md) |
| sccache | Cache repeated clean builds: `cargo install sccache`, then uncomment `rustc-wrapper` in `.cargo/config.toml` |
| cargo-fuzz + C++ stdlib headers | Fuzz targets under [`dev/fuzz/`](dev/fuzz/): `cargo install cargo-fuzz`; on Debian/Ubuntu also `libstdc++-dev` (or `libstdc++-14-dev`) / `libc++-dev`. See [`dev/docs/internal/fuzzing-status.md`](dev/docs/internal/fuzzing-status.md) |
| Python 3 (+ jq for one script) | RFC / obligation helpers in [`dev/tools/`](dev/tools/) and [`dev/scripts/`](dev/scripts/); stdlib only for the `.py` tools; `jq` for `dev/tools/update_obligations.sh` |

**Setup Rust Toolchain**
```bash
# https://rustup.rs/ — then from the repo root:
rustup show          # installs nightly + components from rust-toolchain.toml
cargo build
cargo test
```
**Build and test**

```bash
make build
make test
```
**Run an example** (Earth → Relay → Mars contact plan)

```bash
make example
# or: make example EXAMPLE=expiry_demo
```

See [`examples/three_node.rs`](examples/three_node.rs) for the full scenario.

Other examples live under [`examples/`](examples/), including contact failure reroute and bundle expiry demos. Run them all with `make examples`.

**Feature profiles**

| Feature | Description |
| --- | --- |
| `bpv7` | Bundle Protocol v7 wire codec and processing (default) |
| `sim-basic` | Deterministic discrete-event simulation engine (default) |
| `bpsec-default` | BPSec HMAC and AES-GCM default contexts |
| `tcpclv4-model` | TCPCLv4 protocol state machine over virtual streams |
| `tiptop-experimental` | Experimental IP/QUIC modeling (unstable) |
| `stable-full` | Stable profile: BPv7 + BPSec + sim + TCPCL |
| `full` | All features, including experimental |

```bash
make build FEATURES=stable-full
make build FEATURES=full
make test-all   # all features
```


### SDK Usage

Add the crate and compute a contact-graph route in a few lines:

```rust
use interplanetary_sdk::{
    routing::{CgrConfig, CgrRouter},
    sim::{Contact, ContactId, ContactPlan},
    types::*,
};

fn main() -> Result<()> {
    let mut plan = ContactPlan::new();
    plan.add_contact(Contact {
        id: ContactId(1),
        from_node: NodeId::ipn(0, 1), // Earth
        to_node: NodeId::ipn(0, 2),   // Relay
        start: SimInstant::ZERO,
        end: SimInstant::from_nanos(10_000_000_000),
        rate: BitsPerSecond::from_kbps(8).unwrap(),
        delay: SimDuration::from_secs(4),
        resource_group: None,
    });
    // …add Relay → Mars and optional direct contacts…

    let router = CgrRouter::new(CgrConfig::default());
    let route = router.compute_route(
        &NodeId::ipn(0, 1),
        &NodeId::ipn(0, 3),
        Bytes(1000),
        SimInstant::ZERO,
        &plan,
    )?;
    println!("next hop: {}, arrival: {:?}", route.next_hop, route.arrival_time);
    Ok(())
}
```

### Makefile

Common targets (see `make help`):

| Target | Description |
| --- | --- |
| `make build` | Build the library |
| `make test` / `make test-all` | Run tests (default / all features) |
| `make check` | Type-check all targets |
| `make fmt` / `make fmt-check` | Format / check formatting |
| `make clippy` | Lint with clippy (`-D warnings`) |
| `make doc` | Build and open API docs |
| `make example` | Run one example (`EXAMPLE=…`) |
| `make examples` | Run all examples |
| `make clean` | Remove build artifacts |

Pass feature sets with `FEATURES=…`, for example `make test FEATURES=bpsec-default`.

## Resources

### NASA / CCSDS specifications

Normative protocol behavior for this crate follows the IETF DTN RFCs; the NASA and CCSDS documents below are the space-agency profiles and companion standards used for mission interoperability.

* [NASA DTN Resources for Mission Developers](https://www.nasa.gov/technology/space-comms/delay-disruption-tolerant-networking-mission-resources/) — NASA overview of DTN standards and implementations
* [CCSDS 734.20-O-1 — Bundle Protocol Version 7](https://ccsds.org/publications/ccsdsallpubs/entry/4218/) ([PDF](https://ccsds.org/wp-content/uploads/gravity_forms/5-448e85c647331d9cbaf66c096458bdd5/2025/06/734x20o1.pdf)) — CCSDS BPv7 experimental specification (RFC 9171–based)
* [CCSDS 734.2-B-1 — Bundle Protocol Specification](https://ccsds.org/Pubs/734x2b1.pdf) — CCSDS recommended standard for legacy BPv6 / RFC 5050 space use
* [CCSDS 734.5-R-2 — Bundle Protocol Security](https://ccsds.org/wp-content/uploads/gravity_forms/9-6f599803174a64f5da08b9814720b5c4/2025/02/734x5r2.pdf) — CCSDS BPSec draft (RFC 9172–based)
* [CCSDS 734.3-B-1 — Schedule-Aware Bundle Routing](https://ccsds.org/Pubs/734x3b1.pdf) — SABR / contact-graph routing for scheduled connectivity
* [CCSDS 734.1-B-1 — Licklider Transmission Protocol](https://ccsds.org/Pubs/734x1b1.pdf) — LTP for CCSDS space links
* [IETF DTN Working Group documents](https://datatracker.ietf.org/wg/dtn/documents/) — RFC 9171/9172/9173/9174 and related drafts
* [NASA JPL DTN reference notes](dev/docs/references/nasa-jpl.md) — informative ION / dtnnr comparison pins used by this project

### Project Documentation

Architecture and API contracts are documented under [`dev/docs/`](dev/docs/).

* [Architecture](dev/docs/internal/architecture.md)
* [API contracts](dev/docs/internal/api-contracts.md)
* [Conformance policy](dev/docs/internal/conformance.md)
* [Threat model](dev/docs/internal/threat-model.md)
* [ADRs](dev/docs/adr/)
* [Security Policy](.github/SECURITY.md)

## Communications

Community channels will be published as the project grows. Until then, prefer GitHub issues and pull requests for discussion.

* User Mailing List: TBD
* Developer Mailing List: TBD
* Slack Channel: TBD
* Public Meeting Schedule and Links: TBD
* Social Media: TBD
* Other Channel(s), If Any: [GitHub Issues](https://github.com/geoffsee/interplanetary-sdk/issues)

## Contributing

Community contributions are welcome. Open a pull request with a clear description of the change.

## Conduct

This project adopts the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md).

## License

This project is licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE) (dual license).