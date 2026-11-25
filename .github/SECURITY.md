# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Interplanetary SDK, please report it responsibly. **Do not open a public GitHub issue.**

To report a vulnerability, use one of the following methods:

* **GitHub Private Vulnerability Reporting:** Use [Report a vulnerability](https://github.com/geoffsee/interplanetary-sdk/security/advisories/new) once the repository is published (Security → Advisories → New draft advisory), or the equivalent private reporting flow for the project's GitHub organization.
* **Email / private channel:** Contact the project maintainers through a private channel they designate (a `SECURITY_CONTACTS.md` file will list named contacts when available).

Please include in your report:

* Description of the vulnerability
* Steps to reproduce the issue
* Affected versions (crate version and enabled Cargo features)
* Any potential impact you have identified

Areas of particular interest for this project include:

* Bundle / CBOR decode paths and resource exhaustion
* BPSec cryptographic processing and key handling
* Fail-closed behavior for protected services
* Simulation bounds (queues, storage, event budgets)

See [`../dev/docs/internal/threat-model.md`](../dev/docs/internal/threat-model.md) for the current threat model.

## Response Timeline

The Interplanetary SDK security response contacts will acknowledge receipt of your report within **3 business days** and will provide an estimated timeline for a fix within **10 business days**.

The team will keep you informed of progress toward a fix and may ask for additional information.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |
| < 0.1   | No        |

Only the latest patch release on a supported minor line receives security fixes. Pre-1.0 APIs and feature gates may change; report against the version you observed.

## Disclosure Policy

When a security issue is confirmed, the Interplanetary SDK team will:

1. Develop and test a fix
2. Assign a CVE identifier if appropriate
3. Release a patched version of the crate
4. Publish a security advisory (GitHub Security Advisories and/or crates.io as applicable)

## Security Response Team

The security response team handles all reports of security vulnerabilities according to this policy. Appointment and maintenance of that team will be documented in project governance (`GOVERNANCE.md` / `MAINTAINERS.md`) as those documents land.

Until then, reports are handled by the project maintainers.

## Security Best Practices

This project aims to demonstrate:

* Pure Rust core with `#![deny(unsafe_code)]` in the library crate
* Documented [threat model](../dev/docs/internal/threat-model.md)
* Feature-gated experimental surfaces (`tiptop-experimental`, test-only fixtures)
* Dependency hygiene via Cargo and (planned) automated update tooling
* OpenSSF Best Practices and CNCF TAG Security self-assessment as the project matures
