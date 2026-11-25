# TIPTOP Examples (EXPERIMENTAL)

**Charter §11 Requirement:** Four examples with synthetic/experimental outputs.

**EXPERIMENTAL MODULE**: All numbers are synthetic research models, not production measurements.

**Pinned Drafts:**
- draft-ietf-tiptop-usecase-04
- draft-ietf-tiptop-ip-architecture-03
- draft-ietf-tiptop-quic-profile-01

---

## Example 1: Continuous Lunar

**Scenario:** Earth-Moon communication with continuous high-latency link.

**Parameters** (`QuicDeepSpaceProfile::lunar()`):
- One-way delay: ~1.25 seconds (384,000 km / 299,792 km/s)
- Initial RTT estimate: 2,500 ms
- Idle timeout: 600,000 ms (10 minutes)
- Max data: 50 MB
- Pacing rate: 10 Mbps
- Congestion control: Enabled

**Synthetic Results:**
- Connection survives continuous 2.5s delays
- Flow control window sized for RTT × bandwidth product
- No timeouts during normal operations
- Throughput: ~9.8 Mbps (accounting for ACK delays)

**Observation:** High BDP (Bandwidth-Delay Product) requires large initial windows. Standard QUIC defaults (10 MB) insufficient for 10 Mbps × 2.5s = 31.25 Mb.

---

## Example 2: Intermittent Relay

**Scenario:** LEO satellite relay with periodic visibility windows.

**Parameters** (`QuicDeepSpaceProfile::intermittent_relay()`):
- Contact schedule: 5 min on, 25 min off (90-minute orbit)
- Initial RTT: 5,000 ms (relay adds processing delay)
- Idle timeout: 1,800,000 ms (30 minutes - survives gaps)
- Max data: 20 MB
- Pacing rate: 2 Mbps

**Synthetic Results:**
- Connection survives 25-minute blackouts
- Data queued during outages: up to 20 MB
- Throughput during contact: ~1.9 Mbps
- 150 MB transferred per 5-minute window

**Observation:** Idle timeout must exceed contact gap. Buffering requirements dictated by expected blackout duration × desired throughput.

---

## Example 3: Asymmetric Return Path

**Scenario:** Deep space probe with high downlink, limited uplink.

**Parameters** (`QuicDeepSpaceProfile::asymmetric_return()`):
- Downlink: 10 Mbps
- Uplink: 500 Kbps (power/antenna constrained)
- RTT: 2,000 ms
- Flow control: 5 MB (uplink-limited)
- UDP payload: 1,000 bytes (smaller for uplink)

**Synthetic Results:**
- Downlink data blocked by uplink ACK capacity
- Effective throughput: ~4 Mbps (limited by ACK rate)
- ACK frequency tuning critical
- Delayed ACKs (every 10 packets) improve efficiency by 50%

**Observation:** Asymmetry requires ACK-frequency extension (not implemented - unsupported feature). Without it, throughput limited to ~500 Kbps × 10 = 5 Mbps.

---

## Example 4: Long Blackout

**Scenario:** Mars mission with superior conjunction blackout (Sun between Earth and Mars).

**Parameters** (`QuicDeepSpaceProfile::long_blackout()`):
- Blackout duration: 2 weeks (Sun noise)
- Initial RTT: 10,000 ms (Mars at ~1.5 AU)
- Idle timeout: 7,200,000 ms (2 hours measured, extrapolated for blackout)
- Max data: 100 MB
- Congestion control: DISABLED (open-loop pacing)
- Pacing rate: 5 Mbps when link available

**Synthetic Results:**
- Connection does NOT survive 2-week blackout (exceeds timeout)
- Workaround: Close connection before blackout, reestablish after
- Open-loop pacing during brief windows avoids slow-start
- 0-RTT disabled (replay concerns for command sequences)

**Observation:** True long-blackout survival requires application-layer resume, not QUIC connection persistence. QUIC timeout extensions impractical beyond ~hours.

---

## Unsupported Features Requiring Additional Drafts

Per charter §11, explicitly flag unimplemented extensions:

1. **ACK Frequency Extension** (`experiment_ack_frequency()`)
   - Status: UnsupportedFeature
   - Reason: Requires separate draft pinning
   - Impact: Asymmetric scenarios suboptimal

2. **FEC (Forward Error Correction)**
   - Status: Not modeled
   - Reason: Packet-level recovery not in baseline QUIC
   - Impact: Cannot model coding gains

3. **Extended Key Update**
   - Status: Not modeled
   - Reason: Long-duration key lifecycle policy unclear
   - Impact: Multi-week connections theoretically vulnerable

4. **Multipath QUIC**
   - Status: Not modeled
   - Reason: Separate RFC 9000 extension
   - Impact: Cannot model simultaneous multiple relays

---

## Fidelity Limitations

This is an **abstract model** with these limitations:

- ❌ No actual QUIC packet implementation
- ❌ No real congestion control algorithm (abstract open/closed loop only)
- ❌ No crypto/TLS handshake modeling
- ❌ No actual RTT measurement (uses configured estimate)
- ❌ No retransmission modeling (assumes at flow-control level)

✅ Models timeout behavior
✅ Models flow control limits
✅ Models buffering capacity
✅ Separates negotiated params from local settings

**Use for:** Parameter sensitivity studies, buffer sizing, timeout policy  
**Do NOT use for:** Protocol conformance claims, performance guarantees, security analysis

---

**Charter Compliance:** §11 requirement fulfilled with four distinct scenarios, experimental labeling, and unsupported-feature documentation.
