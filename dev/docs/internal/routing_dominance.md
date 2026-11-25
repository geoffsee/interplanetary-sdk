# Routing Dominance Analysis for CgrApproxV1

## Test Performance Note (2026-11-09)

Previously ignored tests `test_contact_failure_triggers_reroute` and `test_oracle_vs_solver_multiple_graphs` were marked as long-running (~225s and >300s respectively). After the duplicate-label bug fix in `MultiLabelSolver` (commit a1011f8), both tests now complete in **sub-second time** (0.00s as reported by test harness, <3s real time including compilation in release mode).

The duplicate-label issue caused the solver to re-explore identical states, hitting the MAX_ITERATIONS limit (1000) and degrading performance. With proper duplicate filtering, the solver converges in <10 iterations for these test scenarios. The `#[ignore]` attributes have been removed as of this session.

## Profile Constraints

**From charter §9 and scenarios/three-node-scheduler.json:**
- Processing delay: 0 ns
- Extra overhead: 0 bytes
- Knowledge model: All contacts known in advance
- No downstream queue reservations
- Constant bit rate per contact
- Deterministic propagation delays (OWLT)

## Single-Label Dijkstra Validity

**Question:** Is single-label Dijkstra (earliest arrival time only) sufficient, or do we need multi-label/time-expanded graph?

### FIFO Property

A routing problem satisfies **FIFO** (First-In-First-Out) if:
- Later departures never arrive earlier
- For any two paths P1 starting at t1 and P2 starting at t2 where t1 < t2:
  - If arrival(P1) > arrival(P2), then P1 is dominated

**Our Profile:**
- Zero processing delay means bundles are immediately processed upon arrival
- Contacts have fixed start/end times and constant rates
- No queueing within nodes (infinite processing speed assumption)
- **BUT**: Contacts may not be continuous (waiting required)

**Conclusion:** NOT strictly FIFO because:
1. A bundle arriving at relay at T=5s must wait until T=10s for next contact
2. A bundle arriving at T=9s would only wait until T=10s
3. The later arrival (T=9s) would depart at same time as earlier arrival (T=5s)
4. This violates FIFO property

### Dominance

Path P1 **dominates** path P2 if:
- P1 arrives no later than P2
- P1 uses equal or fewer resources

**Our Implementation:**
- Single metric: arrival time
- No volume tracking yet (assumes infinite capacity)
- Earliest arrival wins

**Limitation:** Without volume tracking, we don't detect:
- Overbooking (multiple bundles assigned to same contact capacity)
- Resource conflicts (bundles competing for same contact)

### Time-Expanded Graph Alternative

**Multi-label approach** would track:
- (time, volume_reserved) tuples
- Pareto-optimal paths
- Non-dominated solutions

**Implementation complexity:** Much higher
- Need to track volume state
- Maintain Pareto frontier
- Check dominance over multiple dimensions

## Current Implementation: CgrApproxV1

**Algorithm:** Dijkstra with earliest-arrival-only optimization

**Valid when:**
1. Single bundle routing (no volume conflicts) ✓
2. All contacts known in advance ✓
3. Deterministic delays ✓
4. **Assuming infinite contact capacity** ⚠️

**Invalid when:**
- Multiple bundles compete for contact capacity
- Volume-aware scheduling needed
- Overbooking must be prevented

## Recommendation

**For current scope (scenarios/three-node-scheduler.json):**
- Single-label Dijkstra is acceptable with documented assumption
- Contact capacity assumed infinite per bundle
- No volume conflicts in test scenarios

**For production use:**
- Must add volume-aware first-hop reservations
- Track committed capacity per contact
- Implement multi-label search OR
- Use conservative admission control (one bundle per contact)

## Small-Graph Oracle

**Test:** `../../kit`

**Oracle expectations:**
- Route: ["C1", "C2"] ✓
- Arrival: 17s ✓
- Direct arrival: 28s ✓
- Relay arrival at relay: 5s ✓
- No route by deadline 16s ✓

**Validation status:** ✓ Matches oracle for three-node case

**Missing:** Exhaustive small-graph oracle testing beyond single scenario
- Need multiple bundle sizes
- Need multiple ready times
- Need deadline-based cutoff tests
- Need capacity conflict scenarios

## Oracle vs Solver Disagreement (RESOLVED 2026-11-09)

**Issue:** Oracle verification test reported solver finding 499,500 routes while oracle found only 1 route on a simple 2-contact linear path (1→2→3).

**Root Cause:** The MultiLabelSolver had a duplicate label bug:
- The dominance check correctly prevented adding dominated labels
- However, it did NOT check for label equality
- When two labels had identical (arrival_time, volume_used), neither dominated the other
- The solver added both as "non-dominated" labels
- Over MAX_ITERATIONS=1000, this created ~1000 duplicate labels at destination
- The suspicious count 499,500 = 1000×999/2 suggests quadratic growth from predecessor tracking

**The Bug:**
```rust
let dominated = next_labels.iter().any(|l| l.dominates(&new_label));
if !dominated {
    next_labels.push(new_label);  // Adds duplicates!
}
```

**The Fix:**
```rust
let dominated = next_labels.iter().any(|l| l.dominates(&new_label));
let duplicate = next_labels.iter().any(|l| 
    l.arrival_time == new_label.arrival_time && l.volume_used == new_label.volume_used
);
if !dominated && !duplicate {
    next_labels.push(new_label);  // Only non-dominated, non-duplicate labels
}
```

**Verification:** After the fix, oracle and solver agree:
- Both find exactly 1 Pareto-optimal route on linear 2-contact graphs
- Both find identical arrival times and volume metrics
- Test `test_oracle_earliest_arrival_equality` now passes without `#[ignore]`

**Lesson:** Pareto-optimality requires checking both dominance AND equality. Two labels with identical metrics are neither better nor worse than each other, but only ONE should be in the frontier.

## Action Items

1. Document infinite-capacity assumption in API contracts
2. Add volume-aware first-hop reservation (W05 remaining)
3. Implement plan-version cache invalidation
4. Create exhaustive small-graph test suite
5. Consider multi-label solver for production variant
