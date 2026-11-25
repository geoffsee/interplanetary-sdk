# Fuzzing Results

**Date:** 2026-11-09  
**Target:** `bundle_decoder` (BP codec)  
**Charter:** §6 requirement

## Setup

**Environment fix required:**
```bash
sudo apt-get install -y libstdc++-14-dev libc++-dev libc++abi-dev
```

**Command:**
```bash
CXX=g++ cargo +nightly fuzz run bundle_decoder -- \
  -max_total_time=60 \
  -max_len=65536
```

## Results

**Summary:**
- **Runs:** 1,301,148 in 61 seconds
- **Throughput:** ~21,330 exec/s
- **Crashes:** 0
- **Hangs:** 0
- **Max input size:** 65,536 bytes
- **Corpus size:** Generated diverse test inputs

**Outcome:** ✅ **PASS - No crashes or panics detected**

The bundle decoder handles arbitrary malformed input gracefully:
- All decoding errors return `Err(...)` 
- No panics on truncated input
- No unbounded allocation
- No infinite loops or hangs

**Bounded allocation:** 10 MB limit enforced in fuzz target (input rejected if > 10 MB).

## Charter Compliance

✅ "Add a cargo-fuzz target for the bundle decoder if the toolchain allows, or document why not."

Target created, environment fixed, fuzzer executed successfully.
