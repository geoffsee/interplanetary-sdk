# Cargo Configuration Directory

This directory contains build performance optimizations for the interplanetary-sdk project.

## Files

- **`../../../.cargo/config.toml`** - Main Cargo configuration (build settings, profiles, linker)
- **`../../scripts/INSTALL_LINKER.sh`** - Quick installer for mold linker (run this for major speedup!)

## Quick Start

### 1. Already Active (No Action Needed) ✅
- Debug info reduction (20-50% faster builds)
- Parallel frontend compilation (10-30% faster)
- Enhanced release profiles

### 2. Install mold Linker for Major Gains 🚀

**One command**:
```bash
bash .cargo/INSTALL_LINKER.sh
```

**Or manually**:
```bash
sudo apt install mold  # Ubuntu/Debian
# Then uncomment mold section in config.toml
```

Expected improvement: **50-80% faster linking**

### 3. Optional: Install sccache for Caching
```bash
cargo install sccache
# Then uncomment sccache section in config.toml
```

## Verification

```bash
# Check active configuration
cargo -Z unstable-options config get profile.dev
cargo -Z unstable-options config get build

# Measure performance
cargo clean
cargo build --timings  # Opens HTML report
```

## References

- Based on: [Cargo Book - Build Performance](https://doc.rust-lang.org/cargo/guide/build-performance.html)
