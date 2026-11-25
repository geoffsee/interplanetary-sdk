#![no_main]

use libfuzzer_sys::fuzz_target;
use interplanetary_sdk::bp::BundleCodec;

fuzz_target!(|data: &[u8]| {
    // Fuzz the bundle decoder with bounded allocation
    // Reject extremely large inputs early to prevent OOM
    const MAX_INPUT_SIZE: usize = 10 * 1024 * 1024; // 10 MB
    
    if data.len() > MAX_INPUT_SIZE {
        return;
    }
    
    // Attempt to decode bundle from arbitrary input
    // This should never panic, only return Err for invalid input
    let _ = BundleCodec::decode(data);
});
