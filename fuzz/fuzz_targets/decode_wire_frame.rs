#![no_main]

use libfuzzer_sys::fuzz_target;
use udp2raw_ng_core::WireFrame;

fuzz_target!(|data: &[u8]| {
    let _ = WireFrame::decode(data);
});
