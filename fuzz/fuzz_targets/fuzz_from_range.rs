#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(idx) = s.find('\0') {
            let start = &s[..idx];
            let end = &s[idx + 1..];
            let _ = netcidr::from_range::from_range_ipv4(start, end);
            let _ = netcidr::from_range::from_range_ipv6(start, end);
        }
    }
});
