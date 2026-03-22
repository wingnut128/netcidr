#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let new_prefix = data[0];
    if let Ok(cidr) = std::str::from_utf8(&data[1..]) {
        let _ = netcidr::subnet_generator::count_subnets(cidr, new_prefix);
        let _ = netcidr::subnet_generator::generate_ipv4_subnets(cidr, new_prefix, Some(10));
        let _ = netcidr::subnet_generator::generate_ipv6_subnets(cidr, new_prefix, Some(10));
    }
});
